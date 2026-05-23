/**
 * ParamResolver — 解析危险函数每个参数的来源
 *
 * 输出结构化的 ParamSourceInfo，脚本可以直接用属性判断：
 *   - param.isExternalInput  → 是否有外部输入
 *   - param.isHardcoded      → 是否有硬编码
 *   - param.composite        → 组合方式 (direct/concat/method_return/field/unknown)
 *   - param.parts[]          → 每个组成部分的详细信息
 *     - part.kind            → 'hardcoded' | 'external_input' | ...
 *     - part.value           → 硬编码的值
 *     - part.source          → 'method_parameter' | 'servlet_request' | ...
 *     - part.crossFile       → 是否跨文件
 *     - part.callerMethod    → 跨文件调用者方法名
 */

import * as fs from 'fs';
import * as path from 'path';
import { CallSite } from '../types';
import { ParamSourceInfo, ParamPart } from './script-context';
import { CodeGraphTraverser } from '../analyzer/codegraph-traverser';
import { DeepCallScanner, DeepCallResult } from '../analyzer/deep-call-scanner';
import { MethodParameter } from './script-context';

// ─── Taint source patterns ──────────────────────────────────────────

const EXTERNAL_INPUT_PATTERNS = [
  /request/i, /param/i, /\binput\b/i, /\buser/i,
  /header/i, /body/i, /query/i, /cookie/i,
  /token/i, /password/i, /secret/i,
  /path$/i, /file$/i, /url$/i, /name$/i,
];

export class ParamResolver {
  private deepScanner: DeepCallScanner;
  private cgTraverser: CodeGraphTraverser | null;
  private projectRoot: string;
  private jdkApiIndex: Map<string, string[]> | null = null;
  /** Map of static final String field names to their hardcoded values.
   *  Key format: "ClassName.fieldName" or just "fieldName" for unscoped lookup.
   *  Populated lazily on first access. */
  private staticFinalStrings: Map<string, string> | null = null;

  constructor(
    deepScanner: DeepCallScanner,
    cgTraverser: CodeGraphTraverser | null,
    projectRoot: string,
  ) {
    this.deepScanner = deepScanner;
    this.cgTraverser = cgTraverser;
    this.projectRoot = projectRoot;
    this.loadJdkApiIndex();
  }

  private loadJdkApiIndex(): void {
    try {
      const indexPath = path.join(__dirname, '..', 'analyzer', 'jdk-api-index.json');
      if (fs.existsSync(indexPath)) {
        const raw = JSON.parse(fs.readFileSync(indexPath, 'utf-8'));
        this.jdkApiIndex = new Map();
        for (const [key, value] of Object.entries(raw)) {
          this.jdkApiIndex!.set(key, value as string[]);
        }
      }
    } catch { /* JDK index is optional */ }
  }

  private resolveParameterTypesFromJdk(signature: string): string[] | null {
    if (!this.jdkApiIndex) return null;
    return this.jdkApiIndex.get(signature) || null;
  }

  // ══════════════════════════════════════════════════════════════════
  // 主入口：解析危险函数每个参数的来源
  // ══════════════════════════════════════════════════════════════════

  resolveParamSources(
    callSite: CallSite,
    scanResults: DeepCallResult[],
  ): ParamSourceInfo[] {
    const sourceLine = callSite.fullSignature.sourceLine || '';
    const args = this.extractArguments(sourceLine);

    // 无参数：从签名推断
    if (args.length === 0) {
      return callSite.fullSignature.parameterTypes.map((type, idx) => ({
        position: idx,
        type: type || 'unknown',
        isHardcoded: false,
        isExternalInput: false,
        isTainted: false,
        isResolvable: false,
        composite: 'unknown' as const,
        parts: [{ kind: 'unknown' as const }],
        confidence: 'low' as const,
      }));
    }

    const result: ParamSourceInfo[] = [];
    for (let i = 0; i < args.length; i++) {
      const argText = args[i]!;
      let paramType = callSite.fullSignature.parameterTypes[i];
      if (!paramType) {
        const jdkTypes = this.resolveParameterTypesFromJdk(callSite.fullSignature.fullQualifiedName);
        paramType = jdkTypes?.[i] || 'unknown';
      }
      const parts = this.traceArgParts(argText, callSite, scanResults);
      result.push(this.buildParamSourceInfo(i, paramType || 'unknown', parts));
    }

    return result;
  }

  // ══════════════════════════════════════════════════════════════════
  // 从 ParamPart[] 构建结构化的 ParamSourceInfo
  // ══════════════════════════════════════════════════════════════════

  private buildParamSourceInfo(
    position: number,
    type: string,
    parts: ParamPart[],
  ): ParamSourceInfo {
    const isHardcoded = parts.some(p => p.kind === 'hardcoded');
    const isExternalInput = parts.some(p => p.kind === 'external_input');
    const isResolvable = parts.every(p => p.kind !== 'unknown');

    // 判断 composite
    let composite: ParamSourceInfo['composite'];
    const kinds = new Set(parts.map(p => p.kind));

    if (parts.length > 1) {
      composite = 'concat';
    } else if (kinds.has('method_return')) {
      composite = 'method_return';
    } else if (kinds.has('field')) {
      composite = 'field';
    } else if (kinds.has('unknown')) {
      composite = 'unknown';
    } else {
      composite = 'direct';
    }

    // confidence
    let confidence: 'high' | 'medium' | 'low';
    if (isExternalInput) confidence = 'high';
    else if (isHardcoded && parts.length === 1) confidence = 'high';
    else if (isResolvable) confidence = 'medium';
    else confidence = 'low';

    return {
      position,
      type,
      isHardcoded,
      isExternalInput,
      isTainted: isExternalInput,
      isResolvable,
      composite,
      parts,
      confidence,
    };
  }

  // ══════════════════════════════════════════════════════════════════
  // 参数文本提取
  // ══════════════════════════════════════════════════════════════════

  private extractArguments(sourceLine: string): string[] {
    const methodNamePattern = /\b\w+\s*\(([^)]*)\)/g;
    const matches = [...sourceLine.matchAll(methodNamePattern)];
    if (matches.length === 0) return [];

    const lastMatch = matches[matches.length - 1]!;
    const argsStr = lastMatch[1]!.trim();
    if (!argsStr) return [];

    return this.splitArguments(argsStr);
  }

  private splitArguments(argsStr: string): string[] {
    const args: string[] = [];
    let depth = 0;
    let inString = false;
    let stringChar = '';
    let current = '';

    for (let i = 0; i < argsStr.length; i++) {
      const ch = argsStr[i]!;

      if ((ch === '"' || ch === "'") && (i === 0 || argsStr[i - 1] !== '\\')) {
        if (!inString) { inString = true; stringChar = ch; }
        else if (ch === stringChar) { inString = false; }
        current += ch;
        continue;
      }

      if (inString) { current += ch; continue; }

      if (ch === '(' || ch === '<') depth++;
      else if (ch === ')' || ch === '>') depth--;
      else if (ch === ',' && depth === 0) {
        args.push(current.trim());
        current = '';
        continue;
      }
      current += ch;
    }
    if (current.trim()) args.push(current.trim());
    return args;
  }

  // ══════════════════════════════════════════════════════════════════
  // 核心：追踪参数来源 → 返回 ParamPart[]
  // ══════════════════════════════════════════════════════════════════

  private traceArgParts(
    argText: string,
    callSite: CallSite,
    scanResults: DeepCallResult[],
  ): ParamPart[] {
    // 1. 硬编码字面量
    if (this.isHardcodedLiteral(argText)) {
      return [{
        kind: 'hardcoded',
        value: this.extractHardcodedValue(argText),
      }];
    }

    // 2. 字符串拼接 → 拆分后递归追踪每个 part
    if (argText.includes('+') || argText.includes('concat')) {
      const concatParts = this.splitConcatParts(argText);
      const parts: ParamPart[] = [];
      for (const part of concatParts) {
        if (this.isHardcodedLiteral(part)) {
          parts.push({ kind: 'hardcoded', value: this.extractHardcodedValue(part) });
        } else if (/^[a-zA-Z_]\w*$/.test(part.trim())) {
          parts.push(...this.traceVariableParts(part.trim(), callSite, scanResults));
        } else if (part.includes('(') && part.includes('.')) {
          parts.push(this.traceMethodCallPart(part, callSite));
        } else if (part.includes('.')) {
          parts.push(this.traceFieldPart(part, callSite));
        } else {
          parts.push({ kind: 'unknown' });
        }
      }
      return parts;
    }

    // 3. 纯变量名
    if (/^[a-zA-Z_]\w*$/.test(argText)) {
      return this.traceVariableParts(argText, callSite, scanResults);
    }

    // 4. 方法调用返回值
    if (argText.includes('(') && argText.includes('.')) {
      return [this.traceMethodCallPart(argText, callSite)];
    }

    // 5. 字段访问
    if (argText.includes('.') && !argText.includes('(')) {
      return [this.traceFieldPart(argText, callSite)];
    }

    return [{ kind: 'unknown' }];
  }

  // ══════════════════════════════════════════════════════════════════
  // 变量来源追踪 → 返回 ParamPart[]
  // ══════════════════════════════════════════════════════════════════

  private traceVariableParts(
    varName: string,
    callSite: CallSite,
    scanResults: DeepCallResult[],
  ): ParamPart[] {
    // Step 1: 是否是所在方法的参数？
    const methodParam = this.findMethodParam(varName, callSite, scanResults);
    if (methodParam) {
      const isExternal = EXTERNAL_INPUT_PATTERNS.some(p => p.test(varName));
      if (isExternal) {
        // 检查是否跨文件传入
        const crossFile = this.findCrossFileSource(callSite);
        const part: ParamPart = {
          kind: 'external_input',
          source: 'method_parameter',
          name: varName,
          type: methodParam.type,
          crossFile: !!crossFile,
        };
        if (crossFile) {
          part.callerMethod = crossFile.qualifiedName;
          part.callerFile = crossFile.filePath;
        }
        return [part];
      }
      // 非外部输入的方法参数，只作为普通变量
      return [{ kind: 'variable', varName, type: methodParam.type }];
    }

    // Step 2: 是否是局部变量赋值？
    const localParts = this.traceLocalVariableAssignment(varName, callSite, scanResults);
    if (localParts) return localParts;

    // Step 3: 变量名匹配外部输入模式（模糊匹配）
    if (EXTERNAL_INPUT_PATTERNS.some(p => p.test(varName))) {
      const crossFile = this.findCrossFileSource(callSite);
      const part: ParamPart = {
        kind: 'external_input',
        source: 'variable_pattern',
        name: varName,
        crossFile: !!crossFile,
      };
      if (crossFile) {
        part.callerMethod = crossFile.qualifiedName;
        part.callerFile = crossFile.filePath;
      }
      return [part];
    }

    // Fallback
    return [{ kind: 'variable', varName }];
  }

  // ══════════════════════════════════════════════════════════════════
  // 方法参数查找
  // ══════════════════════════════════════════════════════════════════

  private findMethodParam(
    varName: string,
    callSite: CallSite,
    scanResults: DeepCallResult[],
  ): MethodParameter | null {
    const fileResult = scanResults.find(r => r.filePath === callSite.callerFile);
    if (!fileResult) return null;

    const enclosingMethodCalls = fileResult.calls.filter(
      c => c.enclosingMethod === callSite.callerMethod &&
           c.enclosingClass === callSite.callerClass
    );
    if (enclosingMethodCalls.length === 0) return null;

    const methodSource = this.getMethodSource(callSite, fileResult);
    if (!methodSource) return null;

    const methodParams = this.parseMethodParams(methodSource);
    return methodParams.find(p => p.name === varName) || null;
  }

  // ══════════════════════════════════════════════════════════════════
  // 局部变量赋值追踪
  // ══════════════════════════════════════════════════════════════════

  private traceLocalVariableAssignment(
    varName: string,
    callSite: CallSite,
    scanResults: DeepCallResult[],
  ): ParamPart[] | null {
    const fullPath = path.join(this.projectRoot, callSite.callerFile);
    if (!fs.existsSync(fullPath)) return null;

    const source = fs.readFileSync(fullPath, 'utf-8');
    const lines = source.split('\n');

    let methodStart = -1;
    let methodEnd = lines.length;
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i]!;
      if (line.includes(callSite.callerMethod) &&
          (line.includes('public') || line.includes('private') || line.includes('protected'))) {
        methodStart = i;
      }
    }

    if (methodStart >= 0) {
      let depth = 0;
      let foundOpen = false;
      for (let i = methodStart; i < lines.length; i++) {
        for (const ch of lines[i]!) {
          if (ch === '{') { depth++; foundOpen = true; }
          if (ch === '}') depth--;
          if (foundOpen && depth === 0) { methodEnd = i + 1; break; }
        }
        if (foundOpen && depth === 0) break;
      }
    }

      const assignRegex = new RegExp('(?:final\\s+)?(?:String|int|long|boolean|Object|List|Map|Set|var)\\s+' + this.escapeRegex(varName) + '\\s*=');

    for (let i = methodStart; i < methodEnd && i < lines.length; i++) {
      const line = lines[i]!.trim();
      const assignMatch = line.match(assignRegex);
      if (!assignMatch) continue;

      const eqIdx = line.indexOf('=');
      if (eqIdx < 0) continue;

      let rhs = line.substring(eqIdx + 1).trim().replace(/;\s*$/, '');

      // 字符串拼接：递归追踪每个 part
      if (rhs.includes('+')) {
        return this.traceArgParts(rhs, callSite, scanResults);
      }

      // 方法调用返回值
      if (rhs.includes('(') && rhs.includes('.')) {
        return [this.traceMethodCallPart(rhs, callSite)];
      }

      // 简单变量赋值
      if (/^[a-zA-Z_]\w*$/.test(rhs)) {
        return this.traceVariableParts(rhs, callSite, scanResults);
      }

      // 硬编码
      if (this.isHardcodedLiteral(rhs)) {
        return [{ kind: 'hardcoded', value: this.extractHardcodedValue(rhs) }];
      }
    }

    return null;
  }

  // ══════════════════════════════════════════════════════════════════
  // 方法调用 / 字段追踪
  // ══════════════════════════════════════════════════════════════════

  private traceMethodCallPart(text: string, callSite: CallSite): ParamPart {
    const methodMatch = text.match(/(\w+)\.(\w+)\s*\(/);
    if (methodMatch) {
      const receiver = methodMatch[1]!;
      const method = methodMatch[2]!;

      // If receiver is a static final String field, getBytes()/toString() etc. are derivable
      const constantValue = this.getStaticFinalStringValue(receiver, callSite.callerClass);
      if (constantValue !== undefined) {
        return {
          kind: 'hardcoded',
          value: constantValue,
          methodSignature: `${receiver}.${method}()`,  // 记录来源
        };
      }

      return {
        kind: 'method_return',
        methodSignature: `${receiver}.${method}()`,
      };
    }
    return { kind: 'unknown' };
  }

  private traceFieldPart(text: string, callSite: CallSite): ParamPart {
    const fieldMatch = text.match(/(?:this\.|self\.)?(\w+)/);
    if (fieldMatch) {
      const fieldName = fieldMatch[1]!;

      // Check if this field is a static final String constant
      const constantValue = this.getStaticFinalStringValue(fieldName, callSite.callerClass);
      if (constantValue !== undefined) {
        return {
          kind: 'hardcoded',
          value: constantValue,
          fieldName,  // 记录来源字段名
        };
      }

      return { kind: 'field', fieldName, fieldType: 'unknown' };
    }
    return { kind: 'unknown' };
  }

  // ══════════════════════════════════════════════════════════════════
  // Static final String 常量扫描
  // ══════════════════════════════════════════════════════════════════

  /** Lazily scan all Java source files for static final String field declarations. */
  private ensureStaticFinalStringsScanned(): void {
    if (this.staticFinalStrings !== null) return;

    this.staticFinalStrings = new Map();
    const srcRoot = path.join(this.projectRoot, 'src');
    if (!fs.existsSync(srcRoot)) return;

    const javaFiles = this.findJavaFiles(srcRoot);
    for (const filePath of javaFiles) {
      try {
        const source = fs.readFileSync(filePath, 'utf-8');
        const lines = source.split('\n');
        let currentClass = '';
        for (const line of lines) {
          // Track current class
          const classMatch = line.match(/(?:public\s+)?(?:abstract\s+)?(?:class|interface|enum)\s+(\w+)/);
          if (classMatch) currentClass = classMatch[1]!;

          // Match: [access] static final String FIELD_NAME = "value";
          const fieldMatch = line.match(
            /(?:private|protected|public)?\s*static\s+final\s+String\s+(\w+)\s*=\s*"([^"]*)"\s*;/
          );
          if (fieldMatch && currentClass) {
            const fieldName = fieldMatch[1]!;
            const value = fieldMatch[2]!;
            // Store both scoped (ClassName.field) and unscoped (field)
            this.staticFinalStrings.set(`${currentClass}.${fieldName}`, value);
            this.staticFinalStrings.set(fieldName, value);
          }
        }
      } catch { /* ignore read errors */ }
    }
  }

  /** Get the hardcoded value of a static final String field, or undefined if not found. */
  private getStaticFinalStringValue(fieldName: string, enclosingClass: string): string | undefined {
    this.ensureStaticFinalStringsScanned();
    // Try scoped first
    const scoped = this.staticFinalStrings!.get(`${enclosingClass}.${fieldName}`);
    if (scoped !== undefined) return scoped;
    // Fallback to unscoped
    return this.staticFinalStrings!.get(fieldName);
  }

  /** Recursively find .java files under a directory. */
  private findJavaFiles(dir: string): string[] {
    const results: string[] = [];
    try {
      for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
        const fullPath = path.join(dir, entry.name);
        if (entry.isDirectory()) {
          results.push(...this.findJavaFiles(fullPath));
        } else if (entry.name.endsWith('.java')) {
          results.push(fullPath);
        }
      }
    } catch { /* ignore */ }
    return results;
  }

  // ══════════════════════════════════════════════════════════════════
  // 硬编码检测
  // ══════════════════════════════════════════════════════════════════

  private isHardcodedLiteral(text: string): boolean {
    if (/^"[^"]*"$/.test(text) || /^'[^']*'$/.test(text)) return true;
    if (/^-?\d+(\.\d+)?$/.test(text)) return true;
    if (text === 'null' || text === 'true' || text === 'false') return true;
    return false;
  }

  private extractHardcodedValue(text: string): string {
    if (/^["']/.test(text)) return text.slice(1, -1);
    return text;
  }

  // ══════════════════════════════════════════════════════════════════
  // 字符串拼接拆分
  // ══════════════════════════════════════════════════════════════════

  private splitConcatParts(text: string): string[] {
    const parts: string[] = [];
    let current = '';
    let inString = false;
    let stringChar = '';

    for (let i = 0; i < text.length; i++) {
      const ch = text[i]!;

      if ((ch === '"' || ch === "'") && (i === 0 || text[i - 1] !== '\\')) {
        if (!inString) { inString = true; stringChar = ch; }
        else if (ch === stringChar) {
          inString = false;
          if (i + 1 < text.length && text[i + 1] === '+') {
            parts.push(current + ch);
            current = '';
            i++;
            continue;
          }
        }
        current += ch;
        continue;
      }

      if (inString) { current += ch; continue; }

      if (ch === '+') {
        parts.push(current.trim());
        current = '';
        continue;
      }
      current += ch;
    }

    if (current.trim()) parts.push(current.trim());
    return this.mergeAdjacentStrings(parts);
  }

  private mergeAdjacentStrings(parts: string[]): string[] {
    const merged: string[] = [];
    for (const part of parts) {
      const last = merged[merged.length - 1];
      if (last && this.isHardcodedLiteral(last) && this.isHardcodedLiteral(part)) {
        merged[merged.length - 1] = last + part;
      } else {
        merged.push(part);
      }
    }
    return merged;
  }

  // ══════════════════════════════════════════════════════════════════
  // 辅助方法
  // ══════════════════════════════════════════════════════════════════

  private escapeRegex(s: string): string {
    return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  }

  private findCrossFileSource(callSite: CallSite): { qualifiedName: string; filePath: string } | null {
    if (!this.cgTraverser) return null;
    const methodNodeId = this.cgTraverser.findMethodNodeId(callSite.callerFile, callSite.callerMethod);
    if (!methodNodeId) return null;
    const callers = this.cgTraverser.getCallers(methodNodeId, 1);
    if (callers.length === 0) return null;
    const caller = callers[0]!.caller;
    return { qualifiedName: caller.qualifiedName, filePath: caller.filePath };
  }

  private getMethodSource(callSite: CallSite, scanResult: DeepCallResult): string | null {
    const fullPath = path.join(this.projectRoot, callSite.callerFile);
    if (!fs.existsSync(fullPath)) return null;

    const source = fs.readFileSync(fullPath, 'utf-8');
    const lines = source.split('\n');

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i]!;
      if (line.includes(callSite.callerMethod) && (line.includes('public') || line.includes('private') || line.includes('protected') || line.includes('static'))) {
        let methodDecl = line;
        let j = i + 1;
        while (j < lines.length && !methodDecl.includes('{') && !methodDecl.includes(';')) {
          methodDecl += ' ' + lines[j]!;
          j++;
        }
        return methodDecl.trim();
      }
    }
    return null;
  }

  private parseMethodParams(methodDecl: string): MethodParameter[] {
    const match = methodDecl.match(/\(([^)]*)\)/);
    if (!match) return [];
    const paramsStr = match[1]!.trim();
    if (!paramsStr) return [];

    const params: MethodParameter[] = [];
    for (const part of this.splitParamsSimple(paramsStr)) {
      const tokens = part.trim().split(/\s+/);
      if (tokens.length >= 2) {
        params.push({ type: tokens.slice(0, -1).join(' '), name: tokens[tokens.length - 1]! });
      }
    }
    return params;
  }

  private splitParamsSimple(s: string): string[] {
    const parts: string[] = [];
    let depth = 0;
    let current = '';
    for (const ch of s) {
      if (ch === '<') depth++;
      else if (ch === '>') depth--;
      else if (ch === ',' && depth === 0) { parts.push(current); current = ''; continue; }
      current += ch;
    }
    if (current.trim()) parts.push(current);
    return parts;
  }
}