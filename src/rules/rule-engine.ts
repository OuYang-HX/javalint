/**
 * Rule Engine — 多语言脚本规则的匹配与执行引擎
 *
 * 架构：
 *   1. YAML 规则文件定义签名模式 + 检查脚本
 *   2. ScriptEngineRegistry 根据脚本扩展名选择执行引擎
 *   3. ParamResolver 解析危险函数每个参数的来源
 *   4. buildScriptContext() 组装完整的 ScriptContext
 *   5. 引擎执行脚本，返回 CheckResult
 *
 * 支持的脚本语言：
 *   - .js    → JsEngine    (require(), 零延迟)
 *   - .groovy→ GroovyEngine (子进程 groovy)
 *   - .py    → PythonEngine (子进程 python3)
 */

import * as fs from 'fs';
import * as path from 'path';
import { CallSite, Rule, CheckResult, Alert } from '../types';
import {
  ScriptContext, ScriptCheckResult,
  SinkInfo, MethodInfo, MethodParameter,
  ParamSourceInfo,
  ObjectHistoryInfo, ObjectCallRecord,
  ReturnUsageInfo, ReturnCallRecord,
  TaintChainContext,
} from './script-context';
import { ScriptEngineRegistry } from './script-engine';
import { JsEngine } from './js-engine';
import { GroovyEngine } from './groovy-engine';
import { PythonEngine } from './python-engine';
import { ParamResolver } from './param-resolver';
import { CodeGraphTraverser, CGNode } from '../analyzer/codegraph-traverser';
import { DeepCallScanner, DeepCallResult } from '../analyzer/deep-call-scanner';

export class RuleEngine {
  private rules: Rule[] = [];
  private rulesDir: string;
  private engineRegistry: ScriptEngineRegistry;
  private paramResolver: ParamResolver | null = null;
  private cgTraverser: CodeGraphTraverser | null = null;
  private scanResults: DeepCallResult[] = [];

  constructor(rulesDir: string) {
    this.rulesDir = rulesDir;
    this.engineRegistry = new ScriptEngineRegistry();
    this.engineRegistry.register(new JsEngine());
    this.engineRegistry.register(new GroovyEngine());
    this.engineRegistry.register(new PythonEngine());
  }

  /**
   * 注入 CodeGraph 和 tree-sitter 依赖
   * 必须在 loadRules() 之前调用
   */
  injectDependencies(
    deepScanner: DeepCallScanner,
    cgTraverser: CodeGraphTraverser | null,
    projectRoot: string,
  ): void {
    this.paramResolver = new ParamResolver(deepScanner, cgTraverser, projectRoot);
    this.cgTraverser = cgTraverser;
  }

  /** 注入扫描结果（供参数解析使用） */
  injectScanResults(scanResults: DeepCallResult[]): void {
    this.scanResults = scanResults;
  }

  /**
   * Load rules from YAML/JSON files in the rules directory
   */
  loadRules(): number {
    if (!fs.existsSync(this.rulesDir)) {
      console.error(`Rules directory not found: ${this.rulesDir}`);
      return 0;
    }

    const files = fs.readdirSync(this.rulesDir).filter(f =>
      f.endsWith('.yaml') || f.endsWith('.yml') || f.endsWith('.json')
    );

    for (const file of files) {
      try {
        const fullPath = path.join(this.rulesDir, file);
        const content = fs.readFileSync(fullPath, 'utf-8');
        let rule: any;

        if (file.endsWith('.json')) {
          rule = JSON.parse(content);
        } else {
          rule = this.parseSimpleYaml(content);
        }

        if (rule && rule.id && rule.signaturePatterns) {
          this.rules.push({
            id: rule.id,
            name: rule.name || rule.id,
            severity: rule.severity || 'medium',
            description: rule.description || '',
            signaturePatterns: rule.signaturePatterns || [],
            checkScript: rule.checkScript,
            tags: rule.tags || [],
            requiresTaintAnalysis: rule.requiresTaintAnalysis || false,
          });
        }
      } catch (e) {
        console.error(`Warning: Failed to load rule ${file}:`, (e as Error).message);
      }
    }

    return this.rules.length;
  }

  /**
   * Match a call site's signature against all loaded rules
   */
  matchRules(callSite: CallSite): Rule[] {
    const sig = callSite.fullSignature.fullQualifiedName;
    const matched: Rule[] = [];

    for (const rule of this.rules) {
      for (const pattern of rule.signaturePatterns) {
        if (this.matchPattern(sig, pattern)) {
          matched.push(rule);
          break; // one match per rule is enough
        }
      }
    }

    return matched;
  }

  /**
   * Execute a rule's check script against a call site
   *
   * 新流程：
   *   1. 根据 checkScript 扩展名选择执行引擎
   *   2. 构建 ScriptContext（包含参数来源、对象历史、返回值使用等）
   *   3. 通过引擎执行脚本
   */
  executeCheck(rule: Rule, callSite: CallSite): CheckResult {
    // If no check script, the pattern match itself is the alert
    if (!rule.checkScript) {
      return {
        alert: true,
        message: rule.description,
        confidence: 'medium',
      };
    }

    // Resolve the script path
    const scriptPath = path.resolve(this.rulesDir, rule.checkScript);
    if (!fs.existsSync(scriptPath)) {
      return { alert: true, message: rule.description, confidence: 'low' };
    }

    // Select engine based on script extension
    const engine = this.engineRegistry.getEngineForScript(scriptPath);

    if (!engine) {
      // Fallback to JS engine for backward compatibility (scripts without extension in name)
      const jsEngine = this.engineRegistry.get('js');
      if (jsEngine && jsEngine.isAvailable()) {
        return this.executeWithEngine(jsEngine, scriptPath, rule, callSite);
      }
      return { alert: true, message: rule.description, confidence: 'low' };
    }

    return this.executeWithEngine(engine, scriptPath, rule, callSite);
  }

  /**
   * 使用指定引擎执行脚本
   */
  private executeWithEngine(
    engine: any,
    scriptPath: string,
    rule: Rule,
    callSite: CallSite,
  ): CheckResult {
    // Build the rich ScriptContext
    const context = this.buildScriptContext(callSite);

    // Execute via engine
    const result = engine.execute(scriptPath, context);

    return {
      alert: result.alert,
      message: result.message || rule.description,
      confidence: result.confidence || 'medium',
    };
  }

  /**
   * 构建 ScriptContext — 传递给脚本的全部上下文
   *
   * 这是核心方法，把 CallSite + CodeGraph + tree-sitter 信息
   * 组装成脚本可用的丰富上下文对象
   */
  buildScriptContext(callSite: CallSite): ScriptContext {
    const sink = this.buildSinkInfo(callSite);
    const method = this.buildMethodInfo(callSite);
    const params = this.paramResolver
      ? this.paramResolver.resolveParamSources(callSite, this.scanResults)
      : [];
    const objHistory = this.buildObjectHistory(callSite);
    const retUsage = this.buildReturnUsage(callSite);
    const taintChain = callSite.taintChain ? {
      sourceMethod: callSite.taintChain.sourceMethod,
      sourceFile: callSite.taintChain.sourceFile,
      sourceParameters: callSite.taintChain.sourceParameters,
      propagationPath: callSite.taintChain.propagationPath,
      depth: callSite.taintChain.depth,
      confidence: callSite.taintChain.confidence,
      sourceReason: callSite.taintChain.sourceReason,
    } : null;

    return { sink, method, params, objHistory, retUsage, taintChain };
  }

  // ─── SinkInfo 构建 ──────────────────────────────────────────────────

  private buildSinkInfo(callSite: CallSite): SinkInfo {
    return {
      fullSignature: callSite.fullSignature.fullQualifiedName,
      packageName: callSite.fullSignature.packageName,
      className: callSite.fullSignature.className,
      methodName: callSite.fullSignature.methodName,
      parameterTypes: callSite.fullSignature.parameterTypes,
      sourceLine: callSite.fullSignature.sourceLine,
      filePath: callSite.callerFile,
      line: callSite.callerLine,
    };
  }

  // ─── MethodInfo 构建 ──────────────────────────────────────────────

  private buildMethodInfo(callSite: CallSite): MethodInfo {
    let parameters: MethodParameter[] = [];
    let signature = '';
    let startLine = 0;
    let endLine = 0;

    // Try to get from CodeGraph
    if (this.cgTraverser) {
      const methodNodeId = this.cgTraverser.findMethodNodeId(
        callSite.callerFile,
        callSite.callerMethod,
      );
      if (methodNodeId) {
        const node = this.cgTraverser.getNode(methodNodeId);
        if (node) {
          startLine = node.startLine;
          endLine = node.endLine;
          if (node.signature) {
            signature = `${node.qualifiedName}${node.signature}`;
            parameters = this.parseParamsFromSignature(node.signature);
          }
        }
      }
    }

    // Fallback: 从 CallSite 信息构建
    if (!signature) {
      signature = `${callSite.callerClass}.${callSite.callerMethod}()`;
    }

    return {
      className: callSite.callerClass,
      methodName: callSite.callerMethod,
      signature,
      parameters,
      filePath: callSite.callerFile,
      startLine,
      endLine,
    };
  }

  /** 从 CodeGraph 签名解析参数 */
  private parseParamsFromSignature(sig: string): MethodParameter[] {
    const match = sig.match(/\(([^)]*)\)/);
    if (!match) return [];

    const paramsStr = match[1]!.trim();
    if (!paramsStr) return [];

    const params: MethodParameter[] = [];
    const parts = this.splitParamsSimple(paramsStr);

    for (const part of parts) {
      const trimmed = part.trim();
      const tokens = trimmed.split(/\s+/);
      if (tokens.length >= 2) {
        params.push({
          type: tokens.slice(0, -1).join(' '),
          name: tokens[tokens.length - 1]!,
        });
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
      else if (ch === ',' && depth === 0) {
        parts.push(current);
        current = '';
        continue;
      }
      current += ch;
    }
    if (current.trim()) parts.push(current);

    return parts;
  }

  // ─── ObjectHistory 构建 ────────────────────────────────────────────

  /**
   * 构建危险函数对象的调用历史
   *
   * 例如 stmt.executeQuery(sql) 中，对象是 stmt（类型 java.sql.Statement）
   * 需要追踪 stmt 此前调用过哪些函数、被哪些函数作为参数使用
   */
  private buildObjectHistory(callSite: CallSite): ObjectHistoryInfo | null {
    if (!this.cgTraverser) return null;

    // 从源码行提取对象名： "stmt.executeQuery(sql)" → "stmt"
    const sourceLine = callSite.fullSignature.sourceLine || '';
    const objMatch = sourceLine.match(/(\w+)\.\w+\s*\(/);
    if (!objMatch) return null;

    const objectName = objMatch[1]!;

    // 查找同一方法内、同一行之前的所有调用
    const fileResult = this.scanResults.find(r => r.filePath === callSite.callerFile);
    if (!fileResult) return null;

    const sameMethodCalls = fileResult.calls.filter(
      c => c.enclosingMethod === callSite.callerMethod &&
           c.enclosingClass === callSite.callerClass &&
           c.line < callSite.callerLine
    );

    // 筛选同一对象的调用
    const priorCalls: ObjectCallRecord[] = [];
    const priorPassedTo: ObjectCallRecord[] = [];

    for (const call of sameMethodCalls) {
      if (call.receiver === objectName) {
        // 对象主动调用
        const sig = this.resolveCallSignature(call);
        priorCalls.push({
          signature: sig,
          filePath: callSite.callerFile,
          line: call.line,
          direction: 'called',
        });
      }
      // 检查对象是否被作为参数传入（通过源码行匹配）
      if (call.sourceLine.includes(objectName) && call.receiver !== objectName) {
        const sig = this.resolveCallSignature(call);
        priorPassedTo.push({
          signature: sig,
          filePath: callSite.callerFile,
          line: call.line,
          direction: 'passedTo',
        });
      }
    }

    // 查找对象创建信息
    const creationInfo = this.findObjectCreation(objectName, callSite, fileResult);

    return {
      objectName,
      objectType: callSite.fullSignature.packageName + '.' + callSite.fullSignature.className || objectName,
      creationInfo: creationInfo || {
        method: 'unknown',
        signature: 'unknown',
        line: 0,
      },
      priorCalls,
      priorPassedTo,
    };
  }

  /** 查找对象的创建方式 */
  private findObjectCreation(
    objectName: string,
    callSite: CallSite,
    fileResult: DeepCallResult,
  ): { method: string; signature: string; line: number } | null {
    // 在方法内查找 try-with-resources 或变量声明
    const sameMethodCalls = fileResult.calls.filter(
      c => c.enclosingMethod === callSite.callerMethod &&
           c.enclosingClass === callSite.callerClass
    );

    for (const call of sameMethodCalls) {
      // try (Statement stmt = ...) 或 Statement stmt = ...
      if (call.sourceLine.includes(objectName) &&
          (call.sourceLine.includes('=') || call.sourceLine.includes('try'))) {
        const sig = this.resolveCallSignature(call);
        return {
          method: call.receiver + '.' + call.method + '()',
          signature: sig,
          line: call.line,
        };
      }
    }

    return null;
  }

  /** 解析调用点的签名 */
  private resolveCallSignature(call: any): string {
    const method = call.method || 'unknown';
    const receiver = call.receiver || 'unknown';

    // 如果有 CodeGraph 信息，可以进一步解析
    if (this.cgTraverser) {
      const methodNodeId = this.cgTraverser.findMethodNodeId(
        '', // 不知文件路径
        method,
      );
      if (methodNodeId) {
        const node = this.cgTraverser.getNode(methodNodeId);
        if (node) return node.qualifiedName + (node.signature || '()');
      }
    }

    return `${receiver}.${method}()`;
  }

  // ─── ReturnUsage 构建 ──────────────────────────────────────────────

  /**
   * 构建危险函数返回值的后续使用信息
   *
   * 例如 stmt.executeQuery(sql) 返回 ResultSet
   * 后续可能：rs.next(), rs.getString("username")
   */
  private buildReturnUsage(callSite: CallSite): ReturnUsageInfo | null {
    if (!this.cgTraverser) return null;

    const sourceLine = callSite.fullSignature.sourceLine || '';

    // 检查返回值是否被赋值给变量：ResultSet rs = stmt.executeQuery(sql)
    const assignMatch = sourceLine.match(/(\w+(?:<[^>]+>)?)\s+(\w+)\s*=\s*\w+\.\w+\s*\(/);
    if (!assignMatch) {
      // 检查是否被直接使用： return stmt.execute(sql) ? 1 : 0
      if (sourceLine.includes('return ')) {
        return {
          returnType: callSite.fullSignature.methodName.includes('execute') ? 'boolean' : 'Object',
          subsequentCalls: [],
          subsequentPassedTo: [],
          assignedTo: ['<return value>'],
        };
      }
      return null;
    }

    const returnType = assignMatch[1]!;
    const returnVarName = assignMatch[2]!;

    // 查找同一方法内此变量后续的调用
    const fileResult = this.scanResults.find(r => r.filePath === callSite.callerFile);
    if (!fileResult) {
      return {
        returnType,
        subsequentCalls: [],
        subsequentPassedTo: [],
        assignedTo: [returnVarName],
      };
    }

    const sameMethodLaterCalls = fileResult.calls.filter(
      c => c.enclosingMethod === callSite.callerMethod &&
           c.enclosingClass === callSite.callerClass &&
           c.line > callSite.callerLine
    );

    const subsequentCalls: ReturnCallRecord[] = [];
    const subsequentPassedTo: ReturnCallRecord[] = [];

    for (const call of sameMethodLaterCalls) {
      if (call.receiver === returnVarName) {
        // 返回值作为接收者调用方法
        const sig = this.resolveCallSignature(call);
        subsequentCalls.push({
          signature: sig,
          filePath: callSite.callerFile,
          line: call.line,
          usage: 'called',
        });
      } else if (call.sourceLine.includes(returnVarName)) {
        // 返回值被作为参数传入
        const sig = this.resolveCallSignature(call);
        subsequentPassedTo.push({
          signature: sig,
          filePath: callSite.callerFile,
          line: call.line,
          usage: 'passedTo',
        });
      }
    }

    return {
      returnType,
      subsequentCalls,
      subsequentPassedTo,
      assignedTo: [returnVarName],
    };
  }

  // ─── Pattern matching ──────────────────────────────────────────────

  private matchPattern(signature: string, pattern: string): boolean {
    const regexStr = pattern
      .replace(/[.+^${}()|[\]\\]/g, '\\$&')
      .replace(/\*/g, '\x00');

    const regex = new RegExp(
      '^' + regexStr.replace(/\x00/g, '[^()]*') + '$'
    );

    return regex.test(signature);
  }

  // ─── Simple YAML parser ────────────────────────────────────────────

  private parseSimpleYaml(content: string): any {
    const result: any = {};
    let currentKey = '';
    let inArray = false;

    for (const line of content.split('\n')) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#')) continue;

      if (trimmed.startsWith('- ')) {
        if (!inArray) { result[currentKey] = []; inArray = true; }
        const value = trimmed.substring(2).trim().replace(/^["']|["']$/g, '');
        (result[currentKey] as string[]).push(value);
        continue;
      }

      if (inArray) inArray = false;

      const colonIdx = trimmed.indexOf(':');
      if (colonIdx > 0) {
        currentKey = trimmed.substring(0, colonIdx).trim();
        const value = trimmed.substring(colonIdx + 1).trim().replace(/^["']|["']$/g, '');
        if (value) result[currentKey] = value;
      }
    }

    return result;
  }

  getRules(): Rule[] {
    return this.rules;
  }

  getEngineRegistry(): ScriptEngineRegistry {
    return this.engineRegistry;
  }

  /**
   * Create an Alert from a rule match
   */
  createAlert(rule: Rule, callSite: CallSite, checkResult: CheckResult): Alert {
    return {
      ruleId: rule.id,
      ruleName: rule.name,
      severity: rule.severity,
      message: checkResult.message || rule.description,
      confidence: checkResult.confidence || 'medium',
      filePath: callSite.callerFile,
      line: callSite.callerLine,
      packageName: callSite.fullSignature.packageName,
      className: callSite.fullSignature.className,
      methodName: callSite.fullSignature.methodName,
      parameterTypes: callSite.fullSignature.parameterTypes,
      fullSignature: callSite.fullSignature.fullQualifiedName,
      callerClass: callSite.callerClass,
      callerMethod: callSite.callerMethod,
      sourceLine: callSite.fullSignature.sourceLine,
      detectedAt: Date.now(),
    };
  }
}