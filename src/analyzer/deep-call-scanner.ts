/**
 * Deep Call Scanner
 *
 * Uses tree-sitter to directly parse Java source files and extract
 * ALL method_invocation nodes — including calls to external dependency
 * libraries (JDK, Maven jars, etc.) that CodeGraph silently drops.
 *
 * Type resolution pipeline (3 layers):
 *
 *   1. Variable declaration tracking (type-resolver.ts)
 *      - Field: "private Connection dbConnection" → dbConnection: java.sql.Connection
 *      - Local: "Statement stmt = ..."           → stmt: java.sql.Statement
 *      - Try-with-resources: "try (PreparedStatement stmt = ...)" → stmt: PreparedStatement
 *      - Catch parameter: "catch (Exception e)"  → e: java.lang.Exception
 *
 *   2. Return type inference (return-type-table.ts)
 *      - Chained: "conn.createStatement().executeQuery()"
 *                 conn: java.sql.Connection
 *                 createStatement() returns java.sql.Statement  ← RETURN TYPE TABLE
 *                 executeQuery() on java.sql.Statement           ← RESOLVED
 *
 *   3. Constructor type from "new" expressions
 *      - "new ObjectInputStream(fis).readObject()"
 *        ObjectInputStream → java.io.ObjectInputStream          ← CONSTRUCTOR TYPE
 *        readObject() on java.io.ObjectInputStream              ← RESOLVED
 */

import * as fs from 'fs';
import * as path from 'path';
import { CallSite } from '../types';
import { buildFullQualifiedName } from '../utils/java-utils';
import { buildVariableTypeMap, lookupVariableType, VarType } from './type-resolver';
import { lookupReturnType } from './return-type-table';

export interface RawMethodCall {
  receiver: string;
  method: string;
  line: number;
  column: number;
  enclosingClass: string;
  enclosingMethod: string;
  sourceLine: string;
}

export interface DeepCallResult {
  filePath: string;
  calls: RawMethodCall[];
}

/** Resolved receiver type with provenance info */
interface ResolvedReceiver {
  packageName: string;
  className: string;
  /** How we resolved it — for diagnostics */
  provenance: 'variable' | 'return-type' | 'constructor' | 'import' | 'qualified' | 'field' | 'fallback';
}

export class DeepCallScanner {
  private parser: any = null;
  private javaLang: any = null;
  private projectRoot: string;

  constructor(projectRoot: string) {
    this.projectRoot = projectRoot;
  }

  async init(): Promise<void> {
    const wts = require('web-tree-sitter');
    await wts.Parser.init();
    this.parser = new wts.Parser();
    const grammarPath = this.findJavaGrammarWasm();
    this.javaLang = await wts.Language.load(grammarPath);
    this.parser.setLanguage(this.javaLang);
  }

  private findJavaGrammarWasm(): string {
    const candidates = [
      // 1. 相对于当前文件（dist/analyzer/ → node_modules/）— 通用路径，优先
      path.join(__dirname, '..', '..', 'node_modules', 'tree-sitter-wasms', 'out', 'tree-sitter-java.wasm'),
      // 2. npm 全局安装路径
      path.join(process.env.HOME || '/root', '.npm-global', 'lib', 'node_modules', '@colbymchenry', 'codegraph', 'node_modules', 'tree-sitter-wasms', 'out', 'tree-sitter-java.wasm'),
      // 3. 本地开发路径（开发时使用）
      path.join(process.env.HOME || '/root', 'github', 'codegraph', 'node_modules', 'tree-sitter-wasms', 'out', 'tree-sitter-java.wasm'),
    ];
    for (const c of candidates) {
      if (fs.existsSync(c)) return c;
    }
    throw new Error(
      'Cannot find tree-sitter-java.wasm. ' +
      'Ensure @colbymchenry/codegraph is installed (npm install).\n' +
      'Searched: ' + candidates.join('\n         ')
    );
  }

  // ─── Scanning ────────────────────────────────────────────────────────

  scanFile(filePath: string): DeepCallResult {
    const fullPath = path.join(this.projectRoot, filePath);
    const source = fs.readFileSync(fullPath, 'utf-8');
    const tree = this.parser.parse(source);

    const calls: RawMethodCall[] = [];
    this.walkTree(tree.rootNode, source, '', '', calls);

    tree.delete();
    return { filePath, calls };
  }

  scanAll(): DeepCallResult[] {
    const results: DeepCallResult[] = [];
    for (const file of this.findJavaFiles()) {
      try {
        results.push(this.scanFile(file));
      } catch (e) {
        console.error(`Warning: Failed to scan ${file}: ${(e as Error).message}`);
      }
    }
    return results;
  }

  /**
   * Convert scan results to CallSites with precise type-resolved signatures.
   */
  toCallSites(results: DeepCallResult[]): CallSite[] {
    const sites: CallSite[] = [];

    for (const result of results) {
      const fullPath = path.join(this.projectRoot, result.filePath);
      const source = fs.readFileSync(fullPath, 'utf-8');
      const tree = this.parser.parse(source);

      // Build per-file context
      const imports = this.extractImports(tree.rootNode, source);
      const varTypes = buildVariableTypeMap(tree.rootNode, source, imports);
      // Also build catch parameter map
      const catchParams = this.buildCatchParamMap(tree.rootNode, source, imports);

      tree.delete();

      for (const call of result.calls) {
        const resolved = this.resolveReceiver(
          call.receiver, imports, result.filePath,
          call.enclosingClass, call.enclosingMethod,
          varTypes, catchParams,
        );

        const isConstructor = call.method === '<init>';
        const resolvedMethodName = isConstructor
          ? resolved.className
          : call.method;

        sites.push({
          callerFile: result.filePath,
          callerClass: call.enclosingClass,
          callerMethod: call.enclosingMethod,
          callerLine: call.line,
          calleeRawName: isConstructor
            ? `new ${call.receiver}()`
            : (call.receiver ? `${call.receiver}.${call.method}` : call.method),
          calleeReceiverName: call.receiver,
          calleeMethodName: resolvedMethodName,
          calleeResolved: resolved.provenance !== 'fallback',
          fullSignature: {
            packageName: resolved.packageName,
            className: resolved.className,
            methodName: resolvedMethodName,
            parameterTypes: [],
            fullQualifiedName: isConstructor
              ? buildFullQualifiedName(resolved.packageName, resolved.className, resolved.className, [])
              : buildFullQualifiedName(resolved.packageName, resolved.className, call.method, []),
            sourceLine: call.sourceLine,
          },
        });
      }
    }

    return sites;
  }

  // ─── Tree walking ────────────────────────────────────────────────────

  private walkTree(
    node: any, source: string,
    enclosingClass: string, enclosingMethod: string,
    calls: RawMethodCall[],
  ): void {
    if (node.type === 'class_declaration' || node.type === 'interface_declaration' || node.type === 'enum_declaration') {
      const n = node.childForFieldName('name');
      if (n) enclosingClass = source.substring(n.startIndex, n.endIndex);
    }

    if (node.type === 'method_declaration' || node.type === 'constructor_declaration') {
      const n = node.childForFieldName('name');
      enclosingMethod = n ? source.substring(n.startIndex, n.endIndex) : '<constructor>';
    }

    if (node.type === 'method_invocation') {
      const nameField = node.childForFieldName('name');
      const objectField = node.childForFieldName('object');

      if (nameField) {
        const method = source.substring(nameField.startIndex, nameField.endIndex);
        let receiver = '';
        if (objectField) {
          receiver = source.substring(objectField.startIndex, objectField.endIndex);
        }

        const line = node.startPosition.row + 1;
        const lines = source.split('\n');

        calls.push({
          receiver,
          method,
          line,
          column: node.startPosition.column,
          enclosingClass,
          enclosingMethod,
          sourceLine: lines[line - 1]?.trim() || '',
        });
      }
    }

    // ── Constructor calls: new Type(args) ──
    // object_creation_expression: "new FileInputStream(filename)"
    // We represent these as method="<init>", receiver=Type
    if (node.type === 'object_creation_expression') {
      const typeField = node.childForFieldName('type');
      if (typeField) {
        const typeName = source.substring(typeField.startIndex, typeField.endIndex);
        const line = node.startPosition.row + 1;
        const lines = source.split('\n');

        calls.push({
          receiver: typeName,
          method: '<init>',
          line,
          column: node.startPosition.column,
          enclosingClass,
          enclosingMethod,
          sourceLine: lines[line - 1]?.trim() || '',
        });
      }
    }

    for (let i = 0; i < node.childCount; i++) {
      const child = node.child(i);
      if (child) this.walkTree(child, source, enclosingClass, enclosingMethod, calls);
    }
  }

  // ─── Import extraction ───────────────────────────────────────────────

  private extractImports(rootNode: any, source: string): Map<string, string> {
    const imports = new Map<string, string>();
    for (let i = 0; i < rootNode.childCount; i++) {
      const child = rootNode.child(i);
      if (child && child.type === 'import_declaration') {
        const text = source.substring(child.startIndex, child.endIndex);
        const match = text.match(/import\s+(?:static\s+)?([a-zA-Z_][\w.]*);/);
        if (match && match[1]) {
          const fullName = match[1];
          const lastDot = fullName.lastIndexOf('.');
          if (lastDot > 0) {
            imports.set(fullName.substring(lastDot + 1), fullName);
          }
        }
      }
    }
    return imports;
  }

  // ─── Catch parameter tracking ────────────────────────────────────────

  /**
   * Build a map of catch parameter variables: scopeKey → (varName → VarType)
   * e.g. catch (Exception e) → e: java.lang.Exception
   */
  private buildCatchParamMap(
    rootNode: any, source: string, imports: Map<string, string>,
  ): Map<string, Map<string, VarType>> {
    const map = new Map<string, Map<string, VarType>>();
    this.collectCatchParams(rootNode, source, imports, '', '', map);
    return map;
  }

  private collectCatchParams(
    node: any, source: string, imports: Map<string, string>,
    enclosingClass: string, enclosingMethod: string,
    map: Map<string, Map<string, VarType>>,
  ): void {
    if (node.type === 'class_declaration' || node.type === 'interface_declaration' || node.type === 'enum_declaration') {
      const n = node.childForFieldName('name');
      if (n) enclosingClass = source.substring(n.startIndex, n.endIndex);
    }
    if (node.type === 'method_declaration' || node.type === 'constructor_declaration') {
      const n = node.childForFieldName('name');
      enclosingMethod = n ? source.substring(n.startIndex, n.endIndex) : '<constructor>';
    }

    if (node.type === 'catch_clause') {
      const param = node.childForFieldName('parameter');
      if (param) {
        const typeNode = param.childForFieldName('type');
        const nameNode = param.childForFieldName('name');
        if (typeNode && nameNode) {
          const typeText = source.substring(typeNode.startIndex, typeNode.endIndex).trim();
          const varName = source.substring(nameNode.startIndex, nameNode.endIndex).trim();
          const resolved = this.resolveTypeText(typeText, imports);
          if (resolved) {
            const scopeKey = `${enclosingClass}.${enclosingMethod}`;
            if (!map.has(scopeKey)) map.set(scopeKey, new Map());
            map.get(scopeKey)!.set(varName, resolved);
          }
        }
      }
    }

    for (let i = 0; i < node.childCount; i++) {
      this.collectCatchParams(node.child(i), source, imports, enclosingClass, enclosingMethod, map);
    }
  }

  // ─── Receiver type resolution (core) ─────────────────────────────────

  /**
   * Resolve the receiver (object) of a method call to its precise type.
   *
   * Handles 6 resolution strategies:
   *   1. Variable lookup (local vars, fields, catch params)
   *   2. Chained method call return type inference
   *   3. Constructor "new" expression type
   *   4. Fully-qualified name (java.sql.Statement)
   *   5. Import resolution
   *   6. Fallback (unresolved variable name)
   */
  private resolveReceiver(
    receiver: string,
    imports: Map<string, string>,
    filePath: string,
    enclosingClass: string,
    enclosingMethod: string,
    varTypes: Map<string, Map<string, VarType>>,
    catchParams: Map<string, Map<string, VarType>>,
  ): ResolvedReceiver {

    // ── No receiver ──
    if (!receiver) {
      const pkg = this.packageFromFilePath(filePath);
      return { packageName: pkg, className: enclosingClass, provenance: 'field' };
    }

    // ── Strip "this." / "super." prefix ──
    let cleaned = receiver;
    if (receiver.startsWith('this.')) {
      cleaned = receiver.substring(5);
    } else if (receiver.startsWith('super.')) {
      cleaned = receiver.substring(6);
    }

    // ── Strategy 2: Chained method call ──
    // tree-sitter represents "conn.createStatement().executeQuery()" as:
    //   outer method_invocation: name=executeQuery, object=method_invocation(name=createStatement, object=identifier(conn))
    // But by the time we get here, receiver is the raw text "conn.createStatement()"
    // We can detect this: if the receiver text ends with ")" and contains a method call pattern,
    // parse it as innerReceiver.innerMethod(args)
    const chainMatch = this.parseChainedReceiver(cleaned);
    if (chainMatch) {
      const innerResolved = this.resolveReceiver(
        chainMatch.innerReceiver, imports, filePath,
        enclosingClass, enclosingMethod, varTypes, catchParams,
      );
      if (innerResolved.provenance !== 'fallback') {
        const innerFullClass = innerResolved.packageName
          ? `${innerResolved.packageName}.${innerResolved.className}`
          : innerResolved.className;
        const returnType = lookupReturnType(innerFullClass, chainMatch.innerMethod);
        if (returnType) {
          return {
            packageName: returnType.packageName,
            className: returnType.className,
            provenance: 'return-type',
          };
        }
      }
      // Can't resolve chain — fall through to other strategies
    }

    // ── Strategy 3: Constructor "new Type(...)" ──
    const newMatch = cleaned.match(/^new\s+([A-Za-z_][\w.]*)\s*\(/);
    if (newMatch && newMatch[1]) {
      const resolved = this.resolveTypeText(newMatch[1], imports);
      if (resolved) {
        return { ...resolved, provenance: 'constructor' };
      }
    }

    // ── Strategy 1: Variable lookup ──
    // Try local vars → catch params → fields
    const varType = lookupVariableType(cleaned, enclosingClass, enclosingMethod, varTypes);
    if (varType) {
      return { ...varType, provenance: 'variable' };
    }

    // Try catch params
    const scopeKey = `${enclosingClass}.${enclosingMethod}`;
    const catchScope = catchParams.get(scopeKey);
    if (catchScope && catchScope.has(cleaned)) {
      const ct = catchScope.get(cleaned)!;
      return { ...ct, provenance: 'variable' };
    }

    // ── Strategy 4: Fully-qualified name ──
    if (cleaned.includes('.') && /^[a-z]/.test(cleaned)) {
      const lastDot = cleaned.lastIndexOf('.');
      return {
        packageName: cleaned.substring(0, lastDot),
        className: cleaned.substring(lastDot + 1),
        provenance: 'qualified',
      };
    }

    // ── Strategy 5: Import match (explicit + java.lang implicit) ──
    // java.lang.* classes are auto-imported in every Java file
    // Plus common JDK classes used in security-sensitive code
    const jdkAutoImports: Record<string, string> = {
      // java.lang.*
      'String': 'java.lang.String', 'Integer': 'java.lang.Integer', 'Long': 'java.lang.Long',
      'Double': 'java.lang.Double', 'Float': 'java.lang.Float', 'Boolean': 'java.lang.Boolean',
      'Object': 'java.lang.Object', 'Class': 'java.lang.Class', 'System': 'java.lang.System',
      'Runtime': 'java.lang.Runtime', 'Process': 'java.lang.Process',
      'Thread': 'java.lang.Thread', 'Math': 'java.lang.Math',
      'Exception': 'java.lang.Exception', 'RuntimeException': 'java.lang.RuntimeException',
      'Throwable': 'java.lang.Throwable', 'Error': 'java.lang.Error',
      'StringBuilder': 'java.lang.StringBuilder', 'StringBuffer': 'java.lang.StringBuffer',
      'Comparable': 'java.lang.Comparable', 'Iterable': 'java.lang.Iterable',
      // java.io.*
      'FileInputStream': 'java.io.FileInputStream', 'FileOutputStream': 'java.io.FileOutputStream',
      'FileReader': 'java.io.FileReader', 'FileWriter': 'java.io.FileWriter',
      'File': 'java.io.File', 'InputStream': 'java.io.InputStream', 'OutputStream': 'java.io.OutputStream',
      'BufferedReader': 'java.io.BufferedReader', 'BufferedWriter': 'java.io.BufferedWriter',
      'InputStreamReader': 'java.io.InputStreamReader', 'OutputStreamWriter': 'java.io.OutputStreamWriter',
      'ObjectInputStream': 'java.io.ObjectInputStream', 'ObjectOutputStream': 'java.io.ObjectOutputStream',
      'PrintWriter': 'java.io.PrintWriter', 'PrintStream': 'java.io.PrintStream',
      'Serializable': 'java.io.Serializable',
      // java.net.*
      'URL': 'java.net.URL', 'HttpURLConnection': 'java.net.HttpURLConnection',
      'URLConnection': 'java.net.URLConnection', 'Socket': 'java.net.Socket',
      'ServerSocket': 'java.net.ServerSocket', 'InetAddress': 'java.net.InetAddress',
      // java.sql.*
      'Connection': 'java.sql.Connection', 'Statement': 'java.sql.Statement',
      'PreparedStatement': 'java.sql.PreparedStatement', 'ResultSet': 'java.sql.ResultSet',
      'DriverManager': 'java.sql.DriverManager',
      // javax.crypto.*
      'Cipher': 'javax.crypto.Cipher', 'KeyGenerator': 'javax.crypto.KeyGenerator',
      'SecretKey': 'javax.crypto.SecretKey', 'Mac': 'javax.crypto.Mac',
      'SecretKeySpec': 'javax.crypto.spec.SecretKeySpec',
      'DESKeySpec': 'javax.crypto.spec.DESKeySpec', 'DESedeKeySpec': 'javax.crypto.spec.DESedeKeySpec',
      'IvParameterSpec': 'javax.crypto.spec.IvParameterSpec',
      // java.security.*
      'MessageDigest': 'java.security.MessageDigest', 'Signature': 'java.security.Signature',
      'KeyPairGenerator': 'java.security.KeyPairGenerator', 'SecureRandom': 'java.security.SecureRandom',
      // javax.xml.parsers.*
      'DocumentBuilderFactory': 'javax.xml.parsers.DocumentBuilderFactory',
      'DocumentBuilder': 'javax.xml.parsers.DocumentBuilder',
      'SAXParserFactory': 'javax.xml.parsers.SAXParserFactory',
      'SAXParser': 'javax.xml.parsers.SAXParser',
      // javax.xml.xpath.*
      'XPathFactory': 'javax.xml.xpath.XPathFactory',
      'XPath': 'javax.xml.xpath.XPath', 'XPathExpression': 'javax.xml.xpath.XPathExpression',
      // javax.naming.*
      'Context': 'javax.naming.Context', 'InitialContext': 'javax.naming.InitialContext',
      'DirContext': 'javax.naming.directory.DirContext',
      'InitialDirContext': 'javax.naming.directory.InitialDirContext',
      'NamingEnumeration': 'javax.naming.NamingEnumeration',
      'SearchControls': 'javax.naming.directory.SearchControls',
      'SearchResult': 'javax.naming.directory.SearchResult',
      // java.util.*
      'Random': 'java.util.Random', 'ArrayList': 'java.util.ArrayList',
      'HashMap': 'java.util.HashMap', 'Hashtable': 'java.util.Hashtable',
      'List': 'java.util.List', 'Map': 'java.util.Map', 'Set': 'java.util.Set',
      'Collections': 'java.util.Collections', 'Arrays': 'java.util.Arrays',
      'Properties': 'java.util.Properties',
      // javax.servlet.*
      'HttpServletRequest': 'javax.servlet.http.HttpServletRequest',
      'HttpServletResponse': 'javax.servlet.http.HttpServletResponse',
      // java.util.logging.*
      'Logger': 'java.util.logging.Logger',
    };

    // Check explicit imports first
    if (imports.has(cleaned)) {
      const full = imports.get(cleaned)!;
      const lastDot = full.lastIndexOf('.');
      return {
        packageName: full.substring(0, lastDot),
        className: full.substring(lastDot + 1),
        provenance: 'import',
      };
    }

    // Then check JDK auto-imports
    if (jdkAutoImports[cleaned]) {
      const full = jdkAutoImports[cleaned];
      const lastDot = full.lastIndexOf('.');
      return {
        packageName: full.substring(0, lastDot),
        className: full.substring(lastDot + 1),
        provenance: 'import',
      };
    }

    // ── Strategy 6: Fallback ──
    return { packageName: '', className: cleaned, provenance: 'fallback' };
  }

  /**
   * Parse a chained receiver like "conn.createStatement()" or "runtime.exec(\"ls\")"
   * into { innerReceiver, innerMethod }.
   *
   * Returns null if not a chained call.
   */
  private parseChainedReceiver(receiver: string): { innerReceiver: string; innerMethod: string } | null {
    // Must contain a method call pattern: something.methodName(...)
    // But NOT just a simple identifier (that's not a chain)
    if (!receiver.includes('(')) return null;
    if (!receiver.includes('.')) return null;

    // Find the LAST dot before the first '(' — that separates method from receiver
    const parenIdx = receiver.indexOf('(');
    if (parenIdx < 0) return null;

    // Find the last dot before the paren
    let lastDotBeforeParen = -1;
    for (let i = parenIdx - 1; i >= 0; i--) {
      if (receiver[i] === '.') {
        lastDotBeforeParen = i;
        break;
      }
    }
    if (lastDotBeforeParen < 0) return null;

    const innerMethod = receiver.substring(lastDotBeforeParen + 1, parenIdx).trim();
    if (!innerMethod || !/^[a-zA-Z_]\w*$/.test(innerMethod)) return null;

    // The innerReceiver is everything before the last dot
    // e.g. "conn.createStatement()" → innerReceiver = "conn", innerMethod = "createStatement"
    // e.g. "a.b.c()" → innerReceiver = "a.b", innerMethod = "c"
    let innerReceiver = receiver.substring(0, lastDotBeforeParen).trim();

    // But we need to handle cases like "new ObjectInputStream(fis)" — not a chain
    if (innerReceiver.startsWith('new ')) return null;

    // Strip any trailing parenthesized content from innerReceiver
    // e.g. "runtime.exec(\"ls\")" with method="waitFor" doesn't apply here
    // because the whole receiver IS the chained call
    // The receiver text for the outer call would be "runtime.exec(\"ls\")"
    // and we want innerReceiver="runtime", innerMethod="exec"

    return { innerReceiver, innerMethod };
  }

  // ─── Type text resolution ────────────────────────────────────────────

  private resolveTypeText(typeText: string, imports: Map<string, string>): VarType | null {
    // Strip generics, arrays, varargs
    let clean = typeText.replace(/<.*>/, '').replace(/\[\]$/, '').replace(/\.\.\.+$/, '').trim();
    if (!clean) return null;

    // Fully qualified
    if (clean.includes('.') && /^[a-z]/.test(clean)) {
      const lastDot = clean.lastIndexOf('.');
      return {
        fullClassName: clean,
        packageName: clean.substring(0, lastDot),
        className: clean.substring(lastDot + 1),
      };
    }

    // Short name → resolve
    const resolved = this.resolveShortTypeName(clean, imports);
    if (resolved.includes('.')) {
      const lastDot = resolved.lastIndexOf('.');
      return {
        fullClassName: resolved,
        packageName: resolved.substring(0, lastDot),
        className: resolved.substring(lastDot + 1),
      };
    }

    return { fullClassName: resolved, packageName: '', className: resolved };
  }

  /** Resolve short type name using imports + built-in JDK map */
  private resolveShortTypeName(shortName: string, imports: Map<string, string>): string {
    const JDK_TYPES: Record<string, string> = {
      'String': 'java.lang.String', 'Integer': 'java.lang.Integer', 'Long': 'java.lang.Long',
      'Double': 'java.lang.Double', 'Float': 'java.lang.Float', 'Boolean': 'java.lang.Boolean',
      'Object': 'java.lang.Object', 'Class': 'java.lang.Class', 'Exception': 'java.lang.Exception',
      'RuntimeException': 'java.lang.RuntimeException', 'Throwable': 'java.lang.Throwable',
      'List': 'java.util.List', 'Map': 'java.util.Map', 'Set': 'java.util.Set',
      'ArrayList': 'java.util.ArrayList', 'HashMap': 'java.util.HashMap',
      'Connection': 'java.sql.Connection', 'Statement': 'java.sql.Statement',
      'PreparedStatement': 'java.sql.PreparedStatement', 'ResultSet': 'java.sql.ResultSet',
      'CallableStatement': 'java.sql.CallableStatement',
      'ObjectInputStream': 'java.io.ObjectInputStream', 'FileInputStream': 'java.io.FileInputStream',
      'IOException': 'java.io.IOException', 'InputStream': 'java.io.InputStream',
      'OutputStream': 'java.io.OutputStream', 'Reader': 'java.io.Reader', 'Writer': 'java.io.Writer',
      'File': 'java.io.File', 'Process': 'java.lang.Process', 'Runtime': 'java.lang.Runtime',
      'ProcessBuilder': 'java.lang.ProcessBuilder', 'Thread': 'java.lang.Thread',
      'Runnable': 'java.lang.Runnable',
      'URL': 'java.net.URL', 'URI': 'java.net.URI',
      'BigDecimal': 'java.math.BigDecimal', 'BigInteger': 'java.math.BigInteger',
      'Date': 'java.util.Date', 'Optional': 'java.util.Optional',
      'Path': 'java.nio.file.Path',
      'ScriptEngine': 'javax.script.ScriptEngine',
      'SSLContext': 'javax.net.ssl.SSLContext',
    };

    if (JDK_TYPES[shortName]) return JDK_TYPES[shortName];
    if (imports.has(shortName)) return imports.get(shortName)!;
    return shortName;
  }

  // ─── Helpers ─────────────────────────────────────────────────────────

  private packageFromFilePath(filePath: string): string {
    const withoutExt = filePath.replace(/\.java$/, '');
    for (const p of [/src\/main\/java\/(.+)/, /src\/test\/java\/(.+)/, /src\/(.+)/]) {
      const m = withoutExt.match(p);
      if (m && m[1]) {
        const parts = m[1].split('/');
        if (parts.length > 1) {
          parts.pop();
          return parts.join('.');
        }
      }
    }
    return '';
  }

  private findJavaFiles(): string[] {
    const files: string[] = [];
    const skip = new Set(['.git', '.codegraph', '.javalint', 'node_modules', 'target', 'build', '.gradle']);
    const walk = (dir: string) => {
      try {
        for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
          if (skip.has(entry.name)) continue;
          const full = path.join(dir, entry.name);
          if (entry.isDirectory()) walk(full);
          else if (entry.name.endsWith('.java')) files.push(path.relative(this.projectRoot, full));
        }
      } catch { /* ignore */ }
    };
    walk(this.projectRoot);
    return files;
  }

  close(): void {
    if (this.parser) this.parser.delete();
  }
}
