/**
 * ScriptContext — 传递给规则检查脚本的丰富上下文信息
 *
 * 设计原则：
 *   1. 所有脚本语言（JS/Groovy/Python）收到完全相同的 JSON 结构
 *   2. 高内聚：每个子对象职责单一，边界清晰
 *   3. 低耦合：脚本只读不写，不依赖 JavaLint 内部实现
 *   4. 结构化：脚本拿到后直接用属性判断，不需要解析字符串
 *
 * 结构概览：
 *   {
 *     sink:       危险函数本身的签名信息
 *     method:     危险函数所在方法的签名信息
 *     params:     危险函数每个参数的来源追踪（结构化）
 *     objHistory: 危险函数对象的调用历史
 *     retUsage:   危险函数返回值的后续使用
 *     taintChain: 跨文件污点传播链（如果有）
 *   }
 */

// ─── Sink: 危险函数签名 ────────────────────────────────────────────

/** 危险函数（sink）的完整签名信息 */
export interface SinkInfo {
  /** 完全限定签名，如 "java.sql.Statement.executeQuery()" */
  fullSignature: string;
  /** 包名，如 "java.sql" */
  packageName: string;
  /** 类名，如 "Statement" */
  className: string;
  /** 方法名，如 "executeQuery" */
  methodName: string;
  /** 参数类型列表，如 ["java.lang.String"] */
  parameterTypes: string[];
  /** 源码行文本 */
  sourceLine: string;
  /** 所在文件路径 */
  filePath: string;
  /** 行号 */
  line: number;
}

// ─── Method: 危险函数所在方法的签名 ───────────────────────────────

/** 危险函数所在方法的签名信息 */
export interface MethodInfo {
  /** 方法所在类的短名，如 "UserService" */
  className: string;
  /** 方法名，如 "findByUsername" */
  methodName: string;
  /** 方法完整签名，如 "User findByUsername(String username)" */
  signature: string;
  /** 方法参数列表 */
  parameters: MethodParameter[];
  /** 方法所在文件 */
  filePath: string;
  /** 方法起始行 */
  startLine: number;
  /** 方法结束行 */
  endLine: number;
}

/** 方法参数信息 */
export interface MethodParameter {
  /** 参数类型，如 "String" */
  type: string;
  /** 参数名，如 "username" */
  name: string;
}

// ─── Params: 危险函数每个参数的来源追踪 ──────────────────────────

/**
 * 参数来源追踪结果
 *
 * 核心改进：不再把信息塞进一个字符串让脚本自己解析，
 * 而是拆成结构化字段，脚本直接用。
 *
 * 例子——SQL注入场景：
 *   stmt.executeQuery("SELECT * FROM users WHERE username = '" + username + "'")
 *
 * 参数0 (sql变量) 的来源：
 *   {
 *     position: 0,
 *     type: "String",
 *     isHardcoded: false,
 *     isExternalInput: true,
 *     isTainted: true,
 *     composite: "concat",               // 拼接式来源
 *     parts: [
 *       { kind: "hardcoded", value: "SELECT * FROM users WHERE username = '" },
 *       { kind: "external_input",         // 直接可判断
 *         source: "method_parameter",
 *         name: "username",
 *         type: "String",
 *         crossFile: true,
 *         callerMethod: "UserController.handleGetUser",
 *         callerFile: "src/.../UserController.java" },
 *       { kind: "hardcoded", value: "'" },
 *     ]
 *   }
 *
 * 脚本只需检查：
 *   if (param.isExternalInput) { ... }
 *   if (param.composite === 'concat' && param.parts.some(p => p.kind === 'external_input')) { ... }
 */
export interface ParamSourceInfo {
  /** 参数在危险函数签名中的位置（0-based） */
  position: number;
  /** 参数类型，如 "String", "int" */
  type: string;

  // ── 便捷布尔标志（脚本直接判断，无需遍历 parts）──
  /** 是否包含硬编码值 */
  isHardcoded: boolean;
  /** 是否包含外部输入 */
  isExternalInput: boolean;
  /** 是否受污染（= isExternalInput，语义上更直观） */
  isTainted: boolean;
  /** 来源是否可确定（排除 unknown） */
  isResolvable: boolean;

  // ── 来源组合方式 ──
  /**
   * 参数值的组合方式：
   *   - "direct"     直接来源（单变量或字面量）
   *   - "concat"     字符串拼接（多个 parts 拼接）
   *   - "method_return"  方法返回值
   *   - "field"      类字段
   *   - "unknown"    无法确定
   */
  composite: 'direct' | 'concat' | 'method_return' | 'field' | 'unknown';

  // ── 详细来源拆分 ──
  /** 组成此参数的各个部分（拼接场景下会有多个） */
  parts: ParamPart[];

  /** 置信度 */
  confidence: 'high' | 'medium' | 'low';
}

/**
 * 参数值的一个组成部分
 *
 * kind 决定了其他哪些字段有意义：
 *   - hardcoded      → value
 *   - external_input → source, name, type, crossFile, callerMethod, callerFile
 *   - method_return  → methodSignature
 *   - field          → fieldName, fieldType
 *   - variable       → varName
 *   - unknown        → (无额外字段)
 */
export interface ParamPart {
  /** 此部分的来源类别 */
  kind: 'hardcoded' | 'external_input' | 'tainted' | 'method_return' | 'field' | 'variable' | 'unknown';

  // ── hardcoded ──
  /** 硬编码的具体值 */
  value?: string;

  // ── external_input ──
  /** 外部输入的更细粒度来源 */
  source?: 'method_parameter' | 'servlet_request' | 'spring_annotation' | 'system_env' | 'config' | 'variable_pattern' | 'unresolved';
  /** 变量/参数名 */
  name?: string;
  /** 类型 */
  type?: string;
  /** 是否跨文件传入 */
  crossFile?: boolean;
  /** 跨文件调用者方法名 */
  callerMethod?: string;
  /** 跨文件调用者所在文件 */
  callerFile?: string;

  // ── method_return ──
  /** 方法签名 */
  methodSignature?: string;

  // ── field ──
  /** 字段名 */
  fieldName?: string;
  /** 字段类型 */
  fieldType?: string;

  // ── variable ──
  /** 局部变量名 */
  varName?: string;
}

// ─── ObjHistory: 危险函数对象的调用历史 ──────────────────────────

/** 对象的调用/使用历史 */
export interface ObjectHistoryInfo {
  /** 对象变量名，如 "stmt" */
  objectName: string;
  /** 对象类型，如 "java.sql.Statement" */
  objectType: string;
  /** 对象创建方式 */
  creationInfo: {
    /** 如何创建的 */
    method: string;
    /** 创建时的签名 */
    signature: string;
    /** 所在行 */
    line: number;
  };
  /** 此对象此前被调用过的函数（对象作为调用者） */
  priorCalls: ObjectCallRecord[];
  /** 此对象此前被作为参数传入的函数（对象作为被操作者） */
  priorPassedTo: ObjectCallRecord[];
}

/** 对象的函数调用记录 */
export interface ObjectCallRecord {
  /** 函数签名 */
  signature: string;
  /** 函数所在文件 */
  filePath: string;
  /** 行号 */
  line: number;
  /** 调用方向：called=对象主动调用, passedTo=对象被传入 */
  direction: 'called' | 'passedTo';
}

// ─── RetUsage: 危险函数返回值的后续使用 ──────────────────────────

/** 返回值后续使用信息 */
export interface ReturnUsageInfo {
  /** 返回值类型，如 "boolean", "ResultSet" */
  returnType: string;
  /** 返回值后续被调用的函数（返回值作为接收者） */
  subsequentCalls: ReturnCallRecord[];
  /** 返回值被作为参数传入的函数 */
  subsequentPassedTo: ReturnCallRecord[];
  /** 返回值被赋值给的变量 */
  assignedTo: string[];
}

/** 返回值后续调用记录 */
export interface ReturnCallRecord {
  /** 函数签名 */
  signature: string;
  /** 函数所在文件 */
  filePath: string;
  /** 行号 */
  line: number;
  /** 使用方式：called=返回值作为接收者调用, passedTo=返回值作为参数传入 */
  usage: 'called' | 'passedTo';
}

// ─── TaintChain: 跨文件污点传播链 ─────────────────────────────────

/** 污点传播链信息 */
export interface TaintChainContext {
  /** 污点源方法名 */
  sourceMethod: string;
  /** 污点源文件 */
  sourceFile: string;
  /** 污点源参数名 */
  sourceParameters: string[];
  /** 传播路径描述，如 "handleGetUser → findByUsername" */
  propagationPath: string;
  /** 传播深度（跳数） */
  depth: number;
  /** 污点链置信度 */
  confidence: 'high' | 'medium' | 'low';
  /** 污点来源原因 */
  sourceReason: string;
}

// ─── ScriptContext: 完整上下文 ────────────────────────────────────

/** 传递给规则检查脚本的完整上下文 */
export interface ScriptContext {
  /** 危险函数（sink）的签名信息 */
  sink: SinkInfo;
  /** 危险函数所在方法的签名信息 */
  method: MethodInfo;
  /** 危险函数每个参数的来源追踪（结构化） */
  params: ParamSourceInfo[];
  /** receiver 变量的构造参数来源追踪（如 processBuilder = new ProcessBuilder(commands)） */
  receiverParams: ParamSourceInfo[];
  /** 危险函数对象的调用历史 */
  objHistory: ObjectHistoryInfo | null;
  /** 危险函数返回值的后续使用 */
  retUsage: ReturnUsageInfo | null;
  /** 跨文件污点传播链（如果有） */
  taintChain: TaintChainContext | null;
}

/** 脚本检查结果（所有语言统一格式） */
export interface ScriptCheckResult {
  alert: boolean;
  message?: string;
  confidence?: 'high' | 'medium' | 'low';
}