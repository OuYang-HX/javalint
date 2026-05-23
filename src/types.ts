/**
 * JavaLint 类型定义
 */

/** 已解析的类型信息 */
export interface ResolvedType {
  /** 完全限定类名，如 "java.sql.Statement" */
  fullClassName: string;
  /** 包名，如 "java.sql" */
  packageName: string;
  /** 短类名，如 "Statement" */
  className: string;
}

/** 方法完整签名 */
export interface MethodSignature {
  packageName: string;
  className: string;
  methodName: string;
  parameterTypes: string[];
  fullQualifiedName: string;
  sourceLine: string;
}

/** 调用点 */
export interface CallSite {
  callerFile: string;
  callerClass: string;
  callerMethod: string;
  callerLine: number;
  calleeRawName: string;
  calleeReceiverName: string;
  calleeMethodName: string;
  calleeResolved: boolean;
  calleeNode?: {
    qualifiedName: string;
    signature: string;
    filePath: string;
  };
  fullSignature: MethodSignature;
  /** 跨文件污点传播链（如果有） */
  taintChain?: TaintChainInfo;
}

/** 规则定义 */
export interface Rule {
  id: string;
  name: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  description: string;
  signaturePatterns: string[];
  checkScript?: string;
  tags: string[];
  /** Whether this rule requires cross-file taint analysis */
  requiresTaintAnalysis?: boolean;
}

/** 检查结果 */
export interface CheckResult {
  alert: boolean;
  message?: string;
  confidence?: 'high' | 'medium' | 'low';
}

/** 污点链信息（跨文件传播路径） */
export interface TaintChainInfo {
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

/** 告警记录 */
export interface Alert {
  ruleId: string;
  ruleName: string;
  severity: string;
  message: string;
  confidence: string;
  filePath: string;
  line: number;
  packageName: string;
  className: string;
  methodName: string;
  parameterTypes: string[];
  fullSignature: string;
  callerClass: string;
  callerMethod: string;
  sourceLine: string;
  detectedAt: number;
  /** 跨文件污点传播链（如果有） */
  taintChain?: TaintChainInfo;
}

/** 分析结果 */
export interface AnalysisResult {
  totalCallSites: number;
  alerts: Alert[];
  alertCount: number;
  durationMs: number;
  /** 污点分析统计 */
  taintStats?: {
    sourcesFound: number;
    chainsFound: number;
    methodsAnalyzed: number;
  };
}
