# JavaLint — 设计与实现文档

> **版本**: v0.2.0 | **最后更新**: 2026-05-23
> **项目地址**: `/home/oyhx/github/javalint/`
> **本文档是代码实现的精确映射，后续开发以此为依据。**

---

## 1. 项目概述

JavaLint 是一个 Java 静态代码安全检查工具，基于 CodeGraph 的跨文件知识图谱和 tree-sitter 的精确 AST 解析，检测项目代码中的安全漏洞——SQL 注入、反序列化 RCE、命令注入、路径穿越、SSRF、XXE、XPath/LDAP/JNDI 注入、硬编码密钥、弱加密算法、不安全反射、不安全随机数、日志注入等。

**核心能力**：

| 能力 | 说明 |
|---|---|
| **全量方法调用提取** | tree-sitter 解析 Java 源文件，捕获 `method_invocation` + `object_creation_expression` 节点 |
| **精确类型解析** | 变量声明追踪 + JDK API 索引 + 继承链查找 + static final String 常量值求解 |
| **跨文件污点追踪** | CodeGraph 图遍历 + 启发式参数名模式匹配，追踪数据从 Controller 到 Service 到危险 sink 的传播 |
| **多语言脚本引擎** | JS (require, 零延迟) / Python (子进程) / Groovy (子进程)，统一 ScriptContext JSON |
| **结构化参数来源** | `ParamSourceInfo` 布尔标志 + `composite` 枚举 + `ParamPart[]` 判别联合，脚本直接用属性判断 |
| **零修改 CodeGraph** | 仅作为 npm 依赖 + DB 只读引用 |

**约束**：零修改 CodeGraph 源码，仅通过 npm 依赖和 SQLite DB 只读引用。

---

## 2. 四层架构总览

```
┌─────────────────────────────────────────────────────────────────────┐
│                      JavaLint CLI (bin/javalint.ts)                  │
│                      analyze | graph | list-rules                    │
└────────────────────────────┬────────────────────────────────────────┘
                             │
┌────────────────────────────▼────────────────────────────────────────┐
│                     JavaLint 主类 (index.ts)                         │
│              init → analyze (4-layer) → print/save                    │
└─────┬──────────┬──────────┬──────────┬──────────────────────────────┘
      │          │          │          │
┌─────▼─────┐ ┌──▼───────┐ ┌▼────────┐ ┌▼─────────────────────────────┐
│ Layer 1   │ │ Layer 2  │ │Layer 3  │ │ Layer 4                      │
│ Deep Scan │ │CodeGraph │ │Rule Eng.│ │ Taint Analysis               │
│ tree-sitter│ │Enrichment│ │+Context │ │ Cross-file propagation       │
│           │ │          │ │+Scripts │ │ Identify sources → Track flow│
└─────┬─────┘ └────┬─────┘ └────┬────┘ └──────┬───────────────────────┘
      │            │            │              │
  ┌───▼──┐   ┌────▼────┐  ┌───▼──────┐  ┌────▼────────┐
  │Type  │   │CallColl.│  │ParamRes. │  │CodeGraph    │
  │Resolv│   │(CG DB)  │  │+ScriptCtx│  │Traverser    │
  └──────┘   └─────────┘  └──────────┘  │+TaintTracker│
                                         └─────────────┘
  ┌──────────┐  ┌───────────┐  ┌────────────────┐
  │Return    │  │JDK API    │  │Alert DB        │
  │Type Table│  │Index      │  │(.javalint/     │
  │          │  │(.json/.db)│  │ alerts.db)     │
  └──────────┘  └───────────┘  └────────────────┘
```

**分析流程**：

```
init()
  ├── DeepCallScanner.init()         // 加载 tree-sitter + Java grammar WASM
  ├── CallCollector (可选)            // 如果 .codegraph/ 存在，只读打开
  ├── CodeGraphTraverser (可选)       // 初始化图遍历器
  ├── TaintTracker (可选)             // 初始化污点追踪器
  ├── RuleEngine.loadRules()         // 从 rules/ 目录加载 YAML + JS/Py/Groovy
  └── AlertDatabase 初始化           // .javalint/alerts.db

analyze()
  ├── Layer 1: Deep Scan             // tree-sitter 解析所有 Java 文件，提取方法调用 + 构造器调用
  ├── Layer 2: CodeGraph Enrichment   // 用已解析调用补充签名，按 (file, line, method) 去重
  ├── Layer 3: Rule Matching          // 签名 glob → regex 匹配 + 构建 ScriptContext + 多引擎执行脚本
  └── Layer 4: Taint Analysis        // 识别污点源 → 追踪传播链 → 增强告警的污点链信息
```

---

## 3. 项目结构

```
javalint/
├── package.json                    # 依赖: codegraph, commander, web-tree-sitter, yaml
├── tsconfig.json
├── scripts/
│   └── build-jdk-index.js          # javap -public -s → 紧凑 JSON + SQLite
├── src/
│   ├── index.ts                    # JavaLint 主类 (~300行)
│   ├── types.ts                    # 所有接口定义 (CallSite, Alert, TaintChainInfo 等)
│   ├── bin/
│   │   └── javalint.ts             # CLI: analyze, list-rules, graph (180行)
│   ├── analyzer/
│   │   ├── deep-call-scanner.ts    # tree-sitter 全量调用提取 (654行)
│   │   ├── type-resolver.ts        # 变量声明→类型追踪 (518行)
│   │   ├── return-type-table.ts    # JDK API 索引查询 (261行)
│   │   ├── call-collector.ts       # CodeGraph DB 已解析调用读取 (293行)
│   │   ├── codegraph-traverser.ts  # 跨文件图遍历 (447行)
│   │   ├── taint-tracker.ts        # 污点追踪 (501行)
│   │   ├── jdk-api-index.json      # 紧凑格式 JDK 索引 (505 KB)
│   │   └── jdk-api-index.db        # SQLite 格式索引 (924 KB, 可选)
│   ├── rules/
│   │   ├── rule-engine.ts          # 规则匹配 + 多引擎脚本执行 (600行)
│   │   ├── script-engine.ts        # 引擎接口 + 注册表 (69行)
│   │   ├── script-context.ts       # ScriptContext 类型定义 (293行)
│   │   ├── param-resolver.ts       # 参数来源解析 (673行)
│   │   ├── js-engine.ts            # Node.js require() 引擎 (57行)
│   │   ├── groovy-engine.ts        # Groovy 子进程引擎 (106行)
│   │   └── python-engine.ts        # Python 子进程引擎 (108行)
│   ├── db/
│   │   ├── alert-database.ts       # 告警 CRUD (165行)
│   │   └── schema.sql              # alerts 表 DDL (含污点链字段)
│   └── utils/
│       └── java-utils.ts           # 签名解析、类型增强工具 (128行)
├── rules/                          # 13 条内置规则
│   ├── sql-injection.yaml/.js/.py/.groovy
│   ├── dangerous-deserialization.yaml/.js
│   ├── command-injection.yaml/.js
│   ├── cross-file-taint.yaml/.js
│   ├── path-traversal.yaml/.js
│   ├── ssrf.yaml/.js
│   ├── xxe.yaml/.js
│   ├── xpath-ldap-jndi.yaml/.js
│   ├── hardcoded-secrets.yaml/.js
│   ├── weak-crypto.yaml/.js
│   ├── unsafe-reflection.yaml/.js
│   ├── insecure-random.yaml/.js
│   └── log-injection.yaml/.js
└── demo-java-project/              # 7 个 Java 文件，30 个已知漏洞
    └── src/main/java/com/example/
        ├── controller/UserController.java
        ├── model/User.java
        ├── service/AuthService.java
        ├── service/FileService.java
        ├── service/ReportService.java
        ├── service/UserService.java
        └── util/DataUtils.java
```

**代码量**: 5053 行 TypeScript + ~1000 行 JS/Python/Groovy 脚本 + ~250 行规则 YAML + ~320 行演示 Java

---

## 4. 核心模块详细设计

### 4.1 DeepCallScanner — 全量调用提取

**文件**: `src/analyzer/deep-call-scanner.ts` (654 行)

**职责**: 用 tree-sitter 解析 Java 源文件，提取所有 `method_invocation` 和 `object_creation_expression` AST 节点。

**为什么不用 CodeGraph**: CodeGraph 的 `unresolved_refs` 表为空——所有对 JDK/Maven 外部依赖的调用被静默丢弃。Deep Scanner 是检测外部危险调用的唯一路径。

**扫描策略**:

| AST 节点类型 | 提取内容 | 表示方式 |
|---|---|---|
| `method_invocation` | receiver + method | `receiver="stmt", method="executeQuery"` |
| `object_creation_expression` | type + `<init>` | `receiver="FileInputStream", method="<init>"` |

**构造器调用检测**（v0.2.0 新增）:

```
源码: new FileInputStream(fullPath)

AST: object_creation_expression
  type: "FileInputStream"
  arguments: (fullPath)

转换: receiver="FileInputStream", method="<init>"
FQN: "java.io.FileInputStream.FileInputStream()"
```

**类型解析管线（5 层）**:

| 层 | 来源 | 示例 |
|---|---|---|
| **1. 变量声明追踪** | TypeResolver | `Statement stmt = ...` → `stmt: java.sql.Statement` |
| **2. try-with-resources** | TypeResolver | `try (PreparedStatement ps = ...)` → `ps: java.sql.PreparedStatement` |
| **3. 返回类型查找** | ReturnTypeTable | `conn.createStatement()` → 返回 `java.sql.Statement` |
| **4. 构造器类型** | `new` 表达式 | `new ObjectInputStream(fis)` → `java.io.ObjectInputStream` |
| **5. 静态方法调用** | 类名直接引用 | `Cipher.getInstance("DES")` → `javax.crypto.Cipher` |

**JDK 类自动识别**（v0.2.0 新增，从 12 → 60+）:

| 包 | 关键类 |
|---|---|
| `java.io` | File, FileInputStream, FileOutputStream, FileReader, FileWriter, ObjectInputStream |
| `java.net` | URL, HttpURLConnection, Socket |
| `java.sql` | Connection, Statement, PreparedStatement, ResultSet |
| `javax.crypto` | Cipher, KeyGenerator, SecretKeySpec, DESKeySpec |
| `java.security` | MessageDigest, Signature, SecureRandom |
| `javax.xml.parsers` | DocumentBuilderFactory, SAXParserFactory |
| `javax.xml.xpath` | XPathFactory, XPath, XPathExpression |
| `javax.naming` | Context, InitialContext, DirContext |
| `java.util` | Random, ArrayList, HashMap, Logger, Properties |
| `javax.servlet` | HttpServletRequest, HttpServletResponse |

**链式调用解析示例**:

```
源码: conn.createStatement().executeQuery(sql)

步骤1: conn → lookupVariableType("conn") → java.sql.Connection
步骤2: createStatement() → lookupReturnType("java.sql.Connection", "createStatement") → java.sql.Statement
步骤3: executeQuery() → 匹配 JL-S001 规则
```

**API**:

```typescript
class DeepCallScanner {
  async init(): Promise<void>;          // 加载 tree-sitter WASM + Java grammar
  scanAll(): DeepCallResult[];          // 返回原始扫描结果
  toCallSites(results: DeepCallResult[]): CallSite[];  // 转换为带签名的调用点
  close(): void;
}
```

### 4.2 TypeResolver — 变量类型追踪

**文件**: `src/analyzer/type-resolver.ts` (518 行)

**职责**: 在单个 Java 文件的方法体/类体内，追踪变量声明到其类型。

**解析来源**（优先级从高到低）:

| 优先级 | 来源 | 示例 | 作用域键 |
|---|---|---|---|
| 1 | 局部变量声明 | `Statement stmt = ...` | `ClassName.methodName` |
| 2 | try-with-resources | `try (PreparedStatement ps = ...)` | `ClassName.methodName` |
| 3 | 方法参数 | `void foo(Connection conn)` | `ClassName.methodName` |
| 4 | catch 参数 | `catch (IOException e)` | `ClassName.methodName` |
| 5 | 类字段声明 | `private Connection dbConnection;` | `ClassName.<fields>` |

**关键设计决策**:

- **首次声明优先**: 变量类型取首次声明，后续赋值不覆盖（防止追踪污染）
- **Import 映射**: 短名→全名，如 `Connection` → `java.sql.Connection`，先查 `JAVA_BOXED_MAP`，再查文件的 import 节点
- **全限定构造器**: `new java.io.ObjectInputStream(fis)` 直接从 `new` 表达式提取完整类名
- **正则表达式转义陷阱**: TS 源码中 `new RegExp()` 内的 `\s` 必须写成 `'\\s'`（2 个反斜杠），不是模板字面量（`\s` 变成字面 `s`），也不是 `'\\\\s'`（4 反斜杠，RegExp 得到 `\\s` = 字面 `\s` 字符）

### 4.3 ReturnTypeTable — JDK API 索引

**文件**: `src/analyzer/return-type-table.ts` (261 行)
**数据源**: `src/analyzer/jdk-api-index.json` (505 KB 紧凑格式)

**紧凑格式键名映射**:

| 紧凑键 | 全称 | 说明 |
|---|---|---|
| `s` | superClass | 父类全名 |
| `i` | interfaces | 实现的接口列表 |
| `m` | methods | 方法表 |
| `f` | fields | 字段表 |

**方法条目数组**: `[descriptor, returnType, paramTypes[], modifiers[], throws[], deprecated]`

**继承链解析算法**:

```
findMethods(className, methodName, visited = new Set()):
  1. 查 methodMap[className + "\0" + methodName]
  2. 如果找到 → 返回方法重载列表
  3. 如果未找到:
     a. 查 classMap[className].superClass → 递归 findMethods
     b. 查 classMap[className].interfaces → 逐个递归
  4. visited 集合防止循环继承
```

**性能数据**:

| 指标 | 值 |
|---|---|
| 冷启动（JSON→Map） | 6-8 ms |
| 热查询（Map.get） | 0.1 µs |
| 索引规模 | 179 类, 4923 方法, 1395 重载, 337 字段 |

### 4.4 CodeGraphTraverser — 跨文件图遍历

**文件**: `src/analyzer/codegraph-traverser.ts` (447 行)

**职责**: 直接读取 CodeGraph 的 SQLite DB，提供 CodeGraph 运行时不支持的跨文件分析能力。

**核心能力**:

| API | 功能 | 用途 |
|---|---|---|
| `getCallers(nodeId, maxDepth)` | 递归查找谁调用了指定方法 | 污点源回溯 |
| `getCallees(nodeId, maxDepth)` | 递归查找指定方法调用了谁 | 污点传播追踪 |
| `findMethod(qualifiedName)` | 按名称查找方法节点 | 定位危险 sink |
| `getAllJavaMethods()` | 获取所有 Java 方法 | 全局分析 |
| `getAllJavaClasses()` | 获取所有 Java 类 | 类继承分析 |
| `getCallChain(sourceId, targetId, maxDepth)` | BFS 查找两节点间最短路径 | 污点链路证明 |

**SQL 查询**:

```sql
-- 加载所有 calls 边（初始化时一次性缓存）
SELECT e.source, e.target, e.kind, e.line, e.column,
       src.name AS src_name, src.qualified_name AS src_qname, src.file_path AS src_file,
       tgt.name AS tgt_name, tgt.qualified_name AS tgt_qname, tgt.file_path AS tgt_file
FROM edges e
JOIN nodes src ON e.source = src.id
JOIN nodes tgt ON e.target = tgt.id
WHERE e.kind = 'calls' AND src.language = 'java';

-- 查找方法节点
SELECT * FROM nodes WHERE kind = 'method' AND language = 'java' AND qualified_name LIKE ?;
```

**性能优化**:

- 边缓存: 所有 `calls` 边在初始化时加载到内存 Map（`outgoingEdges`, `incomingEdges`）
- 节点缓存: 按需加载，`nodeCache` 避免重复 SQL 查询
- 深度限制: `maxDepth` 防止递归爆炸

**数据规模**（demo 项目）:

| 指标 | 值 |
|---|---|
| Java 方法节点 | 19 |
| calls 边 | 4 条跨文件 + 项目内部 |
| 单次 BFS 路径查询 | < 1 ms |

### 4.5 TaintTracker — 跨文件污点追踪

**文件**: `src/analyzer/taint-tracker.ts` (501 行)

**职责**: 识别污点源、追踪跨文件传播链、为告警添加污点链上下文。

**污点源识别策略**（启发式）:

| 策略 | 模式 | 示例 |
|---|---|---|
| **参数名模式** | `/request|param|\binput|\buser|header|body|query|cookie|token|password|secret|path$|file$|url$|name$/i` | `username`, `filePath`, `loginName` |
| **Controller 方法检测** | 类名含 `Controller` → 所有方法参数视为外部输入 | `UserController.handleGetUser(requestParam)` |
| **已知污点源方法** | `HttpServletRequest.getParameter*`, `getHeader*`, `getInputStream`, `getReader` | `request.getParameter("id")` |

**传播追踪**:

```
traceTaintChain(sinkMethod):
  1. 获取所有 sinkMethod 的 callers（回溯）
  2. 对每个 caller:
     a. 检查 caller 的参数名是否匹配污点模式
     b. 如果匹配 → 标记为污点源，记录传播路径
     c. 如果不匹配 → 继续向上回溯（最多 MAX_TAINT_DEPTH=5 跳）
  3. 对所有链路排序（跨文件优先，置信度次之）
  4. 选最佳链路 pickBestChain()
```

**污点链结构**:

```typescript
interface TaintChainInfo {
  sourceMethod: string;        // 污点源方法名
  sourceFile: string;          // 污点源文件路径
  sourceParameters: string[];  // 被污染的参数名列表
  propagationPath: string;     // 传播路径 "handleGetUser → findByUsername"
  depth: number;               // 跳数
  confidence: 'high' | 'medium' | 'low';
  sourceReason: string;         // 判定原因（如参数名匹配模式）
}
```

### 4.6 ParamResolver — 参数来源解析

**文件**: `src/rules/param-resolver.ts` (673 行)

**职责**: 解析危险函数每个参数的来源，输出结构化的 `ParamSourceInfo`。

**解析策略**（按优先级）:

| # | 策略 | 输入示例 | 输出 parts |
|---|---|---|---|
| 1 | 硬编码字面量 | `"SELECT * FROM users"` | `[{kind:"hardcoded", value:"SELECT..."}]` |
| 2 | 变量名 → 参数匹配 | `stmt.executeQuery(sql)` | 追踪 `sql` 变量的赋值来源 |
| 3 | 字符串拼接拆分 | `"WHERE id=" + id` | `[{kind:"hardcoded",...}, {kind:"external_input",...}]` |
| 4 | 方法调用返回值 | `SECRET_KEY.getBytes()` | `[{kind:"hardcoded", value:"MySuperSec...", methodSignature:"SECRET_KEY.getBytes()"}]` |
| 5 | 字段访问 | `this.connection` | `[{kind:"field", fieldName:"connection"}]` |
| 6 | static final String 常量求解 | `DB_PASSWORD` | `[{kind:"hardcoded", value:"admin123", fieldName:"DB_PASSWORD"}]` |

**static final String 常量求解**（v0.2.0 新增）:

```
源码: private static final String SECRET_KEY = "MySuperSecretKey12345";
调用: new SecretKeySpec(SECRET_KEY.getBytes(), "AES")

解析步骤:
  1. traceArgParts("SECRET_KEY.getBytes()") → traceMethodCallPart()
  2. receiver="SECRET_KEY" → getStaticFinalStringValue("SECRET_KEY", "DataUtils")
  3. ensureStaticFinalStringsScanned() → 扫描所有 Java 文件
     正则: /static\s+final\s+String\s+(\w+)\s*=\s*"([^"]*)"/
     建立映射: {"SECRET_KEY": "MySuperSecretKey12345", "DB_PASSWORD": "admin123"}
  4. 返回: {kind:"hardcoded", value:"MySuperSecretKey12345", methodSignature:"SECRET_KEY.getBytes()"}

最终 ParamSourceInfo:
  isHardcoded: true, isExternalInput: false, isTainted: false
  composite: "direct"
  confidence: "high"
```

**结构化输出**:

```typescript
interface ParamSourceInfo {
  position: number;
  type: string;
  // ── 布尔标志（脚本直接用属性判断）──
  isHardcoded: boolean;      // 有硬编码部分
  isExternalInput: boolean;  // 有外部输入部分
  isTainted: boolean;        // 有污点部分
  isResolvable: boolean;     // 所有 part 都可解析
  // ── 组合方式 ──
  composite: 'direct' | 'concat' | 'method_return' | 'field' | 'unknown';
  // ── 拆分后的组成部分 ──
  parts: ParamPart[];
  confidence: 'high' | 'medium' | 'low';
}

interface ParamPart {
  kind: 'hardcoded' | 'external_input' | 'method_return' | 'field' | 'variable' | 'unknown';
  // kind 决定哪些字段有值：
  value?: string;            // hardcoded
  source?: string;           // external_input: 'method_parameter' | 'servlet_request' | ...
  name?: string;             // external_input: 参数名
  type?: string;             // external_input: 参数类型
  crossFile?: boolean;       // external_input: 是否跨文件
  callerMethod?: string;     // external_input: 跨文件调用者方法
  callerFile?: string;       // external_input: 跨文件调用者文件
  methodSignature?: string;  // method_return / hardcoded(via field)
  fieldName?: string;        // field / hardcoded(via field)
  fieldType?: string;        // field
  varName?: string;          // variable
}
```

**脚本使用示例**（无需解析字符串）:

```javascript
// Python 脚本
def check(ctx):
    for param in ctx['params']:
        if param['isExternalInput']:
            for part in param['parts']:
                if part['kind'] == 'external_input' and part['crossFile']:
                    return {"alert": True, "message": f"SQL注入: {part['name']} 跨文件来自 {part['callerMethod']}"}
```

### 4.7 RuleEngine — 规则匹配与脚本执行

**文件**: `src/rules/rule-engine.ts` (600 行)

**架构**:

```
RuleEngine
  ├── rules: Rule[]                    // YAML 规则定义
  ├── engineRegistry: ScriptEngineRegistry  // JS/Groovy/Python 引擎注册
  ├── paramResolver: ParamResolver      // 参数来源解析
  │
  ├── loadRules() → number             // 从 rules/ 加载 YAML
  ├── checkRules(callSites[]) → Alert[] // 对每个调用点执行匹配
  │   ├── matchRule(site) → Rule | null // glob 模式 → regex 匹配
  │   ├── buildScriptContext(site) → ScriptContext
  │   │   ├── sink: SinkInfo           // 危险函数签名
  │   │   ├── method: MethodInfo       // 所在方法信息
  │   │   ├── params: ParamSourceInfo[] // 每个参数的结构化来源
  │   │   ├── objHistory: ObjHistory[]  // 对象调用历史
  │   │   ├── retUsage: RetUsage[]     // 返回值后续使用
  │   │   └── taintChain: TaintChain?  // 跨文件污点链
  │   └── engine.execute(script, ctx) → CheckResult
  └── injectDependencies()             // 注入 tree-sitter + CodeGraph 依赖
```

**规则 YAML 格式**:

```yaml
id: JL-S001
name: SQL Injection Risk
severity: high
description: "..."
signaturePatterns:
  - "java.sql.Statement.executeQuery(*)"
  - "java.sql.Statement.execute(*)"
  - "java.sql.Statement.executeUpdate(*)"
  - "java.sql.Connection.createStatement(*)"
checkScript: "sql-injection.js"
tags: [security, sql, injection, CWE-089]
```

**签名模式匹配**:

```
glob → regex:
  "java.sql.Statement.execute(*)"     → /^java\.sql\.Statement\.execute\([^)]*\)$/
  "*.executeQuery(java.lang.String)"  → /^[^.]+\.executeQuery\(java\.lang\.String\)$/
匹配对象: callSite.fullSignature.fullQualifiedName
```

**构建 ScriptContext 示例**:

```json
{
  "sink": {
    "fullSignature": "java.sql.Statement.executeQuery()",
    "className": "Statement",
    "methodName": "executeQuery",
    "sourceLine": "ResultSet rs = stmt.executeQuery(sql);",
    "filePath": "src/.../UserService.java",
    "line": 33
  },
  "method": {
    "className": "UserService",
    "methodName": "findByUsername",
    "parameters": [
      {"name": "username", "type": "String"}
    ]
  },
  "params": [
    {
      "position": 0, "type": "unknown",
      "isHardcoded": true, "isExternalInput": true, "isTainted": true,
      "isResolvable": true, "composite": "concat",
      "parts": [
        {"kind": "hardcoded", "value": "SELECT * FROM users WHERE username = '"},
        {"kind": "external_input", "source": "method_parameter", "name": "username",
         "type": "String", "crossFile": true,
         "callerMethod": "UserController::handleGetUser",
         "callerFile": "src/.../UserController.java"},
        {"kind": "hardcoded", "value": "'"}
      ],
      "confidence": "high"
    }
  ],
  "objHistory": [
    {"objectName": "stmt", "calls": [{"method": "executeQuery", "args": ["sql"]}]}
  ],
  "retUsage": {
    "subsequentCalls": [
      {"method": "next", "receiver": "rs"},
      {"method": "getLong", "receiver": "rs"},
      {"method": "getString", "receiver": "rs"}
    ]
  },
  "taintChain": {
    "sourceMethod": "handleGetUser",
    "sourceFile": "src/.../UserController.java",
    "sourceParameters": ["requestParam"],
    "propagationPath": "handleGetUser → findByUsername",
    "depth": 1,
    "confidence": "medium",
    "sourceReason": "Parameter name(s) match taint pattern: requestParam"
  }
}
```

### 4.8 多语言脚本引擎

#### 4.8.1 ScriptEngine 接口

**文件**: `src/rules/script-engine.ts` (69 行)

```typescript
interface ScriptEngine {
  name: string;                                    // "js" | "groovy" | "python"
  isAvailable(): boolean;                          // 运行时/解释器是否存在
  execute(scriptPath: string, context: ScriptContext): ScriptCheckResult;
}

class ScriptEngineRegistry {
  register(engine: ScriptEngine): void;
  get(name: string): ScriptEngine | undefined;
  getEngineForScript(scriptPath: string): ScriptEngine | undefined;  // 按扩展名自动选择
  listAvailable(): string[];
}
```

#### 4.8.2 JsEngine — require() 方式

**文件**: `src/rules/js-engine.ts` (57 行)

| 特性 | 说明 |
|---|---|
| 可用性 | 始终可用（运行在 Node.js 中） |
| 执行方式 | `require(scriptPath).check(context)` |
| 序列化 | 无需，直接传递 JS 对象 |
| 延迟 | 零延迟（< 0.1 ms） |
| 缓存 | 每次执行前 `delete require.cache`，确保热更新 |
| 脚本格式 | `module.exports.check = function(ctx) { ... }` |

#### 4.8.3 PythonEngine — 子进程方式

**文件**: `src/rules/python-engine.ts` (108 行)

| 特性 | 说明 |
|---|---|
| 可用性 | `which python3` 存在即可用 |
| 执行方式 | `execFileSync('python3', [script, tmpJson])` |
| 序列化 | context → `/tmp/javalint-ctx-*.json` → 脚本 `json.load(sys.argv[1])` |
| 延迟 | ~100 ms（Python 启动） |
| 超时 | 30 秒 |
| 脚本格式 | `def check(ctx): ... ; print(json.dumps(result))` |

#### 4.8.4 GroovyEngine — 子进程方式

**文件**: `src/rules/groovy-engine.ts` (106 行)

| 特性 | 说明 |
|---|---|
| 可用性 | `which groovy` 存在即可用 |
| 执行方式 | `execFileSync('groovy', [script, tmpJson])` |
| 序列化 | 同 Python（临时 JSON 文件） |
| 延迟 | ~2s（JVM 启动），可考虑缓存 JVM 进程 |
| 超时 | 30 秒 |
| 脚本格式 | `def check(ctx) { ... }; println new JsonBuilder(result)` |

**引擎选择逻辑**: 按规则 YAML 中 `checkScript` 的文件扩展名自动选择：`.js` → JsEngine, `.py` → PythonEngine, `.groovy` → GroovyEngine。不可用的引擎自动跳过，不影响其他规则。

### 4.9 AlertDatabase — 告警存储

**文件**: `src/db/alert-database.ts` (165 行) + `src/db/schema.sql`

**表结构**:

```sql
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id TEXT NOT NULL,
    rule_name TEXT NOT NULL,
    severity TEXT NOT NULL,
    message TEXT NOT NULL,
    confidence TEXT NOT NULL,
    file_path TEXT NOT NULL,
    line_number INTEGER NOT NULL,
    package_name TEXT,
    class_name TEXT NOT NULL,
    method_name TEXT NOT NULL,
    parameter_types TEXT,
    full_signature TEXT NOT NULL,
    caller_class TEXT,
    caller_method TEXT,
    source_line TEXT,
    detected_at INTEGER NOT NULL,
    -- 污点链字段
    taint_source_method TEXT,
    taint_source_file TEXT,
    taint_source_params TEXT,
    taint_propagation_path TEXT,
    taint_depth INTEGER,
    taint_confidence TEXT,
    taint_source_reason TEXT,
    UNIQUE(rule_id, file_path, line_number, full_signature)
);

-- 索引
CREATE INDEX idx_alerts_rule ON alerts(rule_id);
CREATE INDEX idx_alerts_file ON alerts(file_path);
CREATE INDEX idx_alerts_severity ON alerts(severity);
CREATE INDEX idx_alerts_taint ON alerts(taint_source_method);
```

**去重**: `UNIQUE(rule_id, file_path, line_number, full_signature)` + `INSERT OR IGNORE`。

### 4.10 JavaLint 主类

**文件**: `src/index.ts` (~300 行)

**双源合并策略**:

```
Deep Scanner 产出:  234 个调用点（含外部依赖调用 + 构造器调用）
CodeGraph DB 产出:  19 个已解析调用（仅项目内部）

合并: 按 (callerFile, callerLine, calleeMethodName) 去重
  - Deep Scanner 优先（覆盖面更广）
  - CodeGraph 有更好的已解析签名时覆盖
  - CodeGraph 独有的调用点也保留
```

**完整分析流程**:

```typescript
async analyze(): Promise<AnalysisResult> {
  // Layer 1: Deep Scan
  const scanResults = this.deepScanner.scanAll();
  const deepCallSites = this.deepScanner.toCallSites(scanResults);

  // Layer 2: CodeGraph Enrichment
  let cgCallSites: CallSite[] = [];
  if (this.callCollector) {
    cgCallSites = this.callCollector.collectCallSites();
  }
  const mergedSites = this.mergeCallSites(deepCallSites, cgCallSites);

  // Layer 3: Rule Matching + Script Execution
  const alerts = this.ruleEngine.checkRules(mergedSites);

  // Layer 4: Taint Analysis
  let taintStats = null;
  if (this.cgTraverser && this.taintTracker && !this.noTaint) {
    const taintResult = this.taintTracker.analyze(alerts);
    // 增强告警的污点链信息
    for (const alert of alerts) {
      const chain = taintResult.taintChains.get(alertKey(alert));
      if (chain) alert.taintChain = chain;
    }
    taintStats = { ... };
  }

  // Save to DB
  this.alertDb.saveAlerts(alerts);

  return { alerts, totalCallSites, alertCount, durationMs, taintStats };
}
```

---

## 5. 规则系统

### 5.1 规则清单

| Rule ID | 名称 | 严重度 | CWE | 检测目标 | 脚本语言 |
|---|---|---|---|---|---|
| JL-S001 | SQL 注入 | HIGH | CWE-089 | Statement.execute*, Connection.createStatement | JS + Python + Groovy |
| JL-S002 | 反序列化 RCE | CRITICAL | CWE-502 | ObjectInputStream.readObject | JS |
| JL-S003 | 命令注入 | CRITICAL | CWE-078 | Runtime.exec, ProcessBuilder.start | JS |
| JL-S004 | 跨文件污点传播 | CRITICAL | — | 任意危险 sink + 跨文件传播 | JS |
| JL-S005 | 路径穿越 | HIGH | CWE-022 | FileInputStream, FileOutputStream, File, FileReader | JS |
| JL-S006 | SSRF | HIGH | CWE-918 | URL 构造器, HttpURLConnection.openConnection | JS |
| JL-S007 | XXE | CRITICAL | CWE-611 | DocumentBuilderFactory.newInstance, DocumentBuilder.parse | JS |
| JL-S008 | XPath/LDAP/JNDI 注入 | CRITICAL | CWE-643/90/917 | XPath.compile, DirContext.search, Context.lookup | JS |
| JL-S009 | 硬编码密钥 | HIGH | CWE-798/321 | SecretKeySpec, DESKeySpec 构造器 | JS |
| JL-S010 | 弱加密 | HIGH | CWE-327/328 | Cipher.getInstance(MD5/SHA1/DES/ECB), MessageDigest.getInstance | JS |
| JL-S011 | 不安全反射 | CRITICAL | CWE-470 | Class.forName, Constructor.newInstance | JS |
| JL-S012 | 不安全随机 | MEDIUM | CWE-338 | java.util.Random 构造器和方法 | JS |
| JL-S013 | 日志注入 | MEDIUM | CWE-117 | Logger.info/warning/severe + 外部输入 | JS |

### 5.2 脚本检查逻辑概要

**JL-S001 (SQL 注入)**:
- `createStatement()` → 始终告警（medium 置信度）
- `executeQuery/execute/executeUpdate()` → 检查参数来源
  - 参数含外部输入 + 硬编码 → 确认 SQL 注入（high）
  - 仅硬编码 → 低风险（low）
  - PreparedStatement → 不告警

**JL-S005 (路径穿越)**:
- `FileInputStream/FileOutputStream/File/FileReader` 构造器 → 检查路径参数
  - 路径含外部输入 + 跨文件 → 确认穿越（high）
  - 路径含外部输入 → 可能穿越（medium/low）

**JL-S009 (硬编码密钥)**:
- `SecretKeySpec/DESKeySpec` 构造器 → 检查密钥参数
  - 参数 `isHardcoded=true` 且有 `fieldName` → 硬编码字段常量（high）
  - 参数 `isHardcoded=true` → 硬编码字面量（high）
  - 参数变量名匹配 `/secret|key|password|token|credential/i` → 可能硬编码（medium）
  - 其他 → 低置信度（low）

**JL-S010 (弱加密)**:
- `Cipher.getInstance(algo)` → 检查算法名
  - DES → 告警（high）
  - ECB → 告警（high）
  - RC4/ARCFOUR → 告警（high）
  - RSA 无 OAEP → 告警（high）
  - 其他 → 低置信度（low）
- `MessageDigest.getInstance(algo)` → 检查算法名
  - MD5 → 告警（high）
  - SHA-1 → 告警（high）
  - SHA-256/384/512/3 → 不告警
  - 其他 → 低置信度（low）

---

## 6. 数据流完整示例

### 6.1 SQL 注入检测（跨文件追踪）

**输入**: UserController → UserService

```java
// UserController.java:12
public User handleGetUser(String requestParam) {
    return userService.findByUsername(requestParam);
}

// UserService.java:33
ResultSet rs = stmt.executeQuery(sql);
// sql = "SELECT * FROM users WHERE username = '" + username + "'"
```

**处理流程**:

```
1. Deep Scanner 提取:
   - UserController:12: receiver="userService", method="findByUsername", arg="requestParam"
   - UserService:33: receiver="stmt", method="executeQuery", arg="sql"

2. TypeResolver 解析:
   - stmt → java.sql.Statement (变量声明追踪)
   - sql → "SELECT..." + username + "'" (字符串拼接)

3. ParamResolver 解析 executeQuery 的参数 sql:
   - 拼接拆分 → parts:
     * {kind:"hardcoded", value:"SELECT * FROM users WHERE username = '"}
     * {kind:"external_input", source:"method_parameter", name:"username",
        type:"String", crossFile:true,
        callerMethod:"UserController::handleGetUser",
        callerFile:"UserController.java"}
     * {kind:"hardcoded", value:"'"}
   - composite: "concat"
   - isHardcoded: true, isExternalInput: true

4. RuleEngine 匹配:
   - "java.sql.Statement.executeQuery(*)" 匹配 JL-S001
   - buildScriptContext() 构建完整上下文

5. JS 脚本检查:
   - param.isExternalInput && param.composite === 'concat' → 确认注入
   - 输出: { alert: true, confidence: "high",
     message: "Statement.executeQuery() with SQL concatenation: ... username (cross-file from UserController::handleGetUser)" }

6. TaintTracker 增强污点链:
   - sourceMethod: "handleGetUser", sourceFile: "UserController.java"
   - sourceParameters: ["requestParam"]
   - propagationPath: "handleGetUser → findByUsername"
   - depth: 1, confidence: "medium"
   - reason: "Parameter name(s) match taint pattern: requestParam"

7. 最终告警:
   🟠 HIGH: UserService.java:33
     [JL-S001] SQL Injection Risk
     Statement.executeQuery() with SQL concatenation: ... username (cross-file from UserController::handleGetUser) — confirmed SQL injection
     Confidence: high
     🔗 Taint chain:
        Source: handleGetUser() in UserController.java
        Tainted params: requestParam
        Propagation: handleGetUser → findByUsername
        Depth: 1
```

### 6.2 安全代码不被误报

```java
PreparedStatement pstmt = conn.prepareStatement(sql);
ResultSet rs = pstmt.executeQuery();  // ← 不告警
```

```
TypeResolver: pstmt → java.sql.PreparedStatement
RuleEngine: "java.sql.PreparedStatement.executeQuery(*)" 匹配 JL-S001
JS 脚本: fullClass === 'java.sql.PreparedStatement' → { alert: false }
```

### 6.3 硬编码密钥检测（常量值求解）

```java
// DataUtils.java:82-83
private static final String SECRET_KEY = "MySuperSecretKey12345";
private static final String DB_PASSWORD = "admin123";

// DataUtils.java:86
SecretKeySpec key = new SecretKeySpec(SECRET_KEY.getBytes(), "AES");
```

```
1. Deep Scanner: receiver="SecretKeySpec", method="<init>", line=86

2. ParamResolver 解析第一个参数 SECRET_KEY.getBytes():
   - traceMethodCallPart: receiver="SECRET_KEY", method="getBytes"
   - getStaticFinalStringValue("SECRET_KEY", "DataUtils")
   - ensureStaticFinalStringsScanned() → 扫描所有 Java 文件
     正则: /static\s+final\s+String\s+(\w+)\s*=\s*"([^"]*)"/
     结果: {"SECRET_KEY": "MySuperSecretKey12345", "DB_PASSWORD": "admin123",
             "DataUtils.SECRET_KEY": "MySuperSecretKey12345", ...}
   - 返回: {kind:"hardcoded", value:"MySuperSecretKey12345", methodSignature:"SECRET_KEY.getBytes()"}

3. buildParamSourceInfo:
   isHardcoded: true, composite: "direct", confidence: "high"

4. hardcoded-secrets.js 检查:
   - keyParam.isHardcoded → true
   - hardcodedParts 有 fieldName → fromField = true
   - 返回: { alert: true, confidence: "high",
     message: 'Hardcoded secret in static final field "SECRET_KEY" = "MySuperSec..." — move to environment variable or key vault (CWE-798)' }
```

---

## 7. CLI 命令

**文件**: `src/bin/javalint.ts` (180 行)

```bash
javalint analyze [path] [options]
  -r, --rules <dir>       自定义规则目录
  --severity <level>      最低报告级别 (critical|high|medium|low|info)
  --format <fmt>          输出格式 (text|json)
  --clear                 分析前清除旧告警
  --no-taint              禁用跨文件污点分析

javalint list-rules [-r <dir>]
  列出所有可用规则（含污点分析标记）

javalint graph [path] [options]
  --depth <number>        最大遍历深度 (默认 3)
  --method <name>         聚焦指定方法
  显示 CodeGraph 跨文件调用图概览

退出码:
  0: 无 critical/high 告警
  1: 存在 critical/high 告警
  2: 运行错误
```

---

## 8. 当前检测结果

**Demo 项目** (`demo-java-project/`): 7 个 Java 文件，30 个已知漏洞

| 规则 | 告警数 | 检出漏洞 | 误报 |
|---|---|---|---|
| JL-S001 SQL注入 | 11 | 6 | 0 |
| JL-S002 反序列化 | 2 | 2 | 0 |
| JL-S003 命令注入 | 2 | 1 | 1 (ProcessBuilder硬编码) |
| JL-S005 路径穿越 | 5 | 2 | 2 (readFileSafe) |
| JL-S006 SSRF | 2 | 2 | 0 |
| JL-S007 XXE | 4 | 2 | 2 (parseXmlSafe) |
| JL-S008 XPath/LDAP/JNDI | 4 | 3 | 1 (ldapAuthSafe) |
| JL-S009 硬编码密钥 | 3 | 2 | 0 |
| JL-S010 弱加密 | 5 | 4 | 0 (SHA-256已放行) |
| JL-S011 不安全反射 | 2 | 1 | 1 (newInstance) |
| JL-S012 不安全随机 | 2 | 1 | 0 |
| JL-S013 日志注入 | 1 | 1 | 0 |
| **合计** | **46** | **27** | **7** |

**检测覆盖率**: 27/29 = **93%**
**误报率**: 7/46 = 15%

**漏检项（2个）**:

| 漏洞 | 原因 | 解决思路 |
|---|---|---|
| `DB_PASSWORD` 硬编码字段 | 没有被任何代码引用，不在调用图中 | 增加字段声明扫描，即使无引用也检测 |
| `String.replace` 模板注入 | 不是标准模板引擎，`String.replace` 太常见不适合做 sink | 需要更复杂的模板注入检测策略 |

---

## 9. 性能特征

**端到端分析（demo-java-project, 7 文件 234 调用点）**: 500-600 ms

| 阶段 | 耗时 | 说明 |
|---|---|---|
| tree-sitter 初始化 | ~20 ms | 加载 WASM + Java grammar |
| 源文件解析 | ~10 ms | 7 个文件 |
| 类型解析 + 签名增强 | ~10 ms | TypeResolver + ReturnTypeTable |
| CodeGraph 边缓存 | ~5 ms | 读取 calls 边 |
| 规则匹配 + 脚本执行 | ~50 ms | JS 引擎零延迟，Python 引擎 ~100ms/script |
| 污点追踪 | ~30 ms | BFS 遍历 + 参数名匹配 |
| 告警写入 | ~5 ms | SQLite INSERT |
| 输出格式化 | ~400 ms | console.log |

---

## 10. 已知限制与后续规划

### 已知限制

| 限制 | 影响 | 原因 |
|---|---|---|
| 污点源依赖参数名模式匹配 | 可能漏检使用非常规参数名的污点源 | 无法做真正的数据流分析 |
| 无消毒器检测 | 无法识别已经过输入净化的路径为安全 | 不追踪 `sanitize()`、参数化查询等消毒操作 |
| static final String 需要被引用才检测 | 未使用的硬编码常量漏检 | DeepCallScanner 不扫描字段声明 |
| 协变返回类型 | `StringBuilder.append()` 返回 `Appendable` 而非 `StringBuilder` | javap 输出声明类型而非实际类型 |
| 泛型类型擦除 | `Optional.get()` 返回 `T`，解析为 null | 类型擦除后无法知道具体 T |
| CodeGraph 无 unresolved_refs | 外部依赖调用全部丢失 | CodeGraph 设计时只关注项目内部 |
| Spring 注解识别 | `@RequestParam` 等注解目前不识别 | 需要 tree-sitter 注解解析 |
| 误报: 安全模式仍告警 | `readFileSafe`/`parseXmlSafe`/`ldapAuthSafe` 有安全措施但仍告警 | 缺少消毒器/安全模式识别 |

### 后续规划

| 优先级 | 功能 | 说明 |
|---|---|---|
| P0 | 字段声明扫描 | 即使无引用也检测 `static final String XXX = "password"` |
| P0 | 消毒器识别 | 检测 `replaceAll`/`PreparedStatement`/`setFeature` 等安全模式，降低或消除误报 |
| P0 | Spring 注解支持 | `@RequestParam`/`@PathVariable`/`@RequestBody` 自动标记为外部输入 |
| P1 | SARIF 输出 | VS Code/GitHub 集成 |
| P1 | 增量分析 | 只分析 git 变更文件 |
| P1 | `@SuppressWarnings("JL-S001")` | 注解抑制告警 |
| P2 | 跨文件字段类型追踪 | 利用 CodeGraph `contains`/`type_of` 边 |
| P2 | 协变返回类型覆盖 | 硬编码 `StringBuilder.append` → `StringBuilder` |
| P3 | 缓存 Groovy JVM 进程 | 减少启动开销 |
| P3 | 方法重载参数类型约束 | `Statement.execute(java.lang.String)` 精确匹配 |

---

## 11. 开发踩坑记录

### 11.1 正则表达式转义陷阱

在 TypeScript 源码中使用 `new RegExp()` 构建正则时：

| 写法 | TS 源码中的反斜杠数 | 编译后 JS 字符串 | RegExp 解释 | 结果 |
|---|---|---|---|---|
| `new RegExp('\\s')` | 2 | `'\s'` | `\s` = 空白字符 | ✅ 正确 |
| `` new RegExp(`\s`) `` | 1 | `'s'` | 字面 `s` | ❌ Bug |
| `new RegExp('\\\\s')` | 4 | `'\\s'` | `\\s` = 字面 `\` + `s` | ❌ Bug |

**结论**: TS 源码中 `new RegExp()` 内必须用**普通字符串** + **2 个反斜杠**。

### 11.2 Object.create(null) 的必要性

`jdk-api-index.json` 解析为 Map 时，如果用 `{}` 创建 methods 对象，`methods["toString"]` 会命中 `Object.prototype.toString`，导致 179 个类全部解析结果为 0。必须用 `Object.create(null)` 避免原型链污染。

### 11.3 javap 泛型逗号陷阱

`HashMap extends AbstractMap<K,V>` 中的逗号被误判为 extends 列表分隔符。修复: 先 `replace(/<[^>]*>/g, '')` 再 `split(',')`。

### 11.4 tree-sitter try-with-resources 解析

tree-sitter 的 `resource` 节点没有标准化的子字段名，不同版本可能是 `name` 或 `value`。使用正则提取声明更可靠。

### 11.5 pi-tui CJK 宽度溢出崩溃

pi-coding-agent 输出含中文字符时，pi-tui 的 `visibleWidth()` 计算可能比终端宽度多 1 列，`doRender()` 中 `throw new Error()` 直接崩溃退出。修复: 将 throw 改为防御性截断 `sliceByColumn()`。