# JavaLint 🛡️

> Java 静态代码安全分析工具 — 基于 CodeGraph 跨文件知识图谱 + tree-sitter 精确 AST 解析

## 它能做什么

JavaLint 扫描 Java 源代码，检测 **13 类安全漏洞**：

| 规则 ID | 漏洞类型 | 严重度 | CWE |
|---------|---------|--------|-----|
| JL-S001 | SQL 注入 | HIGH | CWE-089 |
| JL-S002 | 反序列化 RCE | CRITICAL | CWE-502 |
| JL-S003 | 命令注入 | CRITICAL | CWE-078 |
| JL-S005 | 路径穿越 | HIGH | CWE-022 |
| JL-S006 | SSRF | HIGH | CWE-918 |
| JL-S007 | XXE | CRITICAL | CWE-611 |
| JL-S008 | XPath/LDAP/JNDI 注入 | CRITICAL | CWE-643/90/917 |
| JL-S009 | 硬编码密钥 | HIGH | CWE-798/321 |
| JL-S010 | 弱加密算法 | HIGH | CWE-327/328 |
| JL-S011 | 不安全反射 | CRITICAL | CWE-470 |
| JL-S012 | 不安全随机数 | MEDIUM | CWE-338 |
| JL-S013 | 日志注入 | MEDIUM | CWE-117 |

**核心能力**：

- **全量方法调用提取** — tree-sitter 解析每个 Java 文件，不遗漏任何调用
- **精确类型解析** — 变量声明追踪 → JDK API 索引 → 继承链 → 构造器识别
- **跨文件污点追踪** — 从 Controller 到 Service 到危险 sink，追踪数据流
- **结构化参数来源** — 脚本直接用 `isHardcoded` / `isExternalInput` 判断，无需解析字符串
- **多语言脚本引擎** — 规则脚本支持 JavaScript / Python / Groovy

## 快速开始

### 前置条件

| 依赖 | 版本 | 必需？ | 说明 |
|------|------|--------|------|
| Node.js | ≥ 22 | ✅ 必需 | 运行时（使用 `node:sqlite` 实验性 API） |
| JDK | ≥ 17 | 构建 API 索引时需要 | 提供 `javap` 命令 |
| CodeGraph | ≥ 0.9 | 可选 | 跨文件分析需要，`npm install` 会自动安装 |
| Python 3 | ≥ 3.8 | 可选 | 运行 `.py` 规则脚本 |
| Groovy | ≥ 3.x | 可选 | 运行 `.groovy` 规则脚本 |

### 安装

```bash
# 1. 克隆仓库
git clone git@github.com:OuYang-HX/javalint.git
cd javalint

# 2. 安装依赖
npm install

# 3. 编译 TypeScript
npm run build

# 4. 全局注册命令（可选，方便在任何目录使用）
npm link
```

> 安装完成后，如果执行了 `npm link`，就可以在任意目录直接使用 `javalint` 命令。
> 如果没有执行 `npm link`，请使用 `node /path/to/javalint/dist/bin/javalint.js` 运行。

### 验证安装

```bash
# 用内置 demo 项目验证
javalint analyze demo-java-project/

# 或者不使用 npm link
node dist/bin/javalint.js analyze demo-java-project/
```

如果看到类似输出，说明安装成功：

```
🛡️  JavaLint - Java Static Code Analysis
   Project: demo-java-project/
  Deep scanner initialized (tree-sitter)
  Loaded 13 rules
  ...

  📊 Summary:
     Call sites analyzed: 234
     Alerts found:        46
     Analysis time:       568ms
```

## 使用方法

### 分析整个项目

```bash
javalint analyze /path/to/java-project
```

选项：

| 选项 | 说明 | 默认值 |
|------|------|--------|
| `--severity <level>` | 最低报告级别 (critical/high/medium/low/info) | medium |
| `--format <fmt>` | 输出格式 (text/json) | text |
| `--clear` | 分析前清除旧告警 | false |
| `--no-taint` | 禁用跨文件污点分析 | false |
| `--rules <dir>` | 自定义规则目录 | 内置 rules/ |

### 分析单个文件

```bash
javalint analyze /path/to/project/src/main/java/com/example/Service.java
```

JavaLint 会自动从文件路径往上搜索 `.codegraph` 目录来确定项目根目录。结果只包含该文件的告警。

### 构建依赖 API 索引

> **为什么需要这一步？** JavaLint 默认只索引 179 个 JDK 安全常用类。如果你的项目使用了 Spring、MyBatis、Jackson 等第三方库，需要构建依赖索引，让 JavaLint 能解析这些库的方法返回类型。

#### 从 pom.xml 解析项目依赖（推荐）

```bash
# 基本用法
javalint build-index --pom /path/to/project/pom.xml

# 指定 Maven settings.xml（获取自定义本地仓库路径）
javalint build-index \
  --pom /path/to/project/pom.xml \
  --settings ~/.m2/settings.xml
```

**工作原理**：

```
settings.xml → 本地 Maven 仓库路径（默认 ~/.m2/repository）
     ↓
pom.xml → 依赖坐标 (groupId:artifactId:version)
     ↓
递归解析 parent pom → 传递依赖
     ↓
本地仓库定位 jar 包（跳过 test/provided 作用域）
     ↓
jar tf 提取类名 → javap -public -s 解析方法签名
     ↓
合并 JDK 179 类 + 依赖类 → 输出统一 JSON
```

#### 扫描整个 Maven 本地仓库（全量，慢）

```bash
javalint build-index --maven
```

> ⚠️ 这会扫描 `~/.m2/repository` 下所有 jar，可能包含数万类，耗时 10 秒以上。

#### 让分析使用新索引

```bash
# 替换默认索引（全局生效）
cp /path/to/api-index.json src/analyzer/jdk-api-index.json
npm run build
```

### 启用跨文件分析（可选但推荐）

```bash
# 在项目根目录下先运行 CodeGraph 索引
cd /path/to/java-project
codegraph index

# 然后 JavaLint 会自动检测 .codegraph/ 目录并启用跨文件分析
javalint analyze /path/to/java-project
```

跨文件分析能提供：
- 精确的项目内部方法签名
- 数据从 Controller → Service → 危险 sink 的传播路径
- 更高的告警置信度

### 查看可用规则

```bash
javalint list-rules
```

### 查看 CodeGraph 调用图

```bash
# 项目概览
javalint graph /path/to/project

# 聚焦某个方法
javalint graph /path/to/project --method findByUsername

# 调整遍历深度
javalint graph /path/to/project --depth 5
```

## 完整工作流示例

```bash
# Step 1: 克隆 JavaLint
git clone git@github.com:OuYang-HX/javalint.git
cd javalint
npm install && npm run build && npm link

# Step 2: 进入你要检测的 Java 项目
cd /your/java/project

# Step 3: （可选）构建 CodeGraph 索引，启用跨文件分析
codegraph index

# Step 4: （可选）构建依赖 API 索引
javalint build-index --pom pom.xml

# Step 5: 分析整个项目
javalint analyze .

# 或者只检测一个文件
javalint analyze src/main/java/com/example/Controller.java

# Step 6: CI/CD 集成
javalint analyze . --severity high --format json
# 退出码: 0 = 通过, 1 = 有 critical/high 告警, 2 = 运行错误
```

## 输出示例

```
📍 UserService.java:33
   [JL-S001] SQL Injection Risk
   Statement.executeQuery() with SQL concatenation: "SELECT * FROM ... username (method parameter) — confirmed SQL injection
   Signature: java.sql.Statement.executeQuery()
   Source:    ResultSet rs = stmt.executeQuery(sql);
   Confidence: high

   🔗 Taint chain:
      Source: handleGetUser() in UserController.java
      Tainted params: requestParam
      Propagation: handleGetUser → findByUsername
      Depth: 1, Confidence: medium
      Reason: Parameter name(s) match taint pattern: requestParam
```

**置信度含义**：
- `high` — 确认漏洞（外部输入 + 危险 sink + 注入模式）
- `medium` — 可能漏洞（签名匹配但参数来源不确定）
- `low` — 低风险（签名匹配但参数为硬编码）

## 自定义规则

规则由 YAML 定义 + 脚本文件组成：

```yaml
# rules/my-rule.yaml
id: JL-S099
name: My Custom Rule
severity: high
description: "检测某种危险模式"
signaturePatterns:
  - "com.example.Dangerous.method(*)"
checkScript: "my-rule.js"    # 支持 .js / .py / .groovy
tags: [security, custom]
```

```javascript
// rules/my-rule.js
module.exports.check = function(ctx) {
  // ctx 是完整的 ScriptContext 对象
  // ctx.sink — 危险函数信息
  // ctx.method — 所在方法信息
  // ctx.params — 结构化参数来源
  // ctx.taintChain — 污点链

  for (const param of ctx.params) {
    if (param.isExternalInput && param.composite === 'concat') {
      return {
        alert: true,
        confidence: 'high',
        message: `外部输入拼接到 ${ctx.sink.methodName}()`
      };
    }
  }

  return { alert: false };
};
```

使用自定义规则目录：

```bash
javalint analyze /project --rules /my/custom/rules
```

## 架构概览

```
┌─────────────────────────────────────────────────┐
│              JavaLint CLI                        │
│         analyze | list-rules | graph             │
└───────────────────┬─────────────────────────────┘
                    │
┌───────────────────▼─────────────────────────────┐
│            四层分析架构                           │
├─────────────────────────────────────────────────┤
│ Layer 1: Deep Scan (tree-sitter)                │
│   全量方法调用+构造器提取                         │
├─────────────────────────────────────────────────┤
│ Layer 2: CodeGraph Enrichment                   │
│   跨文件已解析签名合并                             │
├─────────────────────────────────────────────────┤
│ Layer 3: Rule Matching + Script Engine          │
│   13条规则 × 3种脚本引擎(JS/Python/Groovy)       │
├─────────────────────────────────────────────────┤
│ Layer 4: Taint Analysis                         │
│   跨文件污点源追踪 + 传播链构建                    │
└─────────────────────────────────────────────────┘
```

## 常见问题

**Q: 提示 `Cannot find tree-sitter-java.wasm`**

确保已运行 `npm install`。该 WASM 文件由 `@colbymchenry/codegraph` 的依赖提供。

**Q: 提示 `CodeGraph index not found`**

这只是说明没有启用跨文件分析，基础分析仍然可用。如需跨文件分析，在项目目录下运行 `codegraph index`。

**Q: 依赖 jar 包找不到**

`build-index --pom` 只索引本地 Maven 仓库中已有的 jar。如果缺少依赖，先在项目中运行 `mvn dependency:resolve` 下载。

**Q: Node.js 版本需要 22+**

JavaLint 使用了 `node:sqlite` 实验性 API，该 API 从 Node.js 22 开始提供。

## 许可证

MIT