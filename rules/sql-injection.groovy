// SQL Injection Risk - Groovy check script
// Uses the rich ScriptContext to analyze parameter sources and taint chains
//
// Usage: groovy sql-injection.groovy <context.json>
//
// Available context fields:
//   ctx.sink       - 危险函数签名信息
//   ctx.method     - 危险函数所在方法的签名
//   ctx.params     - 危险函数每个参数的来源追踪
//   ctx.objHistory - 危险函数对象的调用历史
//   ctx.retUsage   - 危险函数返回值的后续使用
//   ctx.taintChain - 跨文件污点传播链

def check(ctx) {
    def sink = ctx.sink
    def params = ctx.params ?: []
    def objHist = ctx.objHistory
    def retUsage = ctx.retUsage
    def taint = ctx.taintChain

    def fullClass = sink.packageName ? "${sink.packageName}.${sink.className}" : sink.className
    def methodName = sink.methodName

    // PreparedStatement is safe
    if (fullClass == 'java.sql.PreparedStatement') {
        return [alert: false]
    }

    // Analyze parameter sources
    boolean hasExternalInput = false
    boolean hasHardcoded = false
    def hardcodedValues = []
    def externalSources = []

    for (p in params) {
        for (src in (p.sources ?: [])) {
            if (src.category == 'hardcoded') {
                hasHardcoded = true
                if (src.hardcodedValue) hardcodedValues << src.hardcodedValue
            } else if (src.category == 'external_input') {
                hasExternalInput = true
                externalSources << (src.externalInputSource ?: src.variableName ?: 'unknown')
            } else if (src.category == 'method_return' && taint) {
                hasExternalInput = true
                externalSources << (src.methodSignature ?: 'method_return')
            }
        }
    }

    // Connection.createStatement()
    if (fullClass == 'java.sql.Connection' && methodName == 'createStatement') {
        def msg = 'Connection.createStatement() creates an unsafe Statement — use prepareStatement() instead'
        def conf = 'medium'

        if (hasExternalInput) {
            msg += " [External input: ${externalSources.join(', ')}]"
            conf = 'high'
        } else if (taint) {
            msg += " [Taint from ${taint.sourceMethod}() via ${taint.propagationPath}]"
            conf = 'high'
        }

        return [alert: true, message: msg, confidence: conf]
    }

    // Statement.execute/executeQuery/executeUpdate
    if (fullClass == 'java.sql.Statement') {
        def msg
        def conf

        if (hasHardcoded && hasExternalInput) {
            msg = "Statement.${methodName}() mixes hardcoded ${hardcodedValues} and external [${externalSources.join(', ')}] input — confirmed injection"
            conf = 'high'
        } else if (hasExternalInput) {
            msg = "Statement.${methodName}() with external input (${externalSources.join(', ')}) — confirmed SQL injection"
            conf = 'high'
        } else if (hasHardcoded) {
            msg = "Statement.${methodName}() with hardcoded values only — low risk but use PreparedStatement"
            conf = 'low'
        } else if (taint) {
            msg = "Statement.${methodName}() — taint from ${taint.sourceMethod}() via ${taint.propagationPath} — confirmed SQL injection"
            conf = 'high'
        } else {
            msg = "Statement.${methodName}() uses non-parameterized SQL — use PreparedStatement instead"
            conf = 'medium'
        }

        // Enrich with object history
        if (objHist?.priorCalls) {
            def prior = objHist.priorCalls.collect { it.signature }
            msg += " [Object history: ${prior.join(' → ')}]"
        }

        // Enrich with return value usage
        if (retUsage?.subsequentCalls) {
            def retUses = retUsage.subsequentCalls.collect { it.signature }
            msg += " [Return used by: ${retUses.join(', ')}]"
        }

        return [alert: true, message: msg, confidence: conf]
    }

    return [alert: false]
}

// ── Main entry point ──────────────────────────────────────────────────
if (args.length < 1) {
    println groovy.json.JsonOutput.toJson([alert: false, message: 'No context file provided'])
    System.exit(0)
}

def ctxFile = new File(args[0])
def ctx = new groovy.json.JsonSlurper().parse(ctxFile)
def result = check(ctx)
println groovy.json.JsonOutput.toJson(result)