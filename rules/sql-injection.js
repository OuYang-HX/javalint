/**
 * SQL Injection check script — Node.js
 *
 * Uses structured ScriptContext — no string parsing needed!
 *
 * Key fields on each param:
 *   param.isExternalInput  → bool, 是否有外部输入
 *   param.isHardcoded      → bool, 是否有硬编码
 *   param.isTainted        → bool, 是否受污染
 *   param.composite        → "direct"|"concat"|"method_return"|"field"|"unknown"
 *   param.parts[]          → 每个组成部分
 *     part.kind            → "hardcoded"|"external_input"|"method_return"|"field"|"variable"|"unknown"
 *     part.value           → 硬编码的值 (kind=hardcoded)
 *     part.source          → "method_parameter"|... (kind=external_input)
 *     part.name            → 变量/参数名 (kind=external_input/variable)
 *     part.type            → 类型 (kind=external_input)
 *     part.crossFile       → 是否跨文件 (kind=external_input)
 *     part.callerMethod    → 跨文件调用者方法 (kind=external_input)
 *     part.callerFile      → 跨文件调用者文件 (kind=external_input)
 */

module.exports.check = function(ctx) {
  const sink = ctx.sink;
  const params = ctx.params || [];
  const objHistory = ctx.objHistory;
  const retUsage = ctx.retUsage;
  const taint = ctx.taintChain;

  const fullClass = sink.packageName ? sink.packageName + '.' + sink.className : sink.className;
  const methodName = sink.methodName;

  // PreparedStatement is safe
  if (fullClass === 'java.sql.PreparedStatement') {
    return { alert: false };
  }

  // ── Collect structured parts (no string parsing!) ──────────────────

  const externalParts = [];
  const hardcodedParts = [];

  for (const p of params) {
    for (const part of (p.parts || [])) {
      if (part.kind === 'external_input') externalParts.push(part);
      else if (part.kind === 'hardcoded') hardcodedParts.push(part);
    }
  }

  const hasExternal = externalParts.length > 0;
  const hasHardcoded = hardcodedParts.length > 0;

  // ── Build message ─────────────────────────────────────────────────

  if (fullClass === 'java.sql.Connection' && methodName === 'createStatement') {
    let msg = 'Connection.createStatement() creates an unsafe Statement — use prepareStatement() instead';
    let conf = 'medium';

    if (hasExternal) {
      msg += ` [External input: ${describeExternal(externalParts[0])}]`;
      conf = 'high';
    } else if (taint) {
      msg += ` [Taint from ${taint.sourceMethod}() via ${taint.propagationPath}]`;
      conf = 'high';
    }

    return { alert: true, message: msg, confidence: conf };
  }

  if (fullClass === 'java.sql.Statement') {
    let msg;
    let conf;

    if (hasExternal && hasHardcoded) {
      // Most dangerous: concatenation with external input
      const sqlFragment = hardcodedParts
        .filter(h => h.value)
        .map(h => h.value)
        .join(' + ');
      const extDesc = describeExternal(externalParts[0]);
      msg = `Statement.${methodName}() with SQL concatenation: "${sqlFragment}" + ${extDesc} — confirmed SQL injection`;
      conf = 'high';
    } else if (hasExternal) {
      const extDesc = describeExternal(externalParts[0]);
      msg = `Statement.${methodName}() with external input (${extDesc}) — confirmed SQL injection`;
      conf = 'high';
    } else if (hasHardcoded) {
      msg = `Statement.${methodName}() with hardcoded values only — low risk but use PreparedStatement`;
      conf = 'low';
    } else if (taint) {
      msg = `Statement.${methodName}() — taint from ${taint.sourceMethod}() via ${taint.propagationPath} — confirmed SQL injection`;
      conf = 'high';
    } else {
      msg = `Statement.${methodName}() uses non-parameterized SQL — use PreparedStatement instead`;
      conf = 'medium';
    }

    // Enrich with object history
    if (objHistory && objHistory.priorCalls && objHistory.priorCalls.length > 0) {
      const prior = objHistory.priorCalls.map(r => r.signature);
      msg += ` [Object history: ${prior.join(' → ')}]`;
    }

    // Enrich with return value usage
    if (retUsage && retUsage.subsequentCalls && retUsage.subsequentCalls.length > 0) {
      const retUses = retUsage.subsequentCalls.map(r => r.signature);
      msg += ` [Return used by: ${retUses.join(', ')}]`;
    }

    return { alert: true, message: msg, confidence: conf };
  }

  if (/execute/i.test(methodName)) {
    return { alert: true, message: `${fullClass}.${methodName}() — verify parameterized queries`, confidence: 'low' };
  }

  return { alert: false };
};

function describeExternal(part) {
  const name = part.name || '?';
  const source = part.source || 'unknown';

  if (part.crossFile) {
    const caller = part.callerMethod || '?';
    return `${name} (cross-file from ${caller})`;
  } else if (source === 'method_parameter') {
    return `${name} (method parameter)`;
  } else if (source === 'variable_pattern') {
    return `${name} (variable name pattern)`;
  } else {
    return name;
  }
}