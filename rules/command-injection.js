/**
 * Command Injection check script — Node.js
 *
 * 纯静态分析，只依据语法事实:
 *   - external_input: Controller 注解标注的方法参数 (语法事实)
 *   - tainted: 普通方法参数或未溯源变量 (静态无法确认来源)
 *   - hardcoded: 字面量 / static final String 常量 (语法事实)
 *
 * 三级风险:
 *   HIGH   — external_input → 确认注入
 *   MEDIUM — tainted → 潜在注入，需人工核验
 *   不告警  — 全部 hardcoded
 */

module.exports.check = function(ctx) {
  const sink = ctx.sink;
  const params = ctx.params || [];
  const receiverParams = ctx.receiverParams || [];
  const taint = ctx.taintChain;

  const fullClass = sink.packageName ? sink.packageName + '.' + sink.className : sink.className;
  const methodName = sink.methodName;

  // ── Runtime.exec() ─────────────────────────────────────────────────
  if (fullClass === 'java.lang.Runtime' && methodName === 'exec') {
    return checkParams(params, taint, 'Runtime.exec()');
  }

  // ── ProcessBuilder ────────────────────────────────────────────────
  if (fullClass === 'java.lang.ProcessBuilder') {
    // ProcessBuilder.start() — 无参数，检查 receiver 构造链
    if (methodName === 'start') {
      // 1. 有跨文件污点链 → HIGH
      if (taint) {
        return {
          alert: true,
          message: `ProcessBuilder.start() — CONFIRMED command injection. [Taint from ${taint.sourceMethod}() via ${taint.propagationPath}] (CWE-78)`,
          confidence: 'high'
        };
      }

      // 2. receiver 构造参数含 external_input → HIGH
      if (receiverParams.length > 0) {
        const hasExt = receiverParams.some(p => p.isExternalInput);
        const hasTaint = receiverParams.some(p => p.isTainted && !p.isExternalInput);

        if (hasExt) {
          const names = collectTaintedNames(receiverParams, 'external_input');
          return {
            alert: true,
            message: `ProcessBuilder.start() — CONFIRMED command injection risk (CWE-78). Constructor receives external input: ${names.join(', ')}`,
            confidence: 'high'
          };
        }

        if (hasTaint) {
          const names = collectTaintedNames(receiverParams, 'tainted');
          return {
            alert: true,
            message: `ProcessBuilder.start() — potential command injection risk (CWE-78). Constructor receives tainted data: ${names.join(', ')} (source traced to ordinary method, not a Controller)`,
            confidence: 'medium'
          };
        }
      }

      return { alert: false };
    }

    // ProcessBuilder 构造器 / command() — 有参数可直接分析
    return checkParams(params, taint, 'ProcessBuilder');
  }

  return { alert: false };
};

/**
 * 统一参数检查逻辑
 */
function checkParams(params, taint, sinkName) {
  const hasExternalInput = params.some(p => p.isExternalInput);
  const hasTainted = params.some(p => p.isTainted && !p.isExternalInput);
  const hasHardcoded = params.some(p => p.isHardcoded);

  // HIGH: Controller 外部输入
  if (hasExternalInput || taint) {
    let msg = `${sinkName} with external input — CONFIRMED command injection risk (CWE-78).`;
    let conf = 'high';
    if (taint) {
      msg += ` [Taint from ${taint.sourceMethod}() via ${taint.propagationPath}]`;
    }
    const tainted = collectTaintedNames(params, 'external_input');
    if (tainted.length > 0) msg += ` External input: ${tainted.join(', ')}`;
    return { alert: true, message: msg, confidence: conf };
  }

  // MEDIUM: tainted 参数
  if (hasTainted) {
    const tainted = collectTaintedNames(params, 'tainted');
    let msg = `${sinkName} with unresolved parameter source — potential command injection risk (CWE-78). Tainted param(s): ${tainted.join(', ')} (source traced to ordinary method, not a Controller)`;
    return { alert: true, message: msg, confidence: 'medium' };
  }

  // 不告警: 全部硬编码
  if (hasHardcoded) {
    const allHardcoded = params.every(p =>
      p.isHardcoded && (p.parts || []).every(part => part.kind === 'hardcoded')
    );
    if (allHardcoded) {
      return { alert: false };
    }
    return { alert: true, message: `${sinkName} with hardcoded commands — low injection risk (CWE-78)`, confidence: 'low' };
  }

  return { alert: true, message: `${sinkName} — command injection risk (CWE-78).`, confidence: 'medium' };
}

function collectTaintedNames(params, kind) {
  const names = [];
  for (const p of params) {
    for (const part of (p.parts || [])) {
      if (part.kind === kind) {
        names.push(part.name || `param#${p.position}`);
      }
    }
  }
  return names;
}