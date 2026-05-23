/**
 * Command Injection check script — Node.js
 *
 * 纯静态分析，不依赖变量名语义猜测:
 *   - external_input: Controller 注解标注的方法参数 (语法事实)
 *   - tainted: 普通方法参数或未溯源变量 (静态无法确认来源)
 *   - hardcoded: 字面量 / static final String 常量 (语法事实)
 *
 * 三级风险:
 *   HIGH   — external_input → 确认注入 (Controller 注解事实)
 *   MEDIUM — tainted → 潜在注入 (来源未知，需人工核验)
 *   不告警  — 全部 hardcoded
 */

module.exports.check = function(ctx) {
  const sink = ctx.sink;
  const params = ctx.params || [];
  const taint = ctx.taintChain;

  const fullClass = sink.packageName ? sink.packageName + '.' + sink.className : sink.className;
  const methodName = sink.methodName;

  // ── Runtime.exec() ─────────────────────────────────────────────────
  if (fullClass === 'java.lang.Runtime' && methodName === 'exec') {
    const hasExternalInput = params.some(p => p.isExternalInput);
    const hasTainted = params.some(p => p.isTainted && !p.isExternalInput);
    const hasHardcoded = params.some(p => p.isHardcoded);

    // HIGH: Controller 外部输入
    if (hasExternalInput || taint) {
      let msg = 'Runtime.exec() — CONFIRMED command injection risk (CWE-78).';
      let conf = 'high';
      if (taint) {
        msg += ` [Taint from ${taint.sourceMethod}() via ${taint.propagationPath}]`;
      }
      const tainted = collectTaintedNames(params, 'external_input');
      if (tainted.length > 0) msg += ` External input: ${tainted.join(', ')}`;
      return { alert: true, message: msg, confidence: conf };
    }

    // MEDIUM: 普通方法参数/未溯源变量
    if (hasTainted) {
      const tainted = collectTaintedNames(params, 'tainted');
      let msg = `Runtime.exec() — potential command injection risk (CWE-78). Parameter source unresolved (traced to ordinary method): ${tainted.join(', ')}`;
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
      return { alert: true, message: 'Runtime.exec() with hardcoded command — low injection risk (CWE-78)', confidence: 'low' };
    }

    return { alert: true, message: 'Runtime.exec() — command injection risk (CWE-78). Use ProcessBuilder with separate argument tokens.', confidence: 'medium' };
  }

  // ── ProcessBuilder ─────────────────────────────────────────────────
  if (fullClass === 'java.lang.ProcessBuilder') {
    // ProcessBuilder.start() — 无参数
    if (methodName === 'start') {
      if (taint) {
        return {
          alert: true,
          message: `ProcessBuilder.start() — CONFIRMED command injection. [Taint from ${taint.sourceMethod}() via ${taint.propagationPath}] (CWE-78)`,
          confidence: 'high'
        };
      }
      return { alert: false };
    }

    // ProcessBuilder 构造器 / command() — 有参数可分析
    const hasExternalInput = params.some(p => p.isExternalInput);
    const hasTainted = params.some(p => p.isTainted && !p.isExternalInput);
    const hasHardcoded = params.some(p => p.isHardcoded);

    // HIGH: Controller 外部输入
    if (hasExternalInput || taint) {
      let msg = 'ProcessBuilder with external input — CONFIRMED command injection risk (CWE-78).';
      let conf = 'high';
      if (taint) {
        msg += ` [Taint from ${taint.sourceMethod}() via ${taint.propagationPath}]`;
      }
      const tainted = collectTaintedNames(params, 'external_input');
      if (tainted.length > 0) msg += ` External input: ${tainted.join(', ')}`;
      return { alert: true, message: msg, confidence: conf };
    }

    // MEDIUM: 普通方法参数/未溯源变量
    if (hasTainted) {
      const tainted = collectTaintedNames(params, 'tainted');
      let msg = `ProcessBuilder with unresolved parameter source — potential command injection risk (CWE-78). Tainted param(s): ${tainted.join(', ')} (source traced to ordinary method, not a Controller)`;
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
      return { alert: true, message: 'ProcessBuilder with hardcoded commands — low injection risk (CWE-78)', confidence: 'low' };
    }

    return { alert: true, message: 'ProcessBuilder — command injection risk. Verify arguments are not from user input (CWE-78).', confidence: 'medium' };
  }

  return { alert: false };
};

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