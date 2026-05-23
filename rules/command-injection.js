/**
 * Command Injection check script — Node.js
 *
 * 参数来源三级风险模型:
 *   - external_input (Controller 方法参数) → HIGH — 明确攻击面，确认注入
 *   - tainted (普通方法参数/未溯源变量)     → MEDIUM — 潜在污点，溯源截断在普通函数
 *   - hardcoded/whitelist (字面量/白名单/static final) → 不告警
 *
 * isTainted = isExternalInput || kind==='tainted'
 *   → 脚本用 isExternalInput 区分 high/medium
 *
 * kind: 'hardcoded' = 字面量硬编码; 'whitelist' = 白名单校验后的安全值
 *   → 两者都视为安全，不告警
 */

function isSafePart(part) {
  return part.kind === 'hardcoded' || part.kind === 'whitelist';
}

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

    if (hasTainted) {
      const tainted = collectTaintedNames(params, 'tainted');
      let msg = `Runtime.exec() — potential command injection risk (CWE-78). Parameter source unresolved (traced to ordinary method): ${tainted.join(', ')}`;
      return { alert: true, message: msg, confidence: 'medium' };
    }

    if (hasHardcoded) {
      const allSafe = params.every(p =>
        p.isHardcoded && (p.parts || []).every(isSafePart)
      );
      if (allSafe) {
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
      // start() 无参数且无污点链 → 不告警 (构造器参数安全性由 ProcessBuilder(*) 模式单独检查)
      return { alert: false };
    }

    // ProcessBuilder 构造器 / command() — 有参数可分析
    const hasExternalInput = params.some(p => p.isExternalInput);
    const hasTainted = params.some(p => p.isTainted && !p.isExternalInput);
    const hasHardcoded = params.some(p => p.isHardcoded);

    // HIGH: Controller 外部输入 → 明确攻击面
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

    // MEDIUM: 普通方法参数/未溯源变量 → 潜在污点，溯源截断在普通函数
    if (hasTainted) {
      const tainted = collectTaintedNames(params, 'tainted');
      let msg = `ProcessBuilder with unresolved parameter source — potential command injection risk (CWE-78). Tainted param(s): ${tainted.join(', ')} (source traced to ordinary method, not a Controller)`;
      return { alert: true, message: msg, confidence: 'medium' };
    }

    // 不告警: 全部硬编码或白名单
    if (hasHardcoded) {
      const allSafe = params.every(p =>
        p.isHardcoded && (p.parts || []).every(isSafePart)
      );
      if (allSafe) {
        return { alert: false };
      }
      // 部分 safe + 部分 other → low
      return { alert: true, message: 'ProcessBuilder with hardcoded commands — low injection risk (CWE-78)', confidence: 'low' };
    }

    // 完全未知 → medium
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