/**
 * Command Injection check script — Node.js
 *
 * Detects Runtime.exec() and ProcessBuilder usage with external input.
 *
 * Decision logic:
 *   - External input → alert (high confidence)
 *   - Hardcoded only → no alert (safe pattern)
 *   - Unknown source → alert (medium confidence, manual review needed)
 */

module.exports.check = function(ctx) {
  const sink = ctx.sink;
  const params = ctx.params || [];
  const taint = ctx.taintChain;

  const fullClass = sink.packageName ? sink.packageName + '.' + sink.className : sink.className;
  const methodName = sink.methodName;

  // ── Runtime.exec() ──────────────────────────────────────────────────
  if (fullClass === 'java.lang.Runtime' && methodName === 'exec') {
    const hasExternalInput = params.some(p => p.isExternalInput);
    const hasHardcoded = params.some(p => p.isHardcoded);
    const allHardcoded = params.some(p => p.isHardcoded) && !params.some(p => p.isExternalInput);

    if (hasExternalInput || taint) {
      let msg = 'Runtime.exec() executes external commands — command injection risk (CWE-78).';
      let conf = 'high';
      if (taint) {
        msg += ` [Taint from ${taint.sourceMethod}() via ${taint.propagationPath} — CONFIRMED injection]`;
      } else {
        msg += ' [External input detected in command parameters — CONFIRMED injection]';
      }
      // Show which params are external input
      const extParts = [];
      for (const p of params) {
        if (p.isExternalInput) {
          for (const part of (p.parts || [])) {
            if (part.kind === 'external_input') {
              extParts.push(part.name || `param#${p.position}`);
            }
          }
        }
      }
      if (extParts.length > 0) {
        msg += ` Tainted: ${extParts.join(', ')}`;
      }
      return { alert: true, message: msg, confidence: conf };
    }

    if (allHardcoded) {
      // Hardcoded command — not injection, but still unsafe pattern (low risk)
      return { alert: true, message: 'Runtime.exec() with hardcoded command — low injection risk but prefer ProcessBuilder with separate tokens (CWE-78)', confidence: 'low' };
    }

    // Unknown source — medium risk
    return { alert: true, message: 'Runtime.exec() — command injection risk (CWE-78). Use ProcessBuilder with separate argument tokens.', confidence: 'medium' };
  }

  // ── ProcessBuilder ──────────────────────────────────────────────────
  if (fullClass === 'java.lang.ProcessBuilder') {
    const hasExternalInput = params.some(p => p.isExternalInput);
    const hasHardcoded = params.some(p => p.isHardcoded);

    // ProcessBuilder 构造器参数来自构造器调用的参数解析
    // 对于 new ProcessBuilder(commands)，params 是构造器参数
    // 对于 processBuilder.start()，params 是空（start 无参数）

    if (methodName === 'start') {
      // ProcessBuilder.start() 本身无参数
      // 如果有污点链 → 告警 high
      if (taint) {
        return {
          alert: true,
          message: `ProcessBuilder.start() — command injection risk. [Taint from ${taint.sourceMethod}() via ${taint.propagationPath} — CONFIRMED injection] (CWE-78)`,
          confidence: 'high'
        };
      }
      // start() 无参数且无污点链 → 不告警
      // 构造器的安全性由 ProcessBuilder(*) 或 ProcessBuilder.ProcessBuilder(*) 模式单独检查
      return { alert: false };
    }

    // ProcessBuilder 构造器 / command() — 有参数可分析
    if (hasExternalInput) {
      let msg = 'ProcessBuilder with external input — CONFIRMED command injection risk (CWE-78).';
      const extParts = [];
      for (const p of params) {
        if (p.isExternalInput) {
          for (const part of (p.parts || [])) {
            if (part.kind === 'external_input') {
              extParts.push(part.name || `param#${p.position}`);
              if (part.crossFile) {
                msg += ` [Cross-file: ${part.callerMethod} in ${part.callerFile}]`;
              }
            }
          }
        }
      }
      if (extParts.length > 0) {
        msg += ` Tainted: ${extParts.join(', ')}`;
      }
      if (taint) {
        msg += ` [Taint from ${taint.sourceMethod}() via ${taint.propagationPath}]`;
      }
      return { alert: true, message: msg, confidence: 'high' };
    }

    if (taint) {
      return {
        alert: true,
        message: `ProcessBuilder — command injection risk. [Taint from ${taint.sourceMethod}() via ${taint.propagationPath} — CONFIRMED injection] (CWE-78)`,
        confidence: 'high'
      };
    }

    // 全部硬编码 → 不告警
    if (hasHardcoded && !hasExternalInput) {
      // 检查是否所有 parts 都是 hardcoded
      const allPartsHardcoded = params.every(p =>
        p.isHardcoded && (p.parts || []).every(part => part.kind === 'hardcoded')
      );
      if (allPartsHardcoded) {
        return { alert: false };
      }
      // 部分 hardcode + 部分 unknown → low risk
      return { alert: true, message: 'ProcessBuilder with hardcoded commands — low injection risk but verify no user input reaches the process (CWE-78)', confidence: 'low' };
    }

    // 未知来源 → medium
    return { alert: true, message: 'ProcessBuilder — command injection risk. Verify arguments are not from user input (CWE-78).', confidence: 'medium' };
  }

  return { alert: false };
};