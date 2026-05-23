/**
 * Command Injection check script — Node.js
 *
 * Now uses ScriptContext format (ctx.sink, ctx.method, ctx.params, etc.)
 */

module.exports.check = function(ctx) {
  const sink = ctx.sink;
  const params = ctx.params || [];
  const taint = ctx.taintChain;

  const fullClass = sink.packageName ? sink.packageName + '.' + sink.className : sink.className;
  const methodName = sink.methodName;

  // Runtime.exec()
  if (fullClass === 'java.lang.Runtime' && methodName === 'exec') {
    let msg = 'Runtime.exec() executes external commands — command injection risk (CWE-78). Use ProcessBuilder with separate argument tokens.';
    let conf = 'high';

    // Check for external input in parameters
    const hasExternalInput = params.some(p =>
      p.sources && p.sources.some(s => s.category === 'external_input')
    );

    if (hasExternalInput || taint) {
      if (taint) {
        msg += ` [Taint from ${taint.sourceMethod}() via ${taint.propagationPath} — CONFIRMED injection]`;
        conf = 'high';
      } else {
        msg += ' [External input detected in command parameters — CONFIRMED injection]';
        conf = 'high';
      }
    }

    // Check for hardcoded vs mixed
    const hasHardcoded = params.some(p =>
      p.sources && p.sources.some(s => s.category === 'hardcoded')
    );

    if (hasHardcoded && !hasExternalInput) {
      msg += ' [Parameters appear hardcoded — lower risk but still unsafe pattern]';
      conf = 'medium';
    }

    return { alert: true, message: msg, confidence: conf };
  }

  // ProcessBuilder
  if (fullClass === 'java.lang.ProcessBuilder') {
    let msg = 'ProcessBuilder executes external commands — ensure arguments are not derived from user input (CWE-78).';
    let conf = 'medium';

    const hasExternalInput = params.some(p =>
      p.sources && p.sources.some(s => s.category === 'external_input')
    );

    if (hasExternalInput || taint) {
      if (taint) {
        msg += ` [Taint from ${taint.sourceMethod}() via ${taint.propagationPath} — CONFIRMED injection]`;
        conf = 'high';
      } else {
        msg += ' [External input detected — CONFIRMED injection]';
        conf = 'high';
      }
    }

    return { alert: true, message: msg, confidence: conf };
  }

  return { alert: false };
};