/**
 * Dangerous Deserialization check script — Node.js
 *
 * Now uses ScriptContext format (ctx.sink, ctx.method, ctx.params, etc.)
 * instead of the old CallSite format.
 */

module.exports.check = function(ctx) {
  const sink = ctx.sink;
  const params = ctx.params || [];
  const taint = ctx.taintChain;

  const fullClass = sink.packageName ? sink.packageName + '.' + sink.className : sink.className;
  const methodName = sink.methodName;

  if (fullClass !== 'java.io.ObjectInputStream') {
    return { alert: false };
  }

  let msg = `java.io.ObjectInputStream.${methodName}() — Remote Code Execution risk (CWE-502). Use allow-list filtering or replace with safe serialization.`;
  let conf = 'high';

  // Check parameter sources
  const hasExternalInput = params.some(p =>
    p.sources && p.sources.some(s => s.category === 'external_input')
  );

  if (hasExternalInput || taint) {
    if (taint) {
      msg += ` [Taint from ${taint.sourceMethod}() via ${taint.propagationPath}]`;
      conf = 'high';
    } else {
      msg += ' [External input detected in parameters]';
      conf = 'high';
    }
  }

  return { alert: true, message: msg, confidence: conf };
};