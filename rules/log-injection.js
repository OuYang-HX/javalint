/**
 * Log Injection check script — Node.js
 *
 * Detects user-controllable input passed to logger calls.
 * Log injection can allow attackers to forge log entries,
 * inject false audit trails, or exploit log analysis tools.
 *
 * CWE-117 (Log Injection / Log Forging)
 */
module.exports.check = function(ctx) {
  const sink = ctx.sink;
  const params = ctx.params || [];
  const taint = ctx.taintChain;

  // Only alert if there's external input or taint
  const hasExternalInput = params.some(p => p.isExternalInput);
  const hasTaint = taint !== null && taint !== undefined;

  if (!hasExternalInput && !hasTaint) {
    return { alert: false };
  }

  // Find which params are tainted
  const taintedParams = params.filter(p => p.isExternalInput);
  const taintDesc = taintedParams.map(p => {
    const ext = p.parts.find(part => part.kind === 'external_input');
    if (ext) {
      const name = ext.name || '?';
      if (ext.crossFile) return `${name} (cross-file from ${ext.callerMethod || '?'})`;
      return name;
    }
    return '?';
  }).join(', ');

  return {
    alert: true,
    message: `Logger.${sink.methodName}() with user-controllable input (${taintDesc}) — log injection / log forging risk. Sanitize newlines and CRLF before logging (CWE-117)`,
    confidence: hasExternalInput ? 'high' : 'medium',
  };
};