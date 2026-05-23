/**
 * SSRF check script — Node.js
 *
 * Detects URL construction or HTTP connections with user-controllable URLs.
 */
module.exports.check = function(ctx) {
  const sink = ctx.sink;
  const params = ctx.params || [];
  const taint = ctx.taintChain;
  const className = sink.className;
  const methodName = sink.methodName;

  // URL constructor with user input
  if (className === 'URL') {
    for (const p of params) {
      if (p.isExternalInput) {
        const ext = p.parts.find(part => part.kind === 'external_input');
        const desc = ext ? describeSource(ext) : 'unknown';
        let msg = `URL created with user-controllable input (${desc}) — SSRF risk (CWE-918)`;
        let conf = 'high';
        if (taint) msg += ` [Taint from ${taint.sourceMethod}() via ${taint.propagationPath}]`;
        return { alert: true, message: msg, confidence: conf };
      }
    }
  }

  // HttpURLConnection.openConnection
  if (methodName === 'openConnection') {
    return {
      alert: true,
      message: 'HTTP connection opened — verify URL is not user-controlled (CWE-918)',
      confidence: 'medium',
    };
  }

  if (taint) {
    return {
      alert: true,
      message: `Network operation with taint from ${taint.sourceMethod}() — SSRF risk`,
      confidence: 'medium',
    };
  }

  return { alert: true, message: 'Network operation — verify URL source', confidence: 'low' };
};

function describeSource(part) {
  const name = part.name || '?';
  if (part.crossFile) return `${name} (cross-file from ${part.callerMethod || '?'})`;
  return `${name} (${part.source || 'unknown'})`;
}