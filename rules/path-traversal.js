/**
 * Path Traversal check script — Node.js
 *
 * Detects file operations where the path/filename is derived from
 * external input (user-controlled), allowing directory traversal.
 *
 * Key checks on param:
 *   param.isExternalInput → user-controlled path
 *   param.isHardcoded → safe, hardcoded path
 *   param.parts[].kind === 'external_input' → trace source
 */
module.exports.check = function(ctx) {
  const sink = ctx.sink;
  const params = ctx.params || [];
  const taint = ctx.taintChain;

  // FileInputStream(File) or FileInputStream(String)
  // FileOutputStream(File) or FileOutputStream(String)
  const methodName = sink.methodName;

  // Check each parameter for user-controllable paths
  for (const p of params) {
    if (p.isExternalInput) {
      // External input used as file path — path traversal risk
      const externalPart = p.parts.find(part => part.kind === 'external_input');
      const desc = externalPart ? describeSource(externalPart) : 'unknown source';

      let msg = `File operation ${methodName}() with user-controllable path (${desc}) — path traversal risk (CWE-22)`;
      let conf = 'high';

      if (taint) {
        msg += ` [Taint from ${taint.sourceMethod}() via ${taint.propagationPath}]`;
      }

      return { alert: true, message: msg, confidence: conf };
    }
  }

  // No external input in path parameters — check taint chain
  if (taint) {
    return {
      alert: true,
      message: `File operation ${methodName}() — taint from ${taint.sourceMethod}() via ${taint.propagationPath} — path traversal risk`,
      confidence: 'medium',
    };
  }

  // Hardcoded or unknown source — low risk
  return {
    alert: true,
    message: `${methodName}() — verify file paths are validated against traversal`,
    confidence: 'low',
  };
};

function describeSource(part) {
  const name = part.name || '?';
  if (part.crossFile) {
    return `${name} (cross-file from ${part.callerMethod || '?'})`;
  }
  return `${name} (${part.source || 'unknown'})`;
}