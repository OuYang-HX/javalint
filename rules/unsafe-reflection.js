/**
 * Unsafe Reflection check script — Node.js
 *
 * Detects Class.forName() or newInstance() with user-controllable
 * class names, which may allow arbitrary class loading and code execution.
 *
 * CWE-470 (Unsafe Reflection)
 */
module.exports.check = function(ctx) {
  const sink = ctx.sink;
  const params = ctx.params || [];
  const taint = ctx.taintChain;
  const className = sink.className;
  const methodName = sink.methodName;

  // Class.forName(className) — most dangerous
  if (className === 'Class' && methodName === 'forName') {
    const classNameParam = params.find(p => p.position === 0);

    if (classNameParam && classNameParam.isExternalInput) {
      const ext = classNameParam.parts.find(p => p.kind === 'external_input');
      const desc = ext ? describeSource(ext) : 'unknown';
      return {
        alert: true,
        message: `Class.forName() with user-controllable class name (${desc}) — arbitrary class loading / RCE risk (CWE-470)`,
        confidence: 'high',
      };
    }

    if (classNameParam && classNameParam.isHardcoded) {
      const value = classNameParam.parts
        .filter(p => p.kind === 'hardcoded' && p.value)
        .map(p => p.value)
        .join('');

      // Hardcoded class name — low risk but still dangerous if not whitelisted
      return {
        alert: true,
        message: `Class.forName("${value}") — verify class is from a whitelist, not arbitrary (CWE-470)`,
        confidence: 'low',
      };
    }

    if (taint) {
      return {
        alert: true,
        message: `Class.forName() with taint from ${taint.sourceMethod}() — unsafe reflection risk (CWE-470)`,
        confidence: 'medium',
      };
    }

    return {
      alert: true,
      message: 'Class.forName() — verify class name is not user-controlled (CWE-470)',
      confidence: 'medium',
    };
  }

  // Class.newInstance() or Constructor.newInstance()
  if (methodName === 'newInstance') {
    if (taint) {
      return {
        alert: true,
        message: `newInstance() with taint from ${taint.sourceMethod}() — unsafe reflection (CWE-470)`,
        confidence: 'medium',
      };
    }

    return {
      alert: true,
      message: 'newInstance() — verify instantiated class is not user-controlled (CWE-470)',
      confidence: 'low',
    };
  }

  return { alert: false };
};

function describeSource(part) {
  const name = part.name || '?';
  if (part.crossFile) return `${name} (cross-file from ${part.callerMethod || '?'})`;
  return `${name} (${part.source || 'unknown'})`;
}