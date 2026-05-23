/**
 * XPath/LDAP/JNDI Injection check script — Node.js
 *
 * Detects XPath, LDAP, or JNDI operations where the query/lookup
 * input is user-controllable, allowing injection attacks.
 *
 * CWE-643 (XPath), CWE-90 (LDAP), CWE-917 (JNDI)
 */
module.exports.check = function(ctx) {
  const sink = ctx.sink;
  const params = ctx.params || [];
  const taint = ctx.taintChain;
  const className = sink.className;
  const methodName = sink.methodName;
  const packageName = sink.packageName || '';

  // ── XPath Injection ──
  if (packageName.includes('xpath') || className === 'XPath' || className === 'XPathExpression') {
    for (const p of params) {
      if (p.isExternalInput) {
        const ext = p.parts.find(part => part.kind === 'external_input');
        const desc = ext ? describeSource(ext) : 'unknown';
        return {
          alert: true,
          message: `XPath.compile() with user-controllable expression (${desc}) — XPath injection risk (CWE-643)`,
          confidence: 'high',
        };
      }
    }

    if (taint) {
      return {
        alert: true,
        message: `XPath operation with taint from ${taint.sourceMethod}() — XPath injection risk (CWE-643)`,
        confidence: 'medium',
      };
    }

    return {
      alert: true,
      message: 'XPath expression compilation — verify expression is not user-controlled (CWE-643)',
      confidence: 'low',
    };
  }

  // ── LDAP Injection ──
  if (packageName.includes('naming') || className === 'DirContext' || className === 'InitialDirContext') {
    // DirContext.search() — LDAP filter injection
    if (methodName === 'search') {
      for (const p of params) {
        if (p.isExternalInput) {
          const ext = p.parts.find(part => part.kind === 'external_input');
          const desc = ext ? describeSource(ext) : 'unknown';
          return {
            alert: true,
            message: `DirContext.search() with user-controllable filter (${desc}) — LDAP injection risk (CWE-90)`,
            confidence: 'high',
          };
        }
      }

      if (taint) {
        return {
          alert: true,
          message: `LDAP search with taint from ${taint.sourceMethod}() — LDAP injection risk (CWE-90)`,
          confidence: 'medium',
        };
      }

      return {
        alert: true,
        message: 'LDAP search operation — verify filter parameters are sanitized (CWE-90)',
        confidence: 'medium',
      };
    }
  }

  // ── JNDI Injection ──
  if (methodName === 'lookup' && (className === 'Context' || className === 'InitialContext' || className === 'InitialDirContext')) {
    for (const p of params) {
      if (p.isExternalInput) {
        const ext = p.parts.find(part => part.kind === 'external_input');
        const desc = ext ? describeSource(ext) : 'unknown';
        return {
          alert: true,
          message: `JNDI lookup() with user-controllable name (${desc}) — JNDI injection/RCE risk (CWE-917)`,
          confidence: 'critical',
        };
      }
    }

    if (taint) {
      return {
        alert: true,
        message: `JNDI lookup with taint from ${taint.sourceMethod}() — JNDI injection risk (CWE-917)`,
        confidence: 'high',
      };
    }

    return {
      alert: true,
      message: 'JNDI lookup — verify name is not user-controlled (CWE-917)',
      confidence: 'medium',
    };
  }

  return { alert: false };
};

function describeSource(part) {
  const name = part.name || '?';
  if (part.crossFile) return `${name} (cross-file from ${part.callerMethod || '?'})`;
  return `${name} (${part.source || 'unknown'})`;
}