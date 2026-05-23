/**
 * XXE check script — Node.js
 *
 * Detects XML parsing with DocumentBuilder.parse() where:
 *   1. The XML input may be user-controlled (injection risk)
 *   2. The DocumentBuilderFactory has not been hardened (feature not set)
 *
 * Note: We check DocumentBuilder.parse() as the sink, and trace back
 * to find the factory creation. If no setFeature() calls are found,
 * the factory is vulnerable to XXE.
 */
module.exports.check = function(ctx) {
  const sink = ctx.sink;
  const params = ctx.params || [];
  const objHistory = ctx.objHistory;
  const taint = ctx.taintChain;
  const className = sink.className;
  const methodName = sink.methodName;

  // DocumentBuilder.parse() — check if XML input is user-controlled
  if (className === 'DocumentBuilder' && methodName === 'parse') {
    // Check if user-controlled XML input
    let hasExternalInput = false;
    let extDesc = '';
    for (const p of params) {
      if (p.isExternalInput) {
        hasExternalInput = true;
        const ext = p.parts.find(part => part.kind === 'external_input');
        extDesc = ext ? describeSource(ext) : 'user input';
        break;
      }
    }

    // Check if DocumentBuilderFactory has been hardened
    // Look for setFeature() calls in the object creation chain
    let isHardened = false;
    if (objHistory) {
      // Check if there are priorCalls that include setFeature
      const allCalls = [
        ...(objHistory.priorCalls || []),
        ...(objHistory.priorPassedTo || []),
      ];
      for (const call of allCalls) {
        if (call.signature.includes('setFeature')) {
          isHardened = true;
          break;
        }
      }
    }

    if (!isHardened && hasExternalInput) {
      return {
        alert: true,
        message: `DocumentBuilder.parse() with user-controlled XML input (${extDesc}) and no XXE protection — critical XXE risk (CWE-611)`,
        confidence: 'high',
      };
    }

    if (!isHardened) {
      return {
        alert: true,
        message: 'DocumentBuilder.parse() without XXE protection — set disallow-doctype-decl or disable external entities (CWE-611)',
        confidence: 'high',
      };
    }

    if (hasExternalInput) {
      return {
        alert: true,
        message: `DocumentBuilder.parse() with user-controlled XML (${extDesc}) — verify entity limits even with XXE protection`,
        confidence: 'medium',
      };
    }

    return { alert: false };
  }

  // DocumentBuilderFactory.newInstance() — check if factory is hardened later
  if (className === 'DocumentBuilderFactory' && methodName === 'newInstance') {
    return {
      alert: true,
      message: 'DocumentBuilderFactory created — ensure setFeature() is called to disable XXE (CWE-611)',
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