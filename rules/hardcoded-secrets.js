/**
 * Hardcoded Secrets check script — Node.js
 *
 * Detects hardcoded passwords, API keys, or secret keys passed
 * directly to cryptographic key specifications or stored as
 * static final String constants.
 *
 * CWE-798 (Hardcoded Credentials) / CWE-321 (Hardcoded Cryptographic Key)
 */
module.exports.check = function(ctx) {
  const sink = ctx.sink;
  const params = ctx.params || [];
  const className = sink.className;
  const methodName = sink.methodName;

  // ── SecretKeySpec / DESKeySpec / DESedeKeySpec ──
  if (className === 'SecretKeySpec' || className === 'DESKeySpec' || className === 'DESedeKeySpec') {
    // Key material is typically the first parameter
    const keyParam = params.find(p => p.position === 0);

    if (keyParam && keyParam.isHardcoded) {
      // Key is hardcoded — either literal or static final field
      const hardcodedParts = keyParam.parts.filter(p => p.kind === 'hardcoded' && p.value);
      const keyValue = hardcodedParts.map(p => p.value).join('');

      // Check if the value came from a field constant (fieldName set on the part)
      const fromField = hardcodedParts.find(p => p.fieldName);
      const fromMethod = hardcodedParts.find(p => p.methodSignature);

      if (fromField) {
        return {
          alert: true,
          message: `Hardcoded secret in static final field "${fromField.fieldName}" = "${keyValue.substring(0, 10)}..." — move to environment variable or key vault (CWE-798)`,
          confidence: 'high',
        };
      }

      if (fromMethod && /secret|key|password|token|credential/i.test(fromMethod.methodSignature || '')) {
        return {
          alert: true,
          message: `Hardcoded secret key from ${fromMethod.methodSignature} — value "${keyValue.substring(0, 10)}..." should not be in source code (CWE-798)`,
          confidence: 'high',
        };
      }

      if (keyValue) {
        return {
          alert: true,
          message: `Hardcoded secret key "${keyValue.substring(0, 10)}..." in ${className}() — move to environment variable or key vault (CWE-798)`,
          confidence: 'high',
        };
      }
    }

    // Check if key comes from a variable that matches secret patterns
    if (keyParam && keyParam.isExternalInput) {
      const ext = keyParam.parts.find(p => p.kind === 'external_input');
      if (ext && /secret|key|password|token|credential/i.test(ext.name || '')) {
        return {
          alert: true,
          message: `Secret key passed from variable "${ext.name}" — verify it's not hardcoded elsewhere (CWE-798)`,
          confidence: 'medium',
        };
      }
    }

    // Check variable name for hardcoded secret patterns
    for (const p of keyParam?.parts || []) {
      if (p.kind === 'variable' && /secret|key|password|token|credential/i.test(p.varName || '')) {
        return {
          alert: true,
          message: `Secret key from variable "${p.varName}" — likely hardcoded, use environment variables (CWE-321)`,
          confidence: 'medium',
        };
      }
    }

    // Fallback
    return {
      alert: true,
      message: `${className}() — verify key is not hardcoded in source (CWE-321/798)`,
      confidence: 'low',
    };
  }

  return { alert: false };
};