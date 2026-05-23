/**
 * Weak Cryptography check script — Node.js
 *
 * Detects:
 *   - Weak cipher algorithms: DES, RC4, ECB mode
 *   - Broken hash functions: MD5, SHA-1
 *
 * Key checks on param:
 *   param.isHardcoded → algorithm name is hardcoded, can inspect value
 *   param.parts[].kind === 'hardcoded' → get the algorithm string
 */
module.exports.check = function(ctx) {
  const sink = ctx.sink;
  const params = ctx.params || [];
  const className = sink.className;
  const methodName = sink.methodName;

  // ── Cipher.getInstance(algorithm) ──
  if (className === 'Cipher' && methodName === 'getInstance') {
    const algoParam = params.find(p => p.position === 0);
    if (algoParam) {
      const algoValue = getHardcodedValue(algoParam);

      if (algoValue) {
        // DES (56-bit key, broken)
        if (/\bDES\b/.test(algoValue) && !/\bDESede\b/.test(algoValue) && !/\b3DES\b/.test(algoValue)) {
          return {
            alert: true,
            message: `Cipher.getInstance("${algoValue}") — DES is broken (56-bit key). Use AES with CBC/GCM mode (CWE-327)`,
            confidence: 'high',
          };
        }

        // ECB mode (no semantic security)
        if (/\bECB\b/.test(algoValue)) {
          return {
            alert: true,
            message: `Cipher.getInstance("${algoValue}") — ECB mode provides no semantic security (identical blocks → identical ciphertext). Use CBC or GCM mode (CWE-327)`,
            confidence: 'high',
          };
        }

        // RC4 (broken stream cipher)
        if (/\bRC4\b/.test(algoValue) || /\bARCFOUR\b/.test(algoValue)) {
          return {
            alert: true,
            message: `Cipher.getInstance("${algoValue}") — RC4 is broken. Use AES (CWE-327)`,
            confidence: 'high',
          };
        }

        // RSA without OAEP (vulnerable to padding oracle)
        if (/\bRSA\b/.test(algoValue) && !/\bOAEP\b/.test(algoValue)) {
          return {
            alert: true,
            message: `Cipher.getInstance("${algoValue}") — RSA without OAEP padding is vulnerable. Use RSA/ECB/OAEPWithSHA-256AndMGF1Padding (CWE-327)`,
            confidence: 'high',
          };
        }
      }

      // Algorithm is not hardcoded or unknown
      if (algoParam.isExternalInput) {
        return {
          alert: true,
          message: 'Cipher algorithm from external input — algorithm injection risk (CWE-327)',
          confidence: 'high',
        };
      }

      return {
        alert: true,
        message: `Cipher.getInstance() — verify algorithm is not weak (CWE-327)`,
        confidence: 'low',
      };
    }
  }

  // ── MessageDigest.getInstance(algorithm) ──
  if (className === 'MessageDigest' && methodName === 'getInstance') {
    const algoParam = params.find(p => p.position === 0);
    if (algoParam) {
      const algoValue = getHardcodedValue(algoParam);

      if (algoValue) {
        // MD5 (collision attacks)
        if (/\bMD5\b/i.test(algoValue)) {
          return {
            alert: true,
            message: `MessageDigest.getInstance("${algoValue}") — MD5 is broken (collision attacks). Use SHA-256 or SHA-3 (CWE-328)`,
            confidence: 'high',
          };
        }

        // SHA-1 (collision attacks, SHAttered)
        if (/\bSHA-?1\b/i.test(algoValue) && !/\bSHA-?1[0-9]/.test(algoValue)) {
          return {
            alert: true,
            message: `MessageDigest.getInstance("${algoValue}") — SHA-1 is broken (collision attacks). Use SHA-256 or SHA-3 (CWE-328)`,
            confidence: 'high',
          };
        }

        // Safe algorithms — no alert
        if (/\bSHA-?(224|256|384|512|3)\b/i.test(algoValue)) {
          return { alert: false };
        }
      }

      if (algoParam.isExternalInput) {
        return {
          alert: true,
          message: 'Hash algorithm from external input — algorithm injection risk (CWE-328)',
          confidence: 'high',
        };
      }

      return {
        alert: true,
        message: 'MessageDigest.getInstance() — verify algorithm is not weak (CWE-328)',
        confidence: 'low',
      };
    }
  }

  return { alert: false };
};

function getHardcodedValue(param) {
  if (!param.isHardcoded && param.composite !== 'concat') return null;
  return param.parts
    .filter(p => p.kind === 'hardcoded' && p.value)
    .map(p => p.value)
    .join('');
}