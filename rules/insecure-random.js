/**
 * Insecure Random check script — Node.js
 *
 * Detects java.util.Random usage in security-sensitive contexts.
 * java.security.SecureRandom is the safe alternative.
 */
module.exports.check = function(ctx) {
  const sink = ctx.sink;
  const className = sink.className;
  const methodName = sink.methodName;

  // java.util.Random constructor
  if (className === 'Random' && methodName === 'Random') {
    return {
      alert: true,
      message: 'java.util.Random created — not cryptographically secure. Use java.security.SecureRandom for security-sensitive operations (CWE-338)',
      confidence: 'high',
    };
  }

  // java.util.Random method calls (nextLong, nextInt, etc.)
  if (className === 'Random' && methodName.startsWith('next')) {
    return {
      alert: true,
      message: `Random.${methodName}() — not cryptographically secure. Use SecureRandom for tokens, passwords, or nonces (CWE-338)`,
      confidence: 'high',
    };
  }

  return { alert: false };
};