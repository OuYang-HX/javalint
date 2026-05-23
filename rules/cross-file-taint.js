/**
 * Cross-file taint propagation check script — Node.js
 *
 * Now uses ScriptContext format
 */

module.exports.check = function(ctx) {
  const sink = ctx.sink;
  const taint = ctx.taintChain;

  if (!taint) {
    return { alert: false };
  }

  const fullClass = sink.packageName ? sink.packageName + '.' + sink.className : sink.className;
  const methodName = sink.methodName;
  let message = '';

  if (fullClass === 'java.sql.Statement' || (fullClass === 'java.sql.Connection' && methodName === 'createStatement')) {
    message = `User input '${taint.sourceParameters.join(', ')}' from ${taint.sourceMethod}() ` +
              `flows through ${taint.propagationPath} to ${sink.className}.${methodName}() — confirmed SQL injection (CWE-89)`;
  } else if (fullClass === 'java.io.ObjectInputStream') {
    message = `User input '${taint.sourceParameters.join(', ')}' from ${taint.sourceMethod}() ` +
              `flows through ${taint.propagationPath} to ${sink.className}.${methodName}() — confirmed deserialization RCE (CWE-502)`;
  } else if (fullClass === 'java.lang.Runtime' || fullClass === 'java.lang.ProcessBuilder') {
    message = `User input '${taint.sourceParameters.join(', ')}' from ${taint.sourceMethod}() ` +
              `flows through ${taint.propagationPath} to ${sink.className}.${methodName}() — confirmed command injection (CWE-78)`;
  } else {
    message = `User input from ${taint.sourceMethod}() propagates through ${taint.propagationPath} ` +
              `to dangerous API ${fullClass}.${methodName}() — potential security risk (CWE-9)`;
  }

  return { alert: true, message, confidence: taint.confidence };
};