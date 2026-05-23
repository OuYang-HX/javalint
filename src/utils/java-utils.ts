/**
 * Java signature parsing utilities
 */

import * as path from 'path';
import * as fs from 'fs';

/** Java primitive types */
const JAVA_PRIMITIVES = new Set([
  'int', 'long', 'float', 'double', 'boolean', 'byte', 'short', 'char', 'void',
]);

/** Java boxed/common types: shortName → fullQualifiedName */
const JAVA_BOXED_MAP: Record<string, string> = {
  'String': 'java.lang.String',
  'Integer': 'java.lang.Integer',
  'Long': 'java.lang.Long',
  'Double': 'java.lang.Double',
  'Float': 'java.lang.Float',
  'Boolean': 'java.lang.Boolean',
  'Object': 'java.lang.Object',
  'Class': 'java.lang.Class',
  'List': 'java.util.List',
  'Map': 'java.util.Map',
  'Set': 'java.util.Set',
  'ArrayList': 'java.util.ArrayList',
  'HashMap': 'java.util.HashMap',
  'Connection': 'java.sql.Connection',
  'PreparedStatement': 'java.sql.PreparedStatement',
  'Statement': 'java.sql.Statement',
  'ResultSet': 'java.sql.ResultSet',
  'ObjectInputStream': 'java.io.ObjectInputStream',
  'FileInputStream': 'java.io.FileInputStream',
  'IOException': 'java.io.IOException',
  'Exception': 'java.lang.Exception',
  'RuntimeException': 'java.lang.RuntimeException',
  'Throwable': 'java.lang.Throwable',
  'BigDecimal': 'java.math.BigDecimal',
  'BigInteger': 'java.math.BigInteger',
  'Date': 'java.util.Date',
  'Optional': 'java.util.Optional',
  'Stream': 'java.util.stream.Stream',
  'InputStream': 'java.io.InputStream',
  'OutputStream': 'java.io.OutputStream',
  'Reader': 'java.io.Reader',
  'Writer': 'java.io.Writer',
  'File': 'java.io.File',
  'Path': 'java.nio.file.Path',
  'URL': 'java.net.URL',
  'URI': 'java.net.URI',
  'Thread': 'java.lang.Thread',
  'Runnable': 'java.lang.Runnable',
  'Callable': 'java.util.concurrent.Callable',
  'Future': 'java.util.concurrent.Future',
  'CompletableFuture': 'java.util.concurrent.CompletableFuture',
  'HttpServletRequest': 'javax.servlet.http.HttpServletRequest',
  'HttpServletResponse': 'javax.servlet.http.HttpServletResponse',
  'HttpClient': 'java.net.http.HttpClient',
  'HttpRequest': 'java.net.http.HttpRequest',
  'HttpResponse': 'java.net.http.HttpResponse',
  'ProcessBuilder': 'java.lang.ProcessBuilder',
  'Runtime': 'java.lang.Runtime',
  'ScriptEngine': 'javax.script.ScriptEngine',
  'X509TrustManager': 'javax.net.ssl.X509TrustManager',
  'SSLContext': 'javax.net.ssl.SSLContext',
  'TrustManager': 'javax.net.ssl.TrustManager',
};

/**
 * Parse parameter types from a Java method signature string.
 * "(String, int)" → ["String", "int"]
 * "(Long)" → ["Long"]
 * "()" → []
 */
export function parseParameterTypes(signature: string | null): string[] {
  if (!signature) return [];
  const match = signature.match(/\(([^)]*)\)/);
  if (!match) return [];
  const paramsStr = match[1];
  if (!paramsStr || paramsStr.trim() === '') return [];
  return paramsStr
    .split(',')
    .map(p => p.trim().split(/\s+/)[0] || '')
    .filter(t => t.length > 0);
}

/**
 * Enhance short type names to fully qualified Java class names.
 * Priority: JAVA_BOXED_MAP > imports > original
 */
export function enhanceTypeName(shortName: string, imports: Map<string, string>): string {
  if (JAVA_PRIMITIVES.has(shortName)) return shortName;
  if (JAVA_BOXED_MAP[shortName]) return JAVA_BOXED_MAP[shortName];
  if (imports.has(shortName)) return imports.get(shortName)!;
  return shortName;
}

/**
 * Resolve a short type name to full class name.
 * Used for local variable type resolution.
 */
export function resolveTypeName(shortName: string, imports: Map<string, string>): string {
  if (JAVA_PRIMITIVES.has(shortName)) return shortName;
  if (JAVA_BOXED_MAP[shortName]) return JAVA_BOXED_MAP[shortName];
  if (imports.has(shortName)) return imports.get(shortName)!;
  // Could be a project-internal class or unknown — return as-is
  return shortName;
}

/**
 * Build a full qualified method signature string
 * e.g. "com.example.service.UserService.findByUsername(java.lang.String)"
 */
export function buildFullQualifiedName(
  packageName: string,
  className: string,
  methodName: string,
  parameterTypes: string[],
): string {
  const params = parameterTypes.join(',');
  if (packageName) {
    return `${packageName}.${className}.${methodName}(${params})`;
  }
  if (className) {
    return `${className}.${methodName}(${params})`;
  }
  return `${methodName}(${params})`;
}
