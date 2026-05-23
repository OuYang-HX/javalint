#!/usr/bin/env node
/**
 * JDK API Index Builder (Full Extraction)
 *
 * Uses `javap -public -s` to extract complete method metadata from class files:
 *   - Method descriptors (JVM format: precise param types + return type, no erasure)
 *   - Inheritance (extends + implements)
 *   - Throws declarations
 *   - Method modifiers (static, abstract, final, synchronized, native)
 *   - Field types (with descriptor)
 *   - Deprecated markers (from -verbose, optional)
 *
 * Output format: structured JSON with per-class entries.
 *
 * Performance:
 *   - JDK 156 classes:        ~0.3s
 *   - Maven repo 13K classes:  ~10s
 *
 * Usage:
 *   node build-jdk-index.js                      # JDK only
 *   node build-jdk-index.js --maven              # JDK + Maven local repo
 *   node build-jdk-index.js -o custom.json       # Custom output path
 */

const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const JDK_CLASSES = [
  'java.lang.Object', 'java.lang.String', 'java.lang.StringBuilder', 'java.lang.StringBuffer',
  'java.lang.Integer', 'java.lang.Long', 'java.lang.Double', 'java.lang.Float',
  'java.lang.Boolean', 'java.lang.Byte', 'java.lang.Short', 'java.lang.Character',
  'java.lang.Class', 'java.lang.ClassLoader', 'java.lang.Thread', 'java.lang.Runnable',
  'java.lang.Runtime', 'java.lang.Process', 'java.lang.ProcessBuilder',
  'java.lang.System', 'java.lang.Math', 'java.lang.StrictMath',
  'java.lang.Throwable', 'java.lang.Exception', 'java.lang.RuntimeException',
  'java.lang.Error', 'java.lang.IllegalArgumentException', 'java.lang.IllegalStateException',
  'java.lang.NullPointerException', 'java.lang.IndexOutOfBoundsException',
  'java.lang.Iterable', 'java.lang.Comparable', 'java.lang.AutoCloseable',
  'java.lang.ref.SoftReference', 'java.lang.ref.WeakReference',
  'java.lang.reflect.Method', 'java.lang.reflect.Constructor', 'java.lang.reflect.Field',
  'java.lang.reflect.Proxy', 'java.lang.reflect.Array',
  'java.util.List', 'java.util.Set', 'java.util.Map', 'java.util.Queue', 'java.util.Deque',
  'java.util.ArrayList', 'java.util.LinkedList', 'java.util.HashMap', 'java.util.LinkedHashMap',
  'java.util.TreeMap', 'java.util.HashSet', 'java.util.LinkedHashSet', 'java.util.TreeSet',
  'java.util.Hashtable', 'java.util.Properties', 'java.util.Vector', 'java.util.Stack',
  'java.util.Collections', 'java.util.Arrays', 'java.util.Iterator', 'java.util.ListIterator',
  'java.util.Enumeration', 'java.util.Optional', 'java.util.OptionalInt', 'java.util.OptionalLong',
  'java.util.Scanner', 'java.util.Random', 'java.util.Date', 'java.util.Calendar',
  'java.util.Base64', 'java.util.regex.Pattern', 'java.util.regex.Matcher',
  'java.util.stream.Stream', 'java.util.stream.IntStream', 'java.util.stream.LongStream',
  'java.util.stream.DoubleStream', 'java.util.stream.Collector', 'java.util.stream.Collectors',
  'java.util.function.Function', 'java.util.function.Consumer', 'java.util.function.Supplier',
  'java.util.function.Predicate', 'java.util.function.BiFunction',
  'java.util.concurrent.Future', 'java.util.concurrent.CompletableFuture',
  'java.util.concurrent.ExecutorService', 'java.util.concurrent.ThreadPoolExecutor',
  'java.util.concurrent.ConcurrentHashMap', 'java.util.concurrent.CopyOnWriteArrayList',
  'java.util.concurrent.atomic.AtomicInteger', 'java.util.concurrent.atomic.AtomicLong',
  'java.util.concurrent.atomic.AtomicReference',
  'java.io.File', 'java.io.InputStream', 'java.io.OutputStream',
  'java.io.Reader', 'java.io.Writer', 'java.io.BufferedReader', 'java.io.BufferedWriter',
  'java.io.InputStreamReader', 'java.io.OutputStreamWriter',
  'java.io.FileInputStream', 'java.io.FileOutputStream',
  'java.io.ObjectInputStream', 'java.io.ObjectOutputStream',
  'java.io.ByteArrayInputStream', 'java.io.ByteArrayOutputStream',
  'java.io.DataInputStream', 'java.io.DataOutputStream',
  'java.io.PrintStream', 'java.io.PrintWriter',
  'java.io.RandomAccessFile', 'java.io.Serializable',
  'java.io.IOException', 'java.io.FileNotFoundException',
  'java.nio.file.Path', 'java.nio.file.Paths', 'java.nio.file.Files',
  'java.nio.file.FileSystem', 'java.nio.file.FileSystems',
  'java.nio.ByteBuffer', 'java.nio.CharBuffer',
  'java.nio.channels.FileChannel', 'java.nio.channels.SocketChannel',
  'java.nio.channels.ServerSocketChannel',
  'java.net.URL', 'java.net.URI', 'java.net.URLConnection',
  'java.net.HttpURLConnection', 'java.net.ServerSocket', 'java.net.Socket',
  'java.net.InetAddress', 'java.net.InetSocketAddress',
  'java.net.DatagramSocket', 'java.net.DatagramPacket',
  'java.net.CookieManager', 'java.net.CookieHandler',
  'java.sql.Connection', 'java.sql.Statement', 'java.sql.PreparedStatement',
  'java.sql.CallableStatement', 'java.sql.ResultSet', 'java.sql.ResultSetMetaData',
  'java.sql.DatabaseMetaData', 'java.sql.Driver', 'java.sql.DriverManager',
  'java.sql.SQLException', 'java.sql.Clob', 'java.sql.Blob',
  'javax.net.ssl.SSLContext', 'javax.net.ssl.SSLSocketFactory',
  'javax.net.ssl.SSLServerSocketFactory', 'javax.net.ssl.HttpsURLConnection',
  'javax.net.ssl.SSLSession', 'javax.net.ssl.TrustManager',
  'javax.net.ssl.KeyManager',
  'javax.script.ScriptEngine', 'javax.script.ScriptEngineManager',
  'javax.script.ScriptContext', 'javax.script.Bindings',
  'java.security.SecureRandom', 'java.security.MessageDigest',
  'java.security.Signature', 'java.security.KeyPairGenerator',
  'java.security.KeyFactory', 'java.security.PrivateKey', 'java.security.PublicKey',
  'java.security.cert.CertificateFactory', 'java.security.cert.X509Certificate',
  'javax.crypto.Cipher', 'javax.crypto.KeyGenerator', 'javax.crypto.SecretKey',
  'javax.crypto.Mac', 'javax.crypto.KeyAgreement',
  'java.lang.invoke.MethodHandles', 'java.lang.invoke.MethodHandle',
  'java.lang.invoke.MethodType', 'java.lang.invoke.CallSite',
  'java.awt.Desktop',
];

// ─── JVM Descriptor parser ──────────────────────────────────────────────
//
// Descriptor format: (ParamTypes)ReturnType
//   B=byte C=char D=double F=float I=int J=long S=short Z=boolean V=void
//   Lpackage/Class; = object type  [ = array prefix
//
// Examples:
//   (Ljava/lang/String;)Ljava/sql/PreparedStatement;
//   (II)Ljava/sql/Statement;
//   ([Ljava/lang/String;)Ljava/lang/Process;

const PRIM_MAP = { B: 'byte', C: 'char', D: 'double', F: 'float', I: 'int', J: 'long', S: 'short', Z: 'boolean' };

function parseDescriptor(desc) {
  const closeParen = desc.indexOf(')');
  if (closeParen < 0) return null;
  return {
    params: parseTypeList(desc.substring(1, closeParen)),
    return: parseSingleType(desc.substring(closeParen + 1)),
  };
}

function parseTypeList(str) {
  const types = [];
  let i = 0;
  while (i < str.length) {
    const r = readOneType(str, i);
    if (!r) break;
    types.push(r.type);
    i = r.nextPos;
  }
  return types;
}

function parseSingleType(str) {
  const r = readOneType(str, 0);
  return r ? r.type : null;
}

function readOneType(str, pos) {
  if (pos >= str.length) return null;
  const c = str[pos];
  if (PRIM_MAP[c]) return { type: PRIM_MAP[c], nextPos: pos + 1 };
  if (c === '[') {
    const inner = readOneType(str, pos + 1);
    return inner ? { type: inner.type + '[]', nextPos: inner.nextPos } : null;
  }
  if (c === 'L') {
    const semi = str.indexOf(';', pos);
    if (semi < 0) return null;
    return { type: str.substring(pos + 1, semi).replace(/\//g, '.').replace(/\$/g, '.'), nextPos: semi + 1 };
  }
  if (c === 'V') return { type: 'void', nextPos: pos + 1 };
  return null;
}

// ─── javap -public -s parser ────────────────────────────────────────────
//
// Input format (javap -public -s):
//
//   Compiled from "Connection.java"
//   public interface java.sql.Connection extends java.sql.Wrapper,java.lang.AutoCloseable {
//     public static final int TRANSACTION_NONE;
//       descriptor: I
//     public abstract java.sql.Statement createStatement() throws java.sql.SQLException;
//       descriptor: ()Ljava/sql/Statement;
//     public abstract java.sql.PreparedStatement prepareStatement(java.lang.String) throws java.sql.SQLException;
//       descriptor: (Ljava/lang/String;)Ljava/sql/PreparedStatement;
//   }
//   Compiled from "Runtime.java"
//   public class java.lang.Runtime {
//     ...

function parseJavapPublicS(output) {
  const classes = {};
  let currentClass = null;
  let currentMethod = null;
  let currentFieldName = null;  // track last field for descriptor
  let inMethod = false;

  for (const line of output.split('\n')) {
    const trimmed = line.trim();

    // ── Class declaration ──
    // "public interface java.sql.Connection extends java.sql.Wrapper,java.lang.AutoCloseable {"
    // "public final class java.lang.String implements ... {"
    // "public class java.lang.Runtime {"
    const classMatch = trimmed.match(
      /^public\s+(?:(?:final|abstract)\s+)?(?:class|interface|enum)\s+([\w.$]+)(?:\s*<[^>]*>)?(?:\s+extends\s+([^{]+?))?(?:\s+implements\s+([^{]+?))?\s*\{$/
    );
    if (classMatch) {
      currentClass = {
        name: classMatch[1].replace(/\$/g, '.'),
        superClass: null,
        interfaces: [],
        methods: Object.create(null),  // no prototype — avoids toString/hasOwnProperty collisions
        fields: Object.create(null),
      };

      // Parse extends — may contain generics, multiple for interfaces
      // e.g. "java.sql.Wrapper,java.lang.AutoCloseable" (interface extends)
      // e.g. "java.lang.Number" (class extends)
      // Parse extends — strip generics BEFORE splitting on commas
      // "extends java.util.AbstractMap<K, V>" → "extends java.util.AbstractMap"
      if (classMatch[2]) {
        const stripped = classMatch[2].replace(/<[^>]*>/g, '');
        const extList = stripped.split(',').map(s => s.trim().replace(/\$/g, '.')).filter(Boolean);
        if (extList.length > 0) {
          // For classes: first is superclass. For interfaces: all are parent interfaces.
          currentClass.superClass = extList[0];
          if (extList.length > 1) {
            currentClass.interfaces.push(...extList.slice(1));
          }
        }
      }

      // Parse implements
      // Parse implements — strip generics BEFORE splitting
      if (classMatch[3]) {
        const stripped = classMatch[3].replace(/<[^>]*>/g, '');
        currentClass.interfaces.push(
          ...stripped.split(',').map(s => s.trim().replace(/\$/g, '.')).filter(Boolean)
        );
      }

      classes[currentClass.name] = currentClass;
      inMethod = false;
      currentMethod = null;
      currentFieldName = null;
      continue;
    }

    if (!currentClass) continue;

    // ── Method declaration ──
    // "public abstract java.sql.Statement createStatement() throws java.sql.SQLException;"
    // "public static <T> java.util.Optional<T> empty();"
    // "public void close() throws java.sql.SQLException;"
    const methodMatch = trimmed.match(
      /^public\s+(?:(?:static|abstract|final|synchronized|native|default|strictfp)\s+)*(?:<[^>]+>\s+)?(\S+)\s+(\w+)\s*\(([^)]*)\)(?:\s+throws\s+(.+?))?\s*;?$/
    );
    if (methodMatch) {
      const returnTypeRaw = methodMatch[1];
      const methodName = methodMatch[2];
      const throwsRaw = methodMatch[4];

      // Parse modifiers
      const modifierPart = trimmed.substring(0, trimmed.indexOf(returnTypeRaw));
      const modifiers = [];
      for (const m of ['static', 'abstract', 'final', 'synchronized', 'native', 'default']) {
        if (modifierPart.includes(' ' + m + ' ')) modifiers.push(m);
      }

      currentMethod = {
        descriptor: null,
        returnType: null,
        paramTypes: [],
        modifiers,
        throws: throwsRaw ? throwsRaw.split(',').map(s => s.trim().replace(/\$/g, '.')) : [],
        deprecated: false,
      };

      if (!currentClass.methods[methodName]) {
        currentClass.methods[methodName] = [];
      }
      currentClass.methods[methodName].push(currentMethod);
      inMethod = true;
      currentFieldName = null;
      continue;
    }

    // ── Field declaration ──
    // "public static final java.io.InputStream in;"
    // "public static final int TRANSACTION_NONE;"
    const fieldMatch = trimmed.match(
      /^public\s+(?:(?:static|final|volatile|transient)\s+)+(\S+)\s+(\w+)\s*;?$/
    );
    if (fieldMatch) {
      const fieldTypeRaw = fieldMatch[1];
      const fieldName = fieldMatch[2];

      const modifierPart = trimmed.substring(0, trimmed.indexOf(fieldTypeRaw));
      const modifiers = [];
      for (const m of ['static', 'final', 'volatile', 'transient']) {
        if (modifierPart.includes(' ' + m + ' ')) modifiers.push(m);
      }

      currentClass.fields[fieldName] = { type: null, modifiers };
      inMethod = false;
      currentMethod = null;
      currentFieldName = fieldName;
      continue;
    }

    // ── Descriptor line ──
    // "descriptor: ()Ljava/sql/Statement;"
    // "descriptor: I"
    const descMatch = trimmed.match(/^descriptor:\s+(\S+)$/);
    if (descMatch) {
      const desc = descMatch[1];

      if (inMethod && currentMethod) {
        currentMethod.descriptor = desc;
        const parsed = parseDescriptor(desc);
        if (parsed) {
          currentMethod.returnType = parsed.return;
          currentMethod.paramTypes = parsed.params;
        }
      } else if (currentFieldName && currentClass.fields[currentFieldName]) {
        // Field descriptor
        const parsed = parseSingleType(desc);
        currentClass.fields[currentFieldName].type = parsed;
      }
      continue;
    }

    // ── Deprecated marker ──
    if (trimmed === 'Deprecated: true' && inMethod && currentMethod) {
      currentMethod.deprecated = true;
      continue;
    }

    // ── End of class ──
    if (trimmed === '}') {
      currentClass = null;
      inMethod = false;
      currentMethod = null;
      currentFieldName = null;
    }
  }

  return classes;
}

// ─── Batch runner ───────────────────────────────────────────────────────

function extractBatch(classNames, classpath) {
  const classes = {};
  const CHUNK_SIZE = 2000;
  for (let i = 0; i < classNames.length; i += CHUNK_SIZE) {
    const chunk = classNames.slice(i, i + CHUNK_SIZE);
    try {
      const cmd = classpath
        ? `javap -public -s -classpath "${classpath}" ${chunk.join(' ')} 2>/dev/null`
        : `javap -public -s ${chunk.join(' ')} 2>/dev/null`;
      const output = execSync(cmd, { encoding: 'utf-8', timeout: 60000, maxBuffer: 50 * 1024 * 1024 });
      const parsed = parseJavapPublicS(output);
      Object.assign(classes, parsed);
    } catch (e) {
      // Some classes may not be found or javap may fail — skip
    }
  }
  return classes;
}

// ─── Maven discovery ────────────────────────────────────────────────────

function discoverMavenClasses(repoPath) {
  const classes = [];
  const classpathParts = [];
  const jars = [];
  try {
    const out = execSync(
      `find "${repoPath}" -name "*.jar" -not -name "*sources*" -not -name "*javadoc*" -type f 2>/dev/null`,
      { encoding: 'utf-8', timeout: 10000 }
    );
    jars.push(...out.trim().split('\n').filter(Boolean));
  } catch { /* no maven repo */ }

  for (const jar of jars) {
    classpathParts.push(jar);
    try {
      const listing = execSync(`jar tf "${jar}" 2>/dev/null`, { encoding: 'utf-8', timeout: 5000 });
      for (const line of listing.split('\n')) {
        const m = line.trim().match(/^([\w/$]+)\.class$/);
        if (m && !m[1].includes('$')) {
          classes.push(m[1].replace(/\//g, '.'));
        }
      }
    } catch { /* skip */ }
  }
  return { classes, classpath: classpathParts.join(':') };
}

// ─── Stats ──────────────────────────────────────────────────────────────

function computeStats(classes) {
  let methodCount = 0;
  let overloadCount = 0;
  let fieldCount = 0;
  for (const cls of Object.values(classes)) {
    for (const overloads of Object.values(cls.methods)) {
      methodCount += overloads.length;
      if (overloads.length > 1) overloadCount += overloads.length - 1;
    }
    fieldCount += Object.keys(cls.fields).length;
  }
  return { classCount: Object.keys(classes).length, methodCount, overloadCount, fieldCount };
}

// ─── SQLite writer ─────────────────────────────────────────────────────

function writeSQLite(classes, dbPath) {
  // Use better-sqlite3 if available, else fall back to node:sqlite
  let Database;
  try {
    Database = require('better-sqlite3');
  } catch {
    try {
      Database = require('node:sqlite').DatabaseSync;
    } catch {
      console.log('  SQLite: no driver available, skipping .db output');
      return;
    }
  }

  // Remove existing file
  try { fs.unlinkSync(dbPath); } catch { /* doesn't exist */ }

  const db = new Database(dbPath);
  db.exec(`
    CREATE TABLE classes (name TEXT PRIMARY KEY, super_class TEXT, interfaces TEXT);
    CREATE TABLE methods (class_name TEXT, method_name TEXT, descriptor TEXT, return_type TEXT, param_types TEXT, modifiers TEXT, throws_list TEXT, deprecated INTEGER, ordinal INTEGER);
    CREATE INDEX idx_methods ON methods(class_name, method_name);
    CREATE TABLE fields (class_name TEXT, field_name TEXT, type TEXT, modifiers TEXT);
    CREATE INDEX idx_fields ON fields(class_name, field_name);
  `);

  const insertClass = db.prepare('INSERT INTO classes VALUES (?, ?, ?)');
  const insertMethod = db.prepare('INSERT INTO methods VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)');
  const insertField = db.prepare('INSERT INTO fields VALUES (?, ?, ?, ?)');

  // Wrap in transaction for speed
  db.exec('BEGIN TRANSACTION');
  for (const [name, cls] of Object.entries(classes)) {
    insertClass.run(name, cls.superClass || '', JSON.stringify(cls.interfaces));

    if (cls.methods && typeof cls.methods === 'object') {
      for (const [mName, overloads] of Object.entries(cls.methods)) {
        if (!Array.isArray(overloads)) continue;
        for (let i = 0; i < overloads.length; i++) {
          const m = overloads[i];
          insertMethod.run(
            name, mName,
            m.descriptor || '', m.returnType || '',
            JSON.stringify(m.paramTypes), JSON.stringify(m.modifiers),
            JSON.stringify(m.throws), m.deprecated ? 1 : 0, i
          );
        }
      }
    }

    if (cls.fields && typeof cls.fields === 'object') {
      for (const [fName, f] of Object.entries(cls.fields)) {
        insertField.run(name, fName, f.type || '', JSON.stringify(f.modifiers));
      }
    }
  }
  db.exec('COMMIT');
  db.close();
}

// ─── Compact JSON serializer ────────────────────────────────────────────
//
// Converts full class entries to compact format:
//   { superClass, interfaces, methods: { name: [{ descriptor, returnType, paramTypes, modifiers, throws, deprecated }] } }
//   → { s, i, m: { name: [[desc, retType, params, mods, throws, deprecated], ...] } }
//
// Result: ~505 KB vs ~1618 KB (3.2x compression), JSON.parse ~3ms vs ~6ms

function toCompact(classes) {
  const compact = {};
  for (const [name, cls] of Object.entries(classes)) {
    compact[name] = {
      s: cls.superClass || '',       // superClass → s
      i: cls.interfaces || [],       // interfaces → i
      m: Object.create(null),        // methods → m (no prototype!)
      f: Object.create(null),        // fields → f
    };
    if (cls.methods && typeof cls.methods === 'object') {
      for (const [mName, overloads] of Object.entries(cls.methods)) {
        if (!Array.isArray(overloads)) continue;
        compact[name].m[mName] = overloads.map(m => [
          m.descriptor || '',         // [0] descriptor
          m.returnType || '',         // [1] returnType
          m.paramTypes || [],         // [2] paramTypes
          m.modifiers || [],          // [3] modifiers
          m.throws || [],             // [4] throws
          m.deprecated ? 1 : 0,       // [5] deprecated
        ]);
      }
    }
    if (cls.fields && typeof cls.fields === 'object') {
      for (const [fName, f] of Object.entries(cls.fields)) {
        compact[name].f[fName] = [f.type || '', f.modifiers || []];
      }
    }
  }
  return compact;
}

// ─── Main ───────────────────────────────────────────────────────────────

function main() {
  const args = process.argv.slice(2);
  let outputPath = path.join(__dirname, '..', 'src', 'analyzer', 'jdk-api-index.json');
  let includeMaven = false;
  let mavenRepoPath = path.join(process.env.HOME || '/root', '.m2', 'repository');

  for (let i = 0; i < args.length; i++) {
    if (args[i] === '-o' && args[i + 1]) { outputPath = args[++i]; }
    else if (args[i] === '--maven') { includeMaven = true; }
    else if (args[i] === '-p' && args[i + 1]) { mavenRepoPath = args[++i]; }
  }

  const startTime = Date.now();

  console.log(`Scanning ${JDK_CLASSES.length} JDK classes (javap -public -s)...`);
  const jdkClasses = extractBatch(JDK_CLASSES, null);
  const jdkStats = computeStats(jdkClasses);
  console.log(`  ${jdkStats.classCount} classes, ${jdkStats.methodCount} methods (${jdkStats.overloadCount} overloads), ${jdkStats.fieldCount} fields`);

  let mavenClasses = {};
  if (includeMaven) {
    console.log(`\nScanning Maven local repository: ${mavenRepoPath}`);
    const { classes, classpath } = discoverMavenClasses(mavenRepoPath);
    console.log(`  Found ${classes.length} classes in ${classpath.split(':').length} jars`);
    if (classes.length > 0) {
      mavenClasses = extractBatch(classes, classpath);
      const mvnStats = computeStats(mavenClasses);
      console.log(`  ${mvnStats.classCount} classes, ${mvnStats.methodCount} methods, ${mvnStats.fieldCount} fields`);
    }
  }

  const allClasses = { ...jdkClasses, ...mavenClasses };
  const stats = computeStats(allClasses);

  fs.mkdirSync(path.dirname(outputPath), { recursive: true });
  fs.writeFileSync(outputPath, JSON.stringify(toCompact(allClasses)));

  // Also write SQLite database for fast cold-start lookups
  const dbPath = outputPath.replace(/\.json$/, '.db');
  writeSQLite(allClasses, dbPath);

  const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
  const jsonKB = (fs.statSync(outputPath).size / 1024).toFixed(1);
  const dbKB = fs.existsSync(dbPath) ? (fs.statSync(dbPath).size / 1024).toFixed(1) : '0';
  console.log(`\nDone in ${elapsed}s!`);
  console.log(`  ${stats.classCount} classes, ${stats.methodCount} methods (${stats.overloadCount} overloads), ${stats.fieldCount} fields`);
  console.log(`  JSON: ${outputPath} (${jsonKB} KB)`);
  console.log(`  SQLite: ${dbPath} (${dbKB} KB)`);

  // Sample output
  console.log('\n=== Sample: java.sql.Connection ===');
  const conn = allClasses['java.sql.Connection'];
  if (conn) {
    console.log(`  extends: ${conn.superClass || 'none'}`);
    console.log(`  implements: ${conn.interfaces.join(', ')}`);
    for (const name of ['createStatement', 'prepareStatement']) {
      const overloads = conn.methods[name] || [];
      for (const m of overloads) {
        console.log(`  ${m.modifiers.join(' ')} ${m.returnType || '?'} ${name}(${m.paramTypes.join(', ')})${m.throws.length ? ' throws ' + m.throws.join(', ') : ''}`);
      }
    }
  }

  console.log('\n=== Sample: java.lang.Runtime ===');
  const rt = allClasses['java.lang.Runtime'];
  if (rt) {
    console.log(`  extends: ${rt.superClass || 'none'}`);
    for (const m of (rt.methods.exec || [])) {
      console.log(`  ${m.returnType} exec(${m.paramTypes.join(', ')})${m.deprecated ? ' @Deprecated' : ''}`);
    }
  }

  console.log('\n=== Sample: java.sql.PreparedStatement inheritance ===');
  const ps = allClasses['java.sql.PreparedStatement'];
  if (ps) {
    console.log(`  extends: ${ps.superClass || 'none'}`);
    console.log(`  implements: ${ps.interfaces.join(', ')}`);
    const stmt = allClasses['java.sql.Statement'];
    if (stmt) console.log(`  Statement.executeQuery exists: ${!!stmt.methods.executeQuery}`);
  }
}

main();
