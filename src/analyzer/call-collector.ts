/**
 * Call Collector - reads CodeGraph's SQLite database directly
 *
 * Collects all Java call edges (resolved + unresolved) and builds
 * enhanced method signatures using import mappings.
 */

import { DatabaseSync } from 'node:sqlite';
import * as fs from 'fs';
import * as path from 'path';
import { CallSite, MethodSignature } from '../types';
import { parseParameterTypes, enhanceTypeName, buildFullQualifiedName } from '../utils/java-utils';

interface ResolvedEdgeRow {
  edge_id: number;
  source_id: string;
  target_id: string;
  line: number | null;
  col: number | null;
  caller_name: string;
  caller_kind: string;
  caller_qname: string;
  caller_file: string;
  callee_name: string;
  callee_kind: string;
  callee_qname: string;
  callee_sig: string | null;
  callee_file: string;
}

interface UnresolvedRow {
  from_node_id: string;
  reference_name: string;
  line: number;
  col: number;
  file_path: string;
  caller_name: string;
  caller_qname: string;
}

export class CallCollector {
  private db: DatabaseSync;
  /** filePath → (shortName → fullQualifiedName) */
  private importCache: Map<string, Map<string, string>> = new Map();
  private projectRoot: string;

  constructor(codegraphDbPath: string, projectRoot: string) {
    this.db = new DatabaseSync(codegraphDbPath, { readOnly: true });
    this.projectRoot = projectRoot;
    this.loadImports();
  }

  /**
   * Load all Java import nodes to build shortName→fullName mapping per file
   */
  private loadImports(): void {
    try {
      const stmt = this.db.prepare(`
        SELECT name, qualified_name, file_path
        FROM nodes
        WHERE kind = 'import' AND language = 'java'
      `);
      for (const row of stmt.all() as Array<{ name: string; qualified_name: string; file_path: string }>) {
        if (!row.name || !row.qualified_name || !row.file_path) continue;

        const fullName = this.extractImportClass(row.qualified_name);
        if (!fullName) continue;

        if (!this.importCache.has(row.file_path)) {
          this.importCache.set(row.file_path, new Map());
        }
        this.importCache.get(row.file_path)!.set(row.name, fullName);
      }
    } catch (e) {
      console.error('Warning: Failed to load imports:', (e as Error).message);
    }
  }

  /**
   * Extract full class name from import's qualified_name
   * "import com.example.service.UserService" → "com.example.service.UserService"
   */
  private extractImportClass(qualifiedName: string): string | null {
    let cleaned = qualifiedName.replace(/^import\s+/, '');
    cleaned = cleaned.replace(/^static\s+/, '');
    if (cleaned.endsWith('.*')) return null;
    cleaned = cleaned.replace(/;$/, '').trim();
    return cleaned || null;
  }

  /**
   * Collect all Java call sites with enhanced signatures
   */
  collectCallSites(): CallSite[] {
    const sites: CallSite[] = [];

    // 1. Resolved call edges
    try {
      const stmt = this.db.prepare(`
        SELECT
          e.id as edge_id, e.source as source_id, e.target as target_id,
          e.line, e.col,
          caller.name as caller_name, caller.kind as caller_kind,
          caller.qualified_name as caller_qname, caller.file_path as caller_file,
          callee.name as callee_name, callee.kind as callee_kind,
          callee.qualified_name as callee_qname, callee.signature as callee_sig,
          callee.file_path as callee_file
        FROM edges e
        JOIN nodes caller ON e.source = caller.id
        JOIN nodes callee ON e.target = callee.id
        WHERE e.kind = 'calls'
          AND caller.language = 'java'
          AND callee.language = 'java'
        ORDER BY caller.file_path, e.line
      `);

      for (const rawRow of stmt.all()) {
        const row = rawRow as unknown as ResolvedEdgeRow;
        const calleeInfo = this.extractPackageClassFromQName(row.callee_qname, row.callee_file);
        const callerInfo = this.extractClassFromQName(row.caller_qname);
        const imports = this.importCache.get(row.callee_file) ?? new Map();
        const paramTypes = parseParameterTypes(row.callee_sig).map(t => enhanceTypeName(t, imports));

        const line = row.line ?? 0;
        const sourceLine = this.readSourceLine(row.caller_file, line);

        sites.push({
          callerFile: row.caller_file,
          callerClass: callerInfo,
          callerMethod: row.caller_kind === 'method' ? row.caller_name : '',
          callerLine: line,
          calleeRawName: row.callee_name,
          calleeReceiverName: '',
          calleeMethodName: row.callee_name,
          calleeResolved: true,
          calleeNode: {
            qualifiedName: row.callee_qname,
            signature: row.callee_sig ?? '',
            filePath: row.callee_file,
          },
          fullSignature: {
            packageName: calleeInfo.packageName,
            className: calleeInfo.className,
            methodName: row.callee_name,
            parameterTypes: paramTypes,
            fullQualifiedName: buildFullQualifiedName(
              calleeInfo.packageName, calleeInfo.className, row.callee_name, paramTypes
            ),
            sourceLine,
          },
        });
      }
    } catch (e) {
      console.error('Warning: Failed to collect resolved calls:', (e as Error).message);
    }

    // 2. Unresolved call references
    try {
      const stmt = this.db.prepare(`
        SELECT
          ur.from_node_id, ur.reference_name, ur.line, ur.col,
          ur.file_path, n.name as caller_name, n.qualified_name as caller_qname
        FROM unresolved_refs ur
        JOIN nodes n ON ur.from_node_id = n.id
        WHERE ur.reference_kind = 'calls'
          AND ur.language = 'java'
        ORDER BY ur.file_path, ur.line
      `);

      for (const rawRow of stmt.all()) {
        const row = rawRow as unknown as UnresolvedRow;
        const { receiver, method } = this.parseRefName(row.reference_name);
        const callerClass = this.extractClassFromQName(row.caller_qname);
        const line = row.line;

        // Try to resolve receiver type via imports
        let packageName = '';
        let className = receiver;
        const imports = this.importCache.get(row.file_path) ?? new Map();
        if (receiver && imports.has(receiver)) {
          const fullImport = imports.get(receiver)!;
          const lastDot = fullImport.lastIndexOf('.');
          if (lastDot > 0) {
            packageName = fullImport.substring(0, lastDot);
            className = fullImport.substring(lastDot + 1);
          }
        } else if (!receiver || receiver === 'this' || receiver === 'super') {
          // Self-call: use caller's package/class
          const callerInfo = this.extractPackageClassFromQName(row.caller_qname, row.file_path);
          packageName = callerInfo.packageName;
          className = callerInfo.className;
        }

        const sourceLine = this.readSourceLine(row.file_path, line);

        sites.push({
          callerFile: row.file_path,
          callerClass,
          callerMethod: row.caller_name,
          callerLine: line,
          calleeRawName: row.reference_name,
          calleeReceiverName: receiver,
          calleeMethodName: method,
          calleeResolved: false,
          fullSignature: {
            packageName,
            className,
            methodName: method,
            parameterTypes: [],
            fullQualifiedName: buildFullQualifiedName(packageName, className, method, []),
            sourceLine,
          },
        });
      }
    } catch (e) {
      console.error('Warning: Failed to collect unresolved calls:', (e as Error).message);
    }

    return sites;
  }

  /**
   * Parse reference name into receiver and method
   * "userService.findByUsername" → { receiver: "userService", method: "findByUsername" }
   */
  private parseRefName(refName: string): { receiver: string; method: string } {
    const dot = refName.lastIndexOf('.');
    if (dot > 0) {
      return { receiver: refName.substring(0, dot), method: refName.substring(dot + 1) };
    }
    return { receiver: '', method: refName };
  }

  /**
   * Extract class name from CodeGraph qualified_name
   * Format: "filePath::ClassName" or "filePath::ClassName::methodName"
   */
  private extractClassFromQName(qname: string): string {
    const parts = qname.split('::');
    // "src/main/java/.../Foo.java::Foo::bar" → "Foo"
    if (parts.length >= 2) return parts[parts.length - 2]!;
    return parts[0] ?? '';
  }

  /**
   * Extract package name and class name from qualified_name + file_path
   */
  private extractPackageClassFromQName(qname: string, filePath: string): {
    packageName: string;
    className: string;
  } {
    // Extract class name from qualified_name
    const parts = qname.split('::');
    const className = parts.length >= 2 ? parts[parts.length - 2]! : (parts[0] ?? '');

    // Extract package from file path
    // "src/main/java/com/example/service/UserService.java" → "com.example.service"
    const withoutExt = filePath.replace(/\.java$/, '');
    const javaRootPatterns = [
      /src\/main\/java\/(.+)/,
      /src\/test\/java\/(.+)/,
      /src\/(.+)/,
    ];

    for (const pattern of javaRootPatterns) {
      const match = withoutExt.match(pattern);
      if (match && match[1]) {
        const pathParts = match[1].split('/');
        if (pathParts.length > 1) {
          pathParts.pop(); // remove class name
          return { packageName: pathParts.join('.'), className };
        }
      }
    }

    return { packageName: '', className };
  }

  private readSourceLine(filePath: string, line: number): string {
    try {
      const fullPath = path.join(this.projectRoot, filePath);
      const content = fs.readFileSync(fullPath, 'utf-8');
      const lines = content.split('\n');
      const idx = line - 1;
      if (idx >= 0 && idx < lines.length) return lines[idx]!.trim();
    } catch { /* ignore */ }
    return '';
  }

  close(): void {
    this.db.close();
  }
}
