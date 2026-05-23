/**
 * CodeGraph Traverser — Cross-file graph traversal via CodeGraph's SQLite DB
 *
 * Provides cross-file analysis capabilities that JavaLint's single-file
 * tree-sitter scanner cannot achieve alone:
 *
 *   1. Multi-hop call chain traversal (who calls whom, across files)
 *   2. Caller back-tracing (who calls this dangerous method?)
 *   3. Method-to-method signature enrichment from resolved edges
 *   4. Class hierarchy tracking (extends/implements)
 *
 * Reads CodeGraph's SQLite DB directly — no dependency on CodeGraph's
 * TypeScript runtime. Works with the same DB that CallCollector uses.
 */

import { DatabaseSync } from 'node:sqlite';
import * as fs from 'fs';
import * as path from 'path';

// ─── Graph types ──────────────────────────────────────────────────────

/** A node from CodeGraph's knowledge graph */
export interface CGNode {
  id: string;
  kind: string;
  name: string;
  qualifiedName: string;
  filePath: string;
  language: string;
  startLine: number;
  endLine: number;
  signature?: string;
  visibility?: string;
  isStatic?: boolean;
  isExported?: boolean;
}

/** An edge from CodeGraph's knowledge graph */
export interface CGEdge {
  source: string;
  target: string;
  kind: string;
  line?: number;
  column?: number;
  metadata?: Record<string, any>;
}

/** A call chain path from source to sink */
export interface CallChainPath {
  /** The nodes along the path, in order from source to sink */
  nodes: CGNode[];
  /** The edges connecting the nodes */
  edges: CGEdge[];
  /** Total depth of the chain */
  depth: number;
}

/** Summary of callers for a given method */
export interface CallerInfo {
  /** The method node that calls this method */
  caller: CGNode;
  /** The edge connecting caller → callee */
  edge: CGEdge;
  /** Recursed callers (callers of the caller) */
  transitiveCallers: CallerInfo[];
}

export class CodeGraphTraverser {
  private db: DatabaseSync;
  private projectRoot: string;

  // Caches for performance
  private nodeCache = new Map<string, CGNode>();
  private edgeCacheLoaded = false;
  private outgoingEdges = new Map<string, CGEdge[]>();
  private incomingEdges = new Map<string, CGEdge[]>();

  constructor(codegraphDbPath: string, projectRoot: string) {
    this.db = new DatabaseSync(codegraphDbPath, { readOnly: true });
    this.projectRoot = projectRoot;
  }

  // ─── Node queries ──────────────────────────────────────────────────

  /** Get a node by its ID */
  getNode(id: string): CGNode | null {
    if (this.nodeCache.has(id)) return this.nodeCache.get(id)!;

    const stmt = this.db.prepare(
      `SELECT id, kind, name, qualified_name, file_path, language,
              start_line, end_line, signature, visibility,
              is_static, is_exported
       FROM nodes WHERE id = ?`
    );
    const row = stmt.get(id) as any;
    if (!row) return null;

    const node = this.rowToNode(row);
    this.nodeCache.set(id, node);
    return node;
  }

  /** Find method nodes by name (case-insensitive) */
  findMethodNodes(name: string): CGNode[] {
    const stmt = this.db.prepare(
      `SELECT id, kind, name, qualified_name, file_path, language,
              start_line, end_line, signature, visibility,
              is_static, is_exported
       FROM nodes WHERE kind = 'method' AND lower(name) = ?`
    );
    return (stmt.all(name.toLowerCase()) as any[]).map(r => this.rowToNode(r));
  }

  /** Find class nodes by name */
  findClassNodes(name: string): CGNode[] {
    const stmt = this.db.prepare(
      `SELECT id, kind, name, qualified_name, file_path, language,
              start_line, end_line, signature, visibility,
              is_static, is_exported
       FROM nodes WHERE kind = 'class' AND name = ?`
    );
    return (stmt.all(name) as any[]).map(r => this.rowToNode(r));
  }

  /** Get all method nodes in a specific file */
  getMethodsInFile(filePath: string): CGNode[] {
    const stmt = this.db.prepare(
      `SELECT id, kind, name, qualified_name, file_path, language,
              start_line, end_line, signature, visibility,
              is_static, is_exported
       FROM nodes WHERE kind = 'method' AND file_path = ?`
    );
    return (stmt.all(filePath) as any[]).map(r => this.rowToNode(r));
  }

  /** Get all Java method nodes */
  getAllJavaMethods(): CGNode[] {
    const stmt = this.db.prepare(
      `SELECT id, kind, name, qualified_name, file_path, language,
              start_line, end_line, signature, visibility,
              is_static, is_exported
       FROM nodes WHERE kind = 'method' AND language = 'java'`
    );
    return (stmt.all() as any[]).map(r => this.rowToNode(r));
  }

  /** Get all Java class nodes */
  getAllJavaClasses(): CGNode[] {
    const stmt = this.db.prepare(
      `SELECT id, kind, name, qualified_name, file_path, language,
              start_line, end_line, signature, visibility,
              is_static, is_exported
       FROM nodes WHERE kind = 'class' AND language = 'java'`
    );
    return (stmt.all() as any[]).map(r => this.rowToNode(r));
  }

  // ─── Edge queries ──────────────────────────────────────────────────

  /** Ensure edge cache is loaded */
  private ensureEdgeCache(): void {
    if (this.edgeCacheLoaded) return;
    this.edgeCacheLoaded = true;

    const stmt = this.db.prepare(
      `SELECT source, target, kind, line, col, metadata FROM edges
       WHERE kind IN ('calls', 'references', 'imports', 'instantiates',
                      'extends', 'implements', 'contains')`
    );
    for (const row of stmt.all() as any[]) {
      const edge: CGEdge = {
        source: row.source,
        target: row.target,
        kind: row.kind,
        line: row.line ?? undefined,
        column: row.col ?? undefined,
        metadata: row.metadata ? JSON.parse(row.metadata) : undefined,
      };

      if (!this.outgoingEdges.has(edge.source)) {
        this.outgoingEdges.set(edge.source, []);
      }
      this.outgoingEdges.get(edge.source)!.push(edge);

      if (!this.incomingEdges.has(edge.target)) {
        this.incomingEdges.set(edge.target, []);
      }
      this.incomingEdges.get(edge.target)!.push(edge);
    }
  }

  /** Get outgoing edges from a node, optionally filtered by kind */
  getOutgoingEdges(nodeId: string, kinds?: string[]): CGEdge[] {
    this.ensureEdgeCache();
    const edges = this.outgoingEdges.get(nodeId) ?? [];
    if (!kinds || kinds.length === 0) return edges;
    return edges.filter(e => kinds.includes(e.kind));
  }

  /** Get incoming edges to a node, optionally filtered by kind */
  getIncomingEdges(nodeId: string, kinds?: string[]): CGEdge[] {
    this.ensureEdgeCache();
    const edges = this.incomingEdges.get(nodeId) ?? [];
    if (!kinds || kinds.length === 0) return edges;
    return edges.filter(e => kinds.includes(e.kind));
  }

  // ─── Traversal: callers (who calls this method?) ──────────────────

  /**
   * Find all callers of a method, with optional recursive depth.
   *
   * Example: findByUsername is called by handleGetUser.
   *   getCallers("findByUsername", 1) → [handleGetUser]
   *   getCallers("findByUsername", 2) → [handleGetUser, ...callers of handleGetUser]
   */
  getCallers(nodeId: string, maxDepth: number = 1): CallerInfo[] {
    this.ensureEdgeCache();
    return this.getCallersRecursive(nodeId, maxDepth, 0, new Set<string>());
  }

  private getCallersRecursive(
    nodeId: string,
    maxDepth: number,
    currentDepth: number,
    visited: Set<string>,
  ): CallerInfo[] {
    if (currentDepth >= maxDepth || visited.has(nodeId)) return [];
    visited.add(nodeId);

    const incomingCallEdges = this.getIncomingEdges(nodeId, ['calls']);
    const callers: CallerInfo[] = [];

    for (const edge of incomingCallEdges) {
      const callerNode = this.getNode(edge.source);
      if (!callerNode) continue;

      callers.push({
        caller: callerNode,
        edge,
        transitiveCallers: currentDepth + 1 < maxDepth
          ? this.getCallersRecursive(edge.source, maxDepth, currentDepth + 1, visited)
          : [],
      });
    }

    return callers;
  }

  // ─── Traversal: callees (what does this method call?) ──────────────

  /**
   * Find all methods called by a method, with optional recursive depth.
   *
   * Example: handleGetUser calls findByUsername.
   *   getCallees("handleGetUser", 1) → [findByUsername]
   */
  getCallees(nodeId: string, maxDepth: number = 1): CallerInfo[] {
    this.ensureEdgeCache();
    return this.getCalleesRecursive(nodeId, maxDepth, 0, new Set<string>());
  }

  private getCalleesRecursive(
    nodeId: string,
    maxDepth: number,
    currentDepth: number,
    visited: Set<string>,
  ): CallerInfo[] {
    if (currentDepth >= maxDepth || visited.has(nodeId)) return [];
    visited.add(nodeId);

    const outgoingCallEdges = this.getOutgoingEdges(nodeId, ['calls']);
    const callees: CallerInfo[] = [];

    for (const edge of outgoingCallEdges) {
      const calleeNode = this.getNode(edge.target);
      if (!calleeNode) continue;

      callees.push({
        caller: calleeNode,  // "caller" field = the target node in this context
        edge,
        transitiveCallers: currentDepth + 1 < maxDepth
          ? this.getCalleesRecursive(edge.target, maxDepth, currentDepth + 1, visited)
          : [],
      });
    }

    return callees;
  }

  // ─── Call chain path finding ────────────────────────────────────────

  /**
   * Find a call chain path from sourceNode to targetNode.
   *
   * Uses BFS to find the shortest path through 'calls' edges.
   * Returns null if no path exists within maxDepth hops.
   */
  findCallPath(sourceNodeId: string, targetNodeId: string, maxDepth: number = 5): CallChainPath | null {
    this.ensureEdgeCache();

    if (sourceNodeId === targetNodeId) {
      const node = this.getNode(sourceNodeId);
      return node ? { nodes: [node], edges: [], depth: 0 } : null;
    }

    // BFS
    const visited = new Set<string>();
    const queue: Array<{ nodeId: string; path: Array<{ node: CGNode; edge: CGEdge | null }> }> = [];

    const sourceNode = this.getNode(sourceNodeId);
    if (!sourceNode) return null;

    queue.push({ nodeId: sourceNodeId, path: [{ node: sourceNode, edge: null }] });
    visited.add(sourceNodeId);

    while (queue.length > 0) {
      const { nodeId, path } = queue.shift()!;

      if (path.length - 1 >= maxDepth) continue;

      const callEdges = this.getOutgoingEdges(nodeId, ['calls']);

      for (const edge of callEdges) {
        if (visited.has(edge.target)) continue;
        visited.add(edge.target);

        const targetNode = this.getNode(edge.target);
        if (!targetNode) continue;

        const newPath = [...path, { node: targetNode, edge }];

        if (edge.target === targetNodeId) {
          return {
            nodes: newPath.map(p => p.node),
            edges: newPath.slice(1).map(p => p.edge!),
            depth: newPath.length - 1,
          };
        }

        queue.push({ nodeId: edge.target, path: newPath });
      }
    }

    return null;  // No path found
  }

  // ─── Method enrichment via CodeGraph ───────────────────────────────

  /**
   * Find the CodeGraph node ID for a method by matching (file, methodName, line).
   * Used to link JavaLint's CallSites to CodeGraph's graph nodes.
   */
  findMethodNodeId(filePath: string, methodName: string, line?: number): string | null {
    const stmt = this.db.prepare(
      `SELECT id FROM nodes
       WHERE kind = 'method' AND file_path = ? AND name = ?
       ${line ? 'AND start_line = ?' : ''}
       LIMIT 1`
    );
    const args = line ? [filePath, methodName, line] : [filePath, methodName];
    const row = stmt.get(...args) as any;
    return row?.id ?? null;
  }

  /**
   * Get the signature of a method node from CodeGraph.
   * Returns something like "User (String username)".
   */
  getMethodSignature(nodeId: string): string | null {
    const node = this.getNode(nodeId);
    return node?.signature ?? null;
  }

  /**
   * Get all methods that reference a given class (cross-file type usage).
   * Uses 'references' and 'instantiates' edges.
   */
  getClassReferencers(classNodeId: string): Array<{ node: CGNode; edge: CGEdge }> {
    this.ensureEdgeCache();
    const refEdges = this.getIncomingEdges(classNodeId, ['references', 'instantiates']);
    const results: Array<{ node: CGNode; edge: CGEdge }> = [];

    for (const edge of refEdges) {
      const node = this.getNode(edge.source);
      if (node) results.push({ node, edge });
    }

    return results;
  }

  // ─── Impact analysis ───────────────────────────────────────────────

  /**
   * Get the impact radius of a method — all methods that could be
   * affected by changes to this method (callers, callers of callers, etc.).
   */
  getImpactRadius(nodeId: string, maxDepth: number = 3): CGNode[] {
    const visited = new Set<string>();
    const impacted: CGNode[] = [];

    const bfs = (id: string, depth: number) => {
      if (depth >= maxDepth || visited.has(id)) return;
      visited.add(id);

      const callers = this.getIncomingEdges(id, ['calls']);
      for (const edge of callers) {
        const callerNode = this.getNode(edge.source);
        if (callerNode && !visited.has(edge.source)) {
          impacted.push(callerNode);
          bfs(edge.source, depth + 1);
        }
      }
    };

    bfs(nodeId, 0);
    return impacted;
  }

  // ─── Helpers ────────────────────────────────────────────────────────

  private rowToNode(row: any): CGNode {
    return {
      id: row.id,
      kind: row.kind,
      name: row.name,
      qualifiedName: row.qualified_name,
      filePath: row.file_path,
      language: row.language,
      startLine: row.start_line,
      endLine: row.end_line,
      signature: row.signature ?? undefined,
      visibility: row.visibility ?? undefined,
      isStatic: row.is_static === 1,
      isExported: row.is_exported === 1,
    };
  }

  /** Get the CodeGraph DB path */
  getDbPath(): string {
    return (this.db as any).name ?? 'codegraph.db';
  }

  close(): void {
    this.db.close();
  }
}
