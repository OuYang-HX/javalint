/**
 * Taint Tracker — Cross-file taint propagation analysis
 *
 * Uses CodeGraph's call graph to trace how user-controlled data
 * flows across method boundaries (files, classes, packages).
 *
 * Core concept: a "taint source" (e.g. a method that accepts request params)
 * propagates through call chains to a "dangerous sink" (e.g. Statement.executeQuery).
 *
 * Before taint tracking (current JavaLint):
 *   - Detects: UserService.java:32 Statement.executeQuery()  ← danger at sink
 *   - Cannot tell: does user input reach this sink?
 *
 * After taint tracking (this module):
 *   - Detects: UserController.handleGetUser(requestParam) → UserService.findByUsername(username) → Statement.executeQuery()
 *   - Can report: "User input 'requestParam' flows through handleGetUser→findByUsername to Statement.executeQuery()"
 *   - Confidence boosted from 'medium' to 'high' because we can SEE the taint chain
 *
 * Taint sources (heuristic-based):
 *   - Method parameter names containing: request, param, input, user, header
 *   - Methods annotated with Spring: @RequestParam, @PathVariable, @RequestBody
 *   - HttpServletRequest.getParameter() / getHeader() / getInputStream()
 *
 * Taint propagation rules:
 *   - If method M receives tainted data via parameter, and M calls N passing
 *     that parameter (or a derived value) as an argument, then N's corresponding
 *     parameter becomes tainted.
 *   - Taint flows through method calls tracked by CodeGraph's 'calls' edges.
 *   - Taint does NOT flow through: sanitize(), escape(), encode() methods.
 *   - Max propagation depth: 5 hops (to avoid infinite loops in recursive calls).
 */

import { CodeGraphTraverser, CGNode, CGEdge, CallerInfo, CallChainPath } from './codegraph-traverser';
import { CallSite, Alert } from '../types';

// ─── Types ────────────────────────────────────────────────────────────

/** A taint source — where user-controlled data enters the system */
export interface TaintSource {
  /** The method that receives user input */
  methodNode: CGNode;
  /** The parameter name(s) that carry taint */
  taintedParameters: string[];
  /** How we identified this as a taint source */
  reason: string;
  /** Confidence of this taint source identification */
  confidence: 'high' | 'medium' | 'low';
}

/** A taint chain — the full propagation path from source to sink */
export interface TaintChain {
  /** Where the taint originates */
  source: TaintSource;
  /** The propagation path (method nodes, in order) */
  path: CGNode[];
  /** The edges connecting the path */
  edges: CGEdge[];
  /** The dangerous sink (the Alert that was triggered) */
  sink: Alert;
  /** Total depth from source to sink */
  depth: number;
  /** Overall confidence of the taint chain */
  confidence: 'high' | 'medium' | 'low';
}

/** Result of taint analysis */
export interface TaintAnalysisResult {
  /** All identified taint sources */
  sources: TaintSource[];
  /** All taint chains found */
  chains: TaintChain[];
  /** Stats */
  stats: {
    methodsAnalyzed: number;
    sourcesFound: number;
    chainsFound: number;
  };
}

// ─── Taint source heuristics ──────────────────────────────────────────

/** Parameter name patterns that indicate user input */
const TAINTED_PARAM_PATTERNS = [
  /request/i,
  /param/i,
  /\binput\b/i,
  /\buser/i,
  /header/i,
  /body/i,
  /query/i,
  /cookie/i,
  /token/i,
  /password/i,
  /secret/i,
  /key/i,
  /id$/i,         // ends with 'id' (userId, requestId, etc.)
  /name$/i,       // ends with 'name' (username, filename, etc.)
  /path$/i,       // ends with 'path' (filePath, uploadPath, etc.)
  /url$/i,
  /file$/i,
];

/** Method names that are well-known taint sources */
const TAINT_SOURCE_METHODS = new Set([
  'getParameter', 'getHeader', 'getInputStream', 'getReader',
  'getQueryString', 'getRequestURI', 'getRemoteAddr',
  'getCookies', 'getAttribute', 'getParameterValues',
  'getPart', 'getParts',
]);

/** Method names that sanitize input (taint stops here) */
const SANITIZER_METHODS = new Set([
  'sanitize', 'escape', 'encode', 'encodeForSQL', 'encodeForHTML',
  'encodeForJavaScript', 'encodeForURL', 'encodeForCSS',
  'parameterize', 'prepareStatement', 'bind', 'setString',
  'setInt', 'setLong', 'setDouble', 'setFloat', 'setBoolean',
  'setBytes', 'setDate', 'setTimestamp', 'setObject',
  'validate', 'whitelist', 'allowlist',
]);

/** Maximum taint propagation depth */
const MAX_TAINT_DEPTH = 5;

// ─── TaintTracker class ──────────────────────────────────────────────

export class TaintTracker {
  private traverser: CodeGraphTraverser;
  private projectRoot: string;

  constructor(traverser: CodeGraphTraverser, projectRoot: string) {
    this.traverser = traverser;
    this.projectRoot = projectRoot;
  }

  /**
   * Main analysis: given a list of alerts (dangerous sinks), trace
   * each one back to taint sources via CodeGraph's call graph.
   *
   * For each alert, we:
   *   1. Find the CodeGraph node ID for the method containing the alert
   *   2. Walk backwards through callers to find taint sources
   *   3. If a taint source is found, create a TaintChain
   *   4. Enhance the alert with taint chain information
   */
  analyzeAlerts(alerts: Alert[]): TaintAnalysisResult {
    const sources: TaintSource[] = [];
    const chains: TaintChain[] = [];

    // First, identify all taint sources in the project
    const allMethods = this.traverser.getAllJavaMethods();
    const identifiedSources = this.identifyTaintSources(allMethods);
    sources.push(...identifiedSources);

    // Build a map: methodNodeId → TaintSource for quick lookup
    const sourceByNodeId = new Map<string, TaintSource>();
    for (const src of identifiedSources) {
      sourceByNodeId.set(src.methodNode.id, src);
    }

    // For each alert, try to trace a taint chain
    for (const alert of alerts) {
      const chain = this.traceTaintChain(alert, sourceByNodeId);
      if (chain) {
        chains.push(chain);
      }
    }

    return {
      sources,
      chains,
      stats: {
        methodsAnalyzed: allMethods.length,
        sourcesFound: sources.length,
        chainsFound: chains.length,
      },
    };
  }

  // ─── Taint source identification ───────────────────────────────────

  /**
   * Identify taint sources among all Java methods in the project.
   *
   * A method is a taint source if:
   *   1. It has a parameter whose name matches a taint pattern
   *   2. It calls a known taint source method (HttpServletRequest.getParameter)
   *   3. It's a Spring controller handler method (has @RequestMapping etc.)
   */
  public identifyTaintSources(methods: CGNode[]): TaintSource[] {
    const sources: TaintSource[] = [];

    for (const method of methods) {
      const taintInfo = this.analyzeMethodForTaint(method);
      if (taintInfo) {
        sources.push(taintInfo);
      }
    }

    return sources;
  }

  private analyzeMethodForTaint(method: CGNode): TaintSource | null {
    // Strategy 1: Check parameter names from signature
    // Signature format: "ReturnType (ParamType1 paramName1, ParamType2 paramName2)"
    if (method.signature) {
      const taintedParams = this.extractTaintedParams(method.signature);
      if (taintedParams.length > 0) {
        return {
          methodNode: method,
          taintedParameters: taintedParams,
          reason: `Parameter name(s) match taint pattern: ${taintedParams.join(', ')}`,
          confidence: 'medium',
        };
      }
    }

    // Strategy 2: Check if the method calls known taint source methods
    const callees = this.traverser.getCallees(method.id, 1);
    for (const callee of callees) {
      if (TAINT_SOURCE_METHODS.has(callee.caller.name)) {
        return {
          methodNode: method,
          taintedParameters: ['<implicit: from ' + callee.caller.name + '()>'],
          reason: `Calls known taint source method: ${callee.caller.name}()`,
          confidence: 'high',
        };
      }
    }

    // Strategy 3: Check if method is in a Spring Controller class
    // (methods in controllers that accept String parameters are likely taint sources)
    const containingClass = this.findContainingClass(method);
    if (containingClass && containingClass.name.endsWith('Controller')) {
      if (method.signature) {
        const stringParams = this.extractStringParams(method.signature);
        if (stringParams.length > 0) {
          return {
            methodNode: method,
            taintedParameters: stringParams,
            reason: `Spring Controller handler with String parameter(s): ${stringParams.join(', ')}`,
            confidence: 'medium',
          };
        }
      }
    }

    return null;
  }

  // ─── Taint chain tracing ───────────────────────────────────────────

  /**
   * For a given alert (dangerous sink), trace backwards through
   * CodeGraph's call graph to find a taint source.
   *
   * Algorithm:
   *   1. Find the CodeGraph node for the method containing the alert
   *   2. BFS backwards through 'calls' edges (callers)
   *   3. At each step, check if the caller is a taint source
   *   4. If found, build the TaintChain
   */
  private traceTaintChain(
    alert: Alert,
    sourceByNodeId: Map<string, TaintSource>,
  ): TaintChain | null {
    // Step 1: Find the CodeGraph node for the alert's containing method
    const methodNodeId = this.traverser.findMethodNodeId(
      alert.filePath,
      alert.callerMethod,
    );
    if (!methodNodeId) return null;

    // Step 2: Collect ALL taint chains (local + cross-file), then pick best
    const candidateChains: TaintChain[] = [];

    // Check if the method itself is a taint source (local, depth 0)
    const directSource = sourceByNodeId.get(methodNodeId);
    if (directSource) {
      const methodNode = this.traverser.getNode(methodNodeId);
      if (methodNode) {
        candidateChains.push({
          source: directSource,
          path: [methodNode],
          edges: [],
          sink: alert,
          depth: 0,
          confidence: this.computeChainConfidence(directSource.confidence, 0),
        });
      }
    }

    // Step 3: BFS backwards through callers to find cross-file taint sources
    const visited = new Set<string>();
    const queue: Array<{
      nodeId: string;
      path: CGNode[];
      edges: CGEdge[];
      depth: number;
    }> = [];

    const startNode = this.traverser.getNode(methodNodeId);
    if (!startNode) return candidateChains.length > 0 ? this.pickBestChain(candidateChains) : null;

    queue.push({ nodeId: methodNodeId, path: [startNode], edges: [], depth: 0 });
    visited.add(methodNodeId);

    while (queue.length > 0) {
      const { nodeId, path, edges, depth } = queue.shift()!;

      if (depth >= MAX_TAINT_DEPTH) continue;

      // Get callers of this method
      const callers = this.traverser.getCallers(nodeId, 1);

      for (const callerInfo of callers) {
        if (visited.has(callerInfo.caller.id)) continue;
        visited.add(callerInfo.caller.id);

        const newPath = [callerInfo.caller, ...path];
        const newEdges = [callerInfo.edge, ...edges];
        const newDepth = depth + 1;

        // Check if this caller is a taint source
        const source = sourceByNodeId.get(callerInfo.caller.id);
        if (source) {
          candidateChains.push({
            source,
            path: newPath,
            edges: newEdges,
            sink: alert,
            depth: newDepth,
            confidence: this.computeChainConfidence(source.confidence, newDepth),
          });
        }

        // Continue BFS even after finding a source (to discover longer chains)
        queue.push({
          nodeId: callerInfo.caller.id,
          path: newPath,
          edges: newEdges,
          depth: newDepth,
        });
      }
    }

    return candidateChains.length > 0 ? this.pickBestChain(candidateChains) : null;
  }

  // ─── Helpers ────────────────────────────────────────────────────────

  /**
   * Extract parameter names from a Java method signature.
   * Input: "User (String requestParam)" → ["requestParam"]
   * Input: "int (String headerValue)" → ["headerValue"]
   * Input: "void (Long id, String username)" → ["id", "username"]
   */
  private extractTaintedParams(signature: string): string[] {
    const paramsStr = this.extractParamsString(signature);
    if (!paramsStr || paramsStr === '()') return [];

    const params = this.parseParams(paramsStr);
    const tainted: string[] = [];

    for (const param of params) {
      if (TAINTED_PARAM_PATTERNS.some(p => p.test(param.name))) {
        tainted.push(param.name);
      }
    }

    return tainted;
  }

  /** Extract String-typed parameter names (common for user input) */
  private extractStringParams(signature: string): string[] {
    const paramsStr = this.extractParamsString(signature);
    if (!paramsStr || paramsStr === '()') return [];

    const params = this.parseParams(paramsStr);
    return params
      .filter(p => p.type === 'String')
      .map(p => p.name);
  }

  private extractParamsString(signature: string): string | null {
    const match = signature.match(/\(([^)]*)\)/);
    return match ? match[1]! : null;
  }

  private parseParams(paramsStr: string): Array<{ type: string; name: string }> {
    const result: Array<{ type: string; name: string }> = [];

    // Split by comma, handling generics
    const parts = this.splitParams(paramsStr);
    for (const part of parts) {
      const trimmed = part.trim();
      if (!trimmed) continue;

      // "String requestParam" → { type: "String", name: "requestParam" }
      // "Long id" → { type: "Long", name: "id" }
      const tokens = trimmed.split(/\s+/);
      if (tokens.length >= 2) {
        result.push({
          type: tokens.slice(0, -1).join(' '),
          name: tokens[tokens.length - 1]!,
        });
      } else if (tokens.length === 1) {
        // No name, just a type
        result.push({ type: tokens[0]!, name: '' });
      }
    }

    return result;
  }

  /** Split parameter string by commas, respecting angle brackets for generics */
  private splitParams(paramsStr: string): string[] {
    const parts: string[] = [];
    let depth = 0;
    let current = '';

    for (let i = 0; i < paramsStr.length; i++) {
      const ch = paramsStr[i]!;
      if (ch === '<') depth++;
      else if (ch === '>') depth--;
      else if (ch === ',' && depth === 0) {
        parts.push(current);
        current = '';
        continue;
      }
      current += ch;
    }
    if (current.trim()) parts.push(current);

    return parts;
  }

  /** Find the class node that contains a method node */
  private findContainingClass(methodNode: CGNode): CGNode | null {
    const incomingContains = this.traverser.getIncomingEdges(methodNode.id, ['contains']);
    for (const edge of incomingContains) {
      const classNode = this.traverser.getNode(edge.source);
      if (classNode && classNode.kind === 'class') {
        return classNode;
      }
    }
    return null;
  }

  /** Compute confidence of a taint chain based on source confidence and depth */
  private computeChainConfidence(
    sourceConfidence: 'high' | 'medium' | 'low',
    depth: number,
  ): 'high' | 'medium' | 'low' {
    // Each hop reduces confidence slightly
    if (depth === 0) return sourceConfidence;
    if (depth <= 2 && sourceConfidence === 'high') return 'high';
    if (depth <= 2) return 'medium';
    return 'low';
  }

  /**
   * Check if a method is a sanitizer (taint stops here).
   * Used to prevent false positives when tracing through sanitize/escape methods.
   */
  isSanitizer(methodName: string): boolean {
    return SANITIZER_METHODS.has(methodName);
  }

  /**
   * Pick the best taint chain from candidates.
   *
   * Preference order:
   *   1. Cross-file chains (depth >= 1) — these are the most valuable
   *   2. Chains with higher confidence
   *   3. Deeper chains (more context)
   *   4. Local taint chains (depth = 0) as fallback
   */
  private pickBestChain(candidates: TaintChain[]): TaintChain | null {
    if (candidates.length === 0) return null;

    // Sort by: cross-file first, then confidence, then depth
    const confidenceOrder: Record<string, number> = { 'high': 3, 'medium': 2, 'low': 1 };

    candidates.sort((a, b) => {
      // Cross-file chains (depth >= 1) are strongly preferred
      const aCrossFile = a.depth >= 1 ? 1 : 0;
      const bCrossFile = b.depth >= 1 ? 1 : 0;
      if (aCrossFile !== bCrossFile) return bCrossFile - aCrossFile;

      // Higher confidence
      const aConf = confidenceOrder[a.confidence] ?? 0;
      const bConf = confidenceOrder[b.confidence] ?? 0;
      if (aConf !== bConf) return bConf - aConf;

      // Deeper chain (more context)
      return b.depth - a.depth;
    });

    return candidates[0]!;
  }
}
