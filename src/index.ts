/**
 * JavaLint - Java static code analysis powered by CodeGraph
 *
 * Four-layer analysis architecture:
 *
 *   Layer 1: Deep Scan (tree-sitter)
 *     - Parses all Java source files
 *     - Extracts ALL method_invocation nodes (including external deps)
 *     - Resolves receiver types via TypeResolver + ReturnTypeTable
 *
 *   Layer 2: CodeGraph Enrichment (cross-file graph)
 *     - Reads CodeGraph's SQLite DB for resolved cross-file call edges
 *     - Enriches CallSites with CodeGraph's resolved signatures
 *     - Uses CodeGraphTraverser for multi-hop call chain traversal
 *
 *   Layer 3: Rule Matching + Rich Script Context
 *     - Matches call site signatures against rule patterns
 *     - Builds ScriptContext with param sources, obj history, ret usage
 *     - Executes check scripts via multi-language engine (JS/Groovy/Python)
 *
 *   Layer 4: Taint Analysis (cross-file propagation)
 *     - Identifies taint sources (methods receiving user input)
 *     - Traces taint propagation through call chains
 *     - Enhances alerts with cross-file taint chain information
 *     - Boosts confidence when taint source is confirmed
 *
 * Stores alerts in an independent database.
 */

import * as fs from 'fs';
import * as path from 'path';
import { CallSite, Alert, AnalysisResult, TaintChainInfo } from './types';
import { CallCollector } from './analyzer/call-collector';
import { DeepCallScanner } from './analyzer/deep-call-scanner';
import { CodeGraphTraverser } from './analyzer/codegraph-traverser';
import { TaintTracker, TaintAnalysisResult } from './analyzer/taint-tracker';
import { RuleEngine } from './rules/rule-engine';
import { AlertDatabase } from './db/alert-database';

export class JavaLint {
  private projectRoot: string;
  private targetFile?: string;  // 可指定单个文件
  private callCollector: CallCollector | null = null;
  private deepScanner: DeepCallScanner | null = null;
  private cgTraverser: CodeGraphTraverser | null = null;
  private taintTracker: TaintTracker | null = null;
  private ruleEngine: RuleEngine;
  private alertDb: AlertDatabase | null = null;
  private rulesDir: string;

  constructor(projectRoot: string, rulesDir?: string, targetFile?: string) {
    this.projectRoot = path.resolve(projectRoot);
    this.targetFile = targetFile;
    this.rulesDir = rulesDir || path.join(__dirname, '..', 'rules');
    this.ruleEngine = new RuleEngine(this.rulesDir);
  }

  /**
   * Initialize: load rules, init scanners, optionally use CodeGraph
   */
  async init(): Promise<void> {
    // 1. Initialize deep scanner (tree-sitter, always available)
    this.deepScanner = new DeepCallScanner(this.projectRoot);
    await this.deepScanner.init();
    console.log('  Deep scanner initialized (tree-sitter)');

    // 2. Try to initialize CodeGraph components (optional, for enriched data)
    const codegraphDir = path.join(this.projectRoot, '.codegraph');
    const codegraphDb = path.join(codegraphDir, 'codegraph.db');
    if (fs.existsSync(codegraphDb)) {
      this.callCollector = new CallCollector(codegraphDb, this.projectRoot);
      console.log('  CodeGraph index found (enriched mode)');

      // Initialize CodeGraph traverser for cross-file analysis
      try {
        this.cgTraverser = new CodeGraphTraverser(codegraphDb, this.projectRoot);
        this.taintTracker = new TaintTracker(this.cgTraverser, this.projectRoot);
        console.log('  CodeGraph traverser + taint tracker initialized');
      } catch (e) {
        console.log(`  CodeGraph traverser failed: ${(e as Error).message} (falling back to basic mode)`);
      }
    } else {
      console.log('  CodeGraph index not found (deep-scan-only mode)');
    }

    // 3. Load rules
    const ruleCount = this.ruleEngine.loadRules();
    console.log(`  Loaded ${ruleCount} rules from ${this.rulesDir}`);

    // 4. Inject dependencies into RuleEngine (for param resolution, obj history, etc.)
    if (this.deepScanner) {
      this.ruleEngine.injectDependencies(
        this.deepScanner,
        this.cgTraverser,
        this.projectRoot,
      );
    }

    // 5. Show available script engines
    const engines = this.ruleEngine.getEngineRegistry().listAvailable();
    console.log(`  Script engines: ${engines.join(', ')}`);

    // 6. Initialize alert database
    const javalintDir = path.join(this.projectRoot, '.javalint');
    const alertDbPath = path.join(javalintDir, 'alerts.db');
    this.alertDb = new AlertDatabase(alertDbPath);
  }

  /**
   * Run analysis
   */
  async analyze(targetFile?: string): Promise<AnalysisResult> {
    const startTime = Date.now();

    if (!this.deepScanner || !this.alertDb) {
      throw new Error('JavaLint not initialized. Call init() first.');
    }

    // 允许覆盖 targetFile
    const scanTarget = targetFile || this.targetFile;

    // ── Layer 1: Deep scan ──────────────────────────────────────────
    console.log('\n🔍 Deep scanning Java source files (tree-sitter)...');
    const scanResults = scanTarget
      ? [this.deepScanner.scanFile(path.relative(this.projectRoot, scanTarget))]
      : this.deepScanner.scanAll();
    let totalRawCalls = 0;
    for (const r of scanResults) totalRawCalls += r.calls.length;
    console.log(`  Scanned ${scanResults.length} files, found ${totalRawCalls} method calls`);

    // 2. Convert to CallSites with signature enhancement
    const deepCallSites = this.deepScanner.toCallSites(scanResults);

    // ── Layer 2: CodeGraph enrichment ───────────────────────────────
    let cgCallSites: CallSite[] = [];
    if (this.callCollector) {
      console.log('\n📋 Merging CodeGraph resolved edges...');
      cgCallSites = this.callCollector.collectCallSites();
      console.log(`  CodeGraph: ${cgCallSites.length} call sites (resolved + unresolved)`);
    }

    // 3. Merge deep-scan and CodeGraph call sites
    const mergedSites = this.mergeCallSites(deepCallSites, cgCallSites);
    console.log(`  Merged: ${mergedSites.length} unique call sites`);

    // 4. Inject scan results into RuleEngine (for param resolution)
    this.ruleEngine.injectScanResults(scanResults);

    // ── Layer 3: Rule matching + Rich script context ────────────────
    console.log('\n⚙️  Running rule checks (multi-engine)...');
    const alerts: Alert[] = [];

    for (const callSite of mergedSites) {
      const matchedRules = this.ruleEngine.matchRules(callSite);

      for (const rule of matchedRules) {
        const checkResult = this.ruleEngine.executeCheck(rule, callSite);
        if (checkResult.alert) {
          const alert = this.ruleEngine.createAlert(rule, callSite, checkResult);
          alerts.push(alert);
          this.alertDb.insertAlert(alert);
        }
      }
    }

    console.log(`  Found ${alerts.length} alerts from rule matching`);

    // 调试: 如果0告警, 显示前几个call site的签名和匹配结果
    if (alerts.length === 0 && mergedSites.length > 0) {
      console.log('  ⚠️  No alerts — showing first 5 call site signatures:');
      for (const site of mergedSites.slice(0, 5)) {
        const matched = this.ruleEngine.matchRules(site);
        console.log(`    ${site.fullSignature.fullQualifiedName} → matched: ${matched.map(r => r.id).join(',') || 'NONE'}`);
      }
    }

    // ── Layer 4: Cross-file taint analysis ──────────────────────────
    let taintStats = { sourcesFound: 0, chainsFound: 0, methodsAnalyzed: 0 };

    if (this.taintTracker && alerts.length > 0) {
      console.log('\n🔬 Running cross-file taint analysis...');

      const taintResult = this.taintTracker.analyzeAlerts(alerts);
      taintStats = {
        sourcesFound: taintResult.stats.sourcesFound,
        chainsFound: taintResult.stats.chainsFound,
        methodsAnalyzed: taintResult.stats.methodsAnalyzed,
      };

      console.log(`  Identified ${taintResult.stats.sourcesFound} taint source(s)`);
      console.log(`  Found ${taintResult.stats.chainsFound} taint chain(s)`);

      // Enhance alerts with taint chain information
      for (const chain of taintResult.chains) {
        const matchingAlert = alerts.find(a =>
          a.filePath === chain.sink.filePath &&
          a.line === chain.sink.line &&
          a.fullSignature === chain.sink.fullSignature
        );

        if (matchingAlert) {
          const propagationPath = chain.path
            .map(n => n.name)
            .join(' → ');

          matchingAlert.taintChain = {
            sourceMethod: chain.source.methodNode.name,
            sourceFile: chain.source.methodNode.filePath,
            sourceParameters: chain.source.taintedParameters,
            propagationPath,
            depth: chain.depth,
            confidence: chain.confidence,
            sourceReason: chain.source.reason,
          };

          // Boost confidence if taint chain confirms the alert
          if (chain.confidence === 'high' && matchingAlert.confidence === 'medium') {
            matchingAlert.confidence = 'high';
            matchingAlert.message += ` [Taint confirmed: ${propagationPath}]`;
          } else if (chain.confidence === 'medium' || chain.confidence === 'high') {
            matchingAlert.message += ` [Taint source: ${chain.source.methodNode.name}(${chain.source.taintedParameters.join(', ')})]`;
          }

          // Re-insert with taint chain info
          this.alertDb.insertAlert(matchingAlert);
        }
      }
    }

    const durationMs = Date.now() - startTime;

    return {
      totalCallSites: mergedSites.length,
      alerts,
      alertCount: alerts.length,
      durationMs,
      taintStats,
    };
  }

  /**
   * Merge deep-scan and CodeGraph call sites.
   * Deep scan captures ALL calls (including external deps).
   * CodeGraph provides resolved signatures for project-internal calls.
   * Prefer deep scan for completeness; enrich with CodeGraph data where available.
   */
  private mergeCallSites(deepSites: CallSite[], cgSites: CallSite[]): CallSite[] {
    // Index CodeGraph sites by (file, line, method) for quick lookup
    const cgIndex = new Map<string, CallSite>();
    for (const site of cgSites) {
      const key = `${site.callerFile}:${site.callerLine}:${site.calleeMethodName}`;
      cgIndex.set(key, site);
    }

    const merged: CallSite[] = [];
    const seen = new Set<string>();

    // Add all deep-scan sites
    for (const site of deepSites) {
      const key = `${site.callerFile}:${site.callerLine}:${site.calleeMethodName}`;
      seen.add(key);

      // If CodeGraph has a better signature for this call, use it
      const cgSite = cgIndex.get(key);
      if (cgSite && cgSite.calleeResolved) {
        merged.push({
          ...site,
          calleeResolved: true,
          calleeNode: cgSite.calleeNode,
          fullSignature: {
            ...cgSite.fullSignature,
            sourceLine: site.fullSignature.sourceLine || cgSite.fullSignature.sourceLine,
          },
        });
      } else {
        merged.push(site);
      }
    }

    // Add CodeGraph sites not covered by deep scan
    for (const site of cgSites) {
      const key = `${site.callerFile}:${site.callerLine}:${site.calleeMethodName}`;
      if (!seen.has(key)) {
        merged.push(site);
        seen.add(key);
      }
    }

    return merged;
  }

  /**
   * Print analysis results
   */
  printResults(result: AnalysisResult): void {
    console.log('\n' + '='.repeat(72));
    console.log('  🛡️  JavaLint Analysis Results');
    console.log('='.repeat(72));

    console.log(`\n  📊 Summary:`);
    console.log(`     Call sites analyzed: ${result.totalCallSites}`);
    console.log(`     Alerts found:        ${result.alertCount}`);
    console.log(`     Analysis time:       ${result.durationMs}ms`);

    if (result.taintStats && result.taintStats.sourcesFound > 0) {
      console.log(`\n  🔬 Taint Analysis:`);
      console.log(`     Methods analyzed:  ${result.taintStats.methodsAnalyzed}`);
      console.log(`     Taint sources:     ${result.taintStats.sourcesFound}`);
      console.log(`     Taint chains:      ${result.taintStats.chainsFound}`);
    }

    // Group alerts by severity
    const bySeverity = new Map<string, Alert[]>();
    for (const alert of result.alerts) {
      const sev = alert.severity;
      if (!bySeverity.has(sev)) bySeverity.set(sev, []);
      bySeverity.get(sev)!.push(alert);
    }

    for (const [severity, alertList] of bySeverity) {
      const icon = severity === 'critical' ? '🔴' : severity === 'high' ? '🟠' : '🟡';
      console.log(`\n  ${icon} ${severity.toUpperCase()} (${alertList.length})`);
      console.log('  ' + '-'.repeat(50));

      for (const alert of alertList) {
        console.log(`\n  📍 ${alert.filePath}:${alert.line}`);
        console.log(`     [${alert.ruleId}] ${alert.ruleName}`);
        console.log(`     ${alert.message}`);
        console.log(`     Signature: ${alert.fullSignature}`);
        if (alert.sourceLine) {
          console.log(`     Source:    ${alert.sourceLine}`);
        }
        console.log(`     Confidence: ${alert.confidence}`);

        // Print taint chain if available
        if (alert.taintChain) {
          console.log(`     🔗 Taint chain:`);
          console.log(`        Source: ${alert.taintChain.sourceMethod}() in ${alert.taintChain.sourceFile}`);
          console.log(`        Tainted params: ${alert.taintChain.sourceParameters.join(', ')}`);
          console.log(`        Propagation: ${alert.taintChain.propagationPath}`);
          console.log(`        Depth: ${alert.taintChain.depth}, Confidence: ${alert.taintChain.confidence}`);
          console.log(`        Reason: ${alert.taintChain.sourceReason}`);
        }
      }
    }

    console.log('\n' + '='.repeat(72));
    console.log(`  Alerts saved to: ${path.join(this.projectRoot, '.javalint', 'alerts.db')}`);
    console.log('='.repeat(72) + '\n');
  }

  getRuleEngine(): RuleEngine {
    return this.ruleEngine;
  }

  getCodeGraphTraverser(): CodeGraphTraverser | null {
    return this.cgTraverser;
  }

  close(): void {
    this.deepScanner?.close();
    this.callCollector?.close();
    this.cgTraverser?.close();
    this.alertDb?.close();
  }
}