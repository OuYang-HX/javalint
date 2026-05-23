/**
 * Alert Database - independent SQLite database for storing analysis results
 *
 * Extended to store cross-file taint chain information.
 */

import { DatabaseSync } from 'node:sqlite';
import * as fs from 'fs';
import * as path from 'path';
import { Alert } from '../types';

export class AlertDatabase {
  private db: DatabaseSync;

  constructor(dbPath: string) {
    // Ensure parent directory exists
    const dir = path.dirname(dbPath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }

    this.db = new DatabaseSync(dbPath);
    this.initSchema();
  }

  private initSchema(): void {
    const schemaPath = path.join(__dirname, 'schema.sql');
    let schema: string;

    if (fs.existsSync(schemaPath)) {
      schema = fs.readFileSync(schemaPath, 'utf-8');
    } else {
      // Inline fallback with taint chain fields
      schema = `
        CREATE TABLE IF NOT EXISTS alerts (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          rule_id TEXT NOT NULL,
          rule_name TEXT NOT NULL,
          severity TEXT NOT NULL,
          message TEXT NOT NULL,
          confidence TEXT NOT NULL,
          file_path TEXT NOT NULL,
          line_number INTEGER NOT NULL,
          package_name TEXT,
          class_name TEXT NOT NULL,
          method_name TEXT NOT NULL,
          parameter_types TEXT,
          full_signature TEXT NOT NULL,
          caller_class TEXT,
          caller_method TEXT,
          source_line TEXT,
          detected_at INTEGER NOT NULL,
          taint_source_method TEXT,
          taint_source_file TEXT,
          taint_source_params TEXT,
          taint_propagation_path TEXT,
          taint_depth INTEGER,
          taint_confidence TEXT,
          taint_source_reason TEXT,
          UNIQUE(rule_id, file_path, line_number, full_signature)
        );
        CREATE INDEX IF NOT EXISTS idx_alerts_rule ON alerts(rule_id);
        CREATE INDEX IF NOT EXISTS idx_alerts_file ON alerts(file_path);
        CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
        CREATE INDEX IF NOT EXISTS idx_alerts_detected ON alerts(detected_at);
        CREATE INDEX IF NOT EXISTS idx_alerts_taint ON alerts(taint_source_method);
      `;
    }

    this.db.exec(schema);
  }

  insertAlert(alert: Alert): void {
    this.db.prepare(`
      INSERT OR IGNORE INTO alerts (
        rule_id, rule_name, severity, message, confidence,
        file_path, line_number, package_name, class_name,
        method_name, parameter_types, full_signature,
        caller_class, caller_method, source_line, detected_at,
        taint_source_method, taint_source_file, taint_source_params,
        taint_propagation_path, taint_depth, taint_confidence,
        taint_source_reason
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      alert.ruleId,
      alert.ruleName,
      alert.severity,
      alert.message,
      alert.confidence,
      alert.filePath,
      alert.line,
      alert.packageName,
      alert.className,
      alert.methodName,
      JSON.stringify(alert.parameterTypes),
      alert.fullSignature,
      alert.callerClass,
      alert.callerMethod,
      alert.sourceLine,
      alert.detectedAt,
      alert.taintChain?.sourceMethod ?? null,
      alert.taintChain?.sourceFile ?? null,
      alert.taintChain?.sourceParameters
        ? JSON.stringify(alert.taintChain.sourceParameters)
        : null,
      alert.taintChain?.propagationPath ?? null,
      alert.taintChain?.depth ?? null,
      alert.taintChain?.confidence ?? null,
      alert.taintChain?.sourceReason ?? null,
    );
  }

  getAlerts(): Alert[] {
    const rows = this.db.prepare(`
      SELECT * FROM alerts ORDER BY detected_at DESC
    `).all() as any[];

    return rows.map(row => ({
      ruleId: row.rule_id,
      ruleName: row.rule_name,
      severity: row.severity,
      message: row.message,
      confidence: row.confidence,
      filePath: row.file_path,
      line: row.line_number,
      packageName: row.package_name,
      className: row.class_name,
      methodName: row.method_name,
      parameterTypes: row.parameter_types ? JSON.parse(row.parameter_types) : [],
      fullSignature: row.full_signature,
      callerClass: row.caller_class,
      callerMethod: row.caller_method,
      sourceLine: row.source_line,
      detectedAt: row.detected_at,
      taintChain: row.taint_source_method ? {
        sourceMethod: row.taint_source_method,
        sourceFile: row.taint_source_file,
        sourceParameters: row.taint_source_params
          ? JSON.parse(row.taint_source_params)
          : [],
        propagationPath: row.taint_propagation_path ?? '',
        depth: row.taint_depth ?? 0,
        confidence: row.taint_confidence ?? 'low',
        sourceReason: row.taint_source_reason ?? '',
      } : undefined,
    }));
  }

  getAlertCount(): number {
    const row = this.db.prepare('SELECT COUNT(*) as count FROM alerts').get() as { count: number };
    return row.count;
  }

  /** Get alerts that have taint chain info */
  getTaintAlerts(): Alert[] {
    return this.getAlerts().filter(a => a.taintChain);
  }

  clearAlerts(): void {
    this.db.exec('DELETE FROM alerts');
  }

  close(): void {
    this.db.close();
  }
}