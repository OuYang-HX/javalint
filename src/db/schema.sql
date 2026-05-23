-- Alert database schema

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
    -- Taint chain fields (cross-file propagation)
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
