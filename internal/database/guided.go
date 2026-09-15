package database

const createGuidedRunsTable = `CREATE TABLE IF NOT EXISTS guided_runs (
 id TEXT PRIMARY KEY, target_id TEXT NOT NULL, capture_id TEXT NOT NULL,
 task_id TEXT NOT NULL DEFAULT '', encrypted_input TEXT NOT NULL,
 encrypted_report TEXT NOT NULL DEFAULT '', redacted_report TEXT NOT NULL DEFAULT '{}',
 created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
 FOREIGN KEY(target_id) REFERENCES targets(id) ON DELETE CASCADE,
 FOREIGN KEY(capture_id) REFERENCES capture_sessions(id) ON DELETE CASCADE
);`

const createCaptureAuditTable = `CREATE TABLE IF NOT EXISTS capture_audit (
 id INTEGER PRIMARY KEY AUTOINCREMENT, target_id TEXT NOT NULL, resource_id TEXT NOT NULL,
 action TEXT NOT NULL, created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
 FOREIGN KEY(target_id) REFERENCES targets(id) ON DELETE CASCADE
);`
