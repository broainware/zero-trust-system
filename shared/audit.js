
const db = require('./db');

// Mencatat keputusan akses ke database
function writeAuditLog({
  subject = 'anonymous',
  endpoint = 'unknown',
  method = null,
  deviceId = null,
  decision,
  reason
}) {
  const result = String(decision || '').toUpperCase();

  if (!['ALLOW', 'DENY'].includes(result)) {
    throw new Error('Keputusan harus ALLOW atau DENY.');
  }

  if (!reason) {
    throw new Error('Alasan keputusan wajib diisi.');
  }

  const timestamp = new Date().toISOString();

  const statement = db.prepare(`
    INSERT INTO audit_logs (
      timestamp,
      subject,
      endpoint,
      method,
      device_id,
      decision,
      reason
    )
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `);

  const info = statement.run(
    timestamp,
    String(subject),
    String(endpoint),
    method,
    deviceId,
    result,
    String(reason)
  );

  return info.lastInsertRowid;
}

// Mengambil riwayat audit log
function getAuditLogs(limit = 100) {
  const safeLimit = Math.min(
    Math.max(Number.parseInt(limit, 10) || 100, 1),
    500
  );

  return db.prepare(`
    SELECT
      id,
      timestamp,
      subject,
      endpoint,
      method,
      device_id,
      decision,
      reason
    FROM audit_logs
    ORDER BY id DESC
    LIMIT ?
  `).all(safeLimit);
}

module.exports = {
  writeAuditLog,
  getAuditLogs
};
