const db = require('../shared/db');
const { writeAuditLog } = require('../shared/audit');

function verifyRegisteredDevice(req, res, next) {
  const principal = req.principal;

  // Service tidak menggunakan device ID pengguna
  if (principal.token_use === 'service') {
    return next();
  }

  const deviceId = req.get('X-Device-ID');

  if (!deviceId) {
    return reject(req, res, 'Header X-Device-ID wajib diisi.');
  }

  const userId = Number(principal.sub);

  const device = db.prepare(`
    SELECT id
    FROM devices
    WHERE user_id = ?
      AND device_id = ?
      AND is_active = 1
  `).get(userId, deviceId);

  if (!device) {
    return reject(
      req,
      res,
      'Perangkat tidak terdaftar atau tidak aktif.'
    );
  }

  req.deviceId = deviceId;

  next();
}

function reject(req, res, reason) {
  try {
    writeAuditLog({
      subject: `${req.principal.role}:${req.principal.sub}`,
      endpoint: req.originalUrl,
      method: req.method,
      deviceId: req.get('X-Device-ID') || null,
      decision: 'DENY',
      reason
    });
  } catch (error) {
    console.error('Audit log error:', error.message);
  }

  return res.status(403).json({
    success: false,
    decision: 'DENY',
    message: reason
  });
}

module.exports = {
  verifyRegisteredDevice
};