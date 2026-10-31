const {
  verifyBearerToken
} = require('../shared/security');

const {
  evaluatePolicy
} = require('./policy');

const {
  writeAuditLog
} = require('../shared/audit');

function logDecision(req, decision, reason) {
  try {
    writeAuditLog({
      subject: req.principal
        ? `${req.principal.role}:${req.principal.sub}`
        : 'anonymous',
      endpoint: req.originalUrl,
      method: req.method,
      deviceId: req.get('X-Device-ID') || null,
      decision,
      reason
    });
  } catch (error) {
    console.error('Audit log error:', error.message);
  }
}

// Memeriksa access token atau service token
function authenticateToken(req, res, next) {
  const authorization = req.get('Authorization') || '';
  const match = authorization.match(/^Bearer\s+(.+)$/i);

  if (!match) {
    logDecision(req, 'DENY', 'Authorization token tidak ditemukan.');
    return res.status(401).json({
      success: false,
      message: 'Authorization Bearer token wajib disertakan.'
    });
  }

  try {
    req.principal = verifyBearerToken(match[1]);
    next();
  } catch (error) {
    logDecision(req, 'DENY', 'Token tidak valid atau kedaluwarsa.');

    return res.status(401).json({
      success: false,
      message: 'Token tidak valid atau sudah kedaluwarsa.'
    });
  }
}

// Meminta keputusan kepada Policy Engine
function authorizeRequest(req, res, next) {
  try {
    const result = evaluatePolicy({
      method: req.method,
      path: req.originalUrl,
      principal: req.principal
    });

    if (!result.allowed) {
      logDecision(req, 'DENY', result.reason);

      return res.status(403).json({
        success: false,
        decision: 'DENY',
        message: result.reason
      });
    }

    req.policyDecision = result;

    logDecision(req, 'ALLOW', result.reason);

    next();
  } catch (error) {
    logDecision(req, 'DENY', 'Terjadi kesalahan pemeriksaan kebijakan.');

    return res.status(500).json({
      success: false,
      message: 'Gagal memeriksa kebijakan akses.'
    });
  }
}

module.exports = {
  authenticateToken,
  authorizeRequest
};