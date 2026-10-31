const express = require('express');
const path = require('node:path');
const dotenv = require('dotenv');

dotenv.config({
  path: path.resolve(__dirname, '../.env')
});

const router = express.Router();
router.use(express.json({ limit: '32kb' }));

const db = require('../shared/db');

const {
  createAccessToken,
  createRefreshToken,
  hashToken,
  createServiceToken,
  verifyPassword
} = require('../shared/security');

const {
  writeAuditLog
} = require('../shared/audit');

function logAuth(subject, req, decision, reason) {
  try {
    writeAuditLog({
      subject,
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

// Menyimpan refresh token ke database
function saveRefreshToken(userId) {
  const refresh = createRefreshToken();

  db.prepare(`
    INSERT INTO refresh_tokens (
      user_id,
      token_hash,
      expires_at
    )
    VALUES (?, ?, ?)
  `).run(
    userId,
    refresh.tokenHash,
    refresh.expiresAt
  );

  return refresh;
}

// LOGIN
router.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body || {};
    const deviceId = req.get('X-Device-ID');

    if (!username || !password || !deviceId) {
      return res.status(400).json({
        success: false,
        message: 'Username, password, dan device ID wajib diisi.'
      });
    }

    const user = db.prepare(`
      SELECT id, username, password_hash, role, nim
      FROM users
      WHERE username = ?
    `).get(username);

    if (
      !user ||
      !(await verifyPassword(password, user.password_hash))
    ) {
      logAuth(username, req, 'DENY', 'Kredensial tidak valid.');

      return res.status(401).json({
        success: false,
        message: 'Username atau password salah.'
      });
    }

    const device = db.prepare(`
      SELECT id
      FROM devices
      WHERE user_id = ?
        AND device_id = ?
        AND is_active = 1
    `).get(user.id, deviceId);

    if (!device) {
      logAuth(username, req, 'DENY', 'Device tidak terdaftar.');

      return res.status(403).json({
        success: false,
        message: 'Perangkat tidak terdaftar untuk pengguna ini.'
      });
    }

    const accessToken = createAccessToken(user);
    const refresh = saveRefreshToken(user.id);

    logAuth(username, req, 'ALLOW', 'Login berhasil.');

    return res.json({
      success: true,
      message: 'Login berhasil.',
      tokenType: 'Bearer',
      accessToken,
      refreshToken: refresh.token,
      expiresIn: '10m',
      user: {
        id: user.id,
        username: user.username,
        role: user.role,
        nim: user.nim
      }
    });
  } catch (error) {
    console.error('Login error:', error.message);

    return res.status(500).json({
      success: false,
      message: 'Terjadi kesalahan saat login.'
    });
  }
});

// REFRESH TOKEN
router.post('/refresh', (req, res) => {
  try {
    const { refreshToken } = req.body || {};

    if (!refreshToken) {
      return res.status(400).json({
        success: false,
        message: 'Refresh token wajib diisi.'
      });
    }

    const tokenHash = hashToken(refreshToken);

    const stored = db.prepare(`
      SELECT
        rt.id,
        rt.user_id,
        rt.expires_at,
        u.username,
        u.role,
        u.nim
      FROM refresh_tokens rt
      JOIN users u ON u.id = rt.user_id
      WHERE rt.token_hash = ?
        AND rt.revoked_at IS NULL
    `).get(tokenHash);

    if (!stored || Date.parse(stored.expires_at) <= Date.now()) {
      logAuth('unknown', req, 'DENY', 'Refresh token tidak valid.');

      return res.status(401).json({
        success: false,
        message: 'Refresh token tidak valid, kedaluwarsa, atau dicabut.'
      });
    }

    const newRefresh = createRefreshToken();
    const now = new Date().toISOString();

    const rotate = db.transaction(() => {
      db.prepare(`
        UPDATE refresh_tokens
        SET revoked_at = ?
        WHERE id = ?
      `).run(now, stored.id);

      db.prepare(`
        INSERT INTO refresh_tokens (
          user_id,
          token_hash,
          expires_at
        )
        VALUES (?, ?, ?)
      `).run(
        stored.user_id,
        newRefresh.tokenHash,
        newRefresh.expiresAt
      );
    });

    rotate();

    const accessToken = createAccessToken({
      id: stored.user_id,
      role: stored.role
    });

    logAuth(stored.username, req, 'ALLOW', 'Refresh token berhasil diperbarui.');

    return res.json({
      success: true,
      message: 'Token berhasil diperbarui.',
      tokenType: 'Bearer',
      accessToken,
      refreshToken: newRefresh.token,
      expiresIn: '10m'
    });
  } catch (error) {
    console.error('Refresh error:', error.message);

    return res.status(500).json({
      success: false,
      message: 'Gagal memperbarui token.'
    });
  }
});

// LOGOUT
router.post('/logout', (req, res) => {
  try {
    const { refreshToken } = req.body || {};

    if (!refreshToken) {
      return res.status(400).json({
        success: false,
        message: 'Refresh token wajib diisi.'
      });
    }

    const now = new Date().toISOString();
    const tokenHash = hashToken(refreshToken);

    const result = db.prepare(`
      UPDATE refresh_tokens
      SET revoked_at = ?
      WHERE token_hash = ?
        AND revoked_at IS NULL
    `).run(now, tokenHash);

    if (result.changes === 0) {
      logAuth('unknown', req, 'DENY', 'Refresh token tidak ditemukan atau sudah dicabut.');

      return res.status(401).json({
        success: false,
        message: 'Refresh token tidak valid atau sudah dicabut.'
      });
    }

    logAuth(
      'user:' + result.changes,
      req,
      'ALLOW',
      'Refresh token berhasil dicabut.'
    );

    return res.json({
      success: true,
      message: 'Logout berhasil. Refresh token telah dicabut.'
    });
  } catch (error) {
    console.error('Logout error:', error.message);

    return res.status(500).json({
      success: false,
      message: 'Gagal melakukan logout.'
    });
  }
});

// AUTENTIKASI SERVICE
router.post('/service', async (req, res) => {
  try {
    const { clientId, clientSecret } = req.body || {};

    if (!clientId || !clientSecret) {
      return res.status(400).json({
        success: false,
        message: 'Client ID dan client secret wajib diisi.'
      });
    }

    const client = db.prepare(`
      SELECT client_id, client_secret_hash
      FROM service_clients
      WHERE client_id = ?
        AND is_active = 1
    `).get(clientId);

    if (
      !client ||
      !(await verifyPassword(clientSecret, client.client_secret_hash))
    ) {
      logAuth(clientId, req, 'DENY', 'Kredensial service tidak valid.');

      return res.status(401).json({
        success: false,
        message: 'Client ID atau secret tidak valid.'
      });
    }

    const serviceToken = createServiceToken(client.client_id);

    logAuth(clientId, req, 'ALLOW', 'Service authentication berhasil.');

    return res.json({
      success: true,
      message: 'Service authentication berhasil.',
      tokenType: 'Bearer',
      accessToken: serviceToken,
      expiresIn: '5m'
    });
  } catch (error) {
    console.error('Service authentication error:', error.message);

    return res.status(500).json({
      success: false,
      message: 'Gagal melakukan autentikasi service.'
    });
  }
});

module.exports = router;