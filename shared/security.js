
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const crypto = require('node:crypto');
const path = require('node:path');
const dotenv = require('dotenv');

dotenv.config({
  path: path.resolve(__dirname, '../.env')
});

const JWT_ISSUER = 'zero-trust-system';

function getSecret(name) {
  const secret = process.env[name];

  if (!secret || secret.startsWith('change_this')) {
    throw new Error(`Konfigurasi ${name} belum diatur dengan benar.`);
  }

  return secret;
}

// Membuat access token JWT
function createAccessToken(user) {
  if (!user || !user.id || !user.role) {
    throw new Error('Data pengguna tidak lengkap.');
  }

  return jwt.sign(
    {
      role: user.role,
      token_use: 'access'
    },
    getSecret('JWT_ACCESS_SECRET'),
    {
      subject: String(user.id),
      expiresIn: process.env.ACCESS_TOKEN_EXPIRES_IN || '10m',
      algorithm: 'HS256',
      issuer: JWT_ISSUER
    }
  );
}

// Memverifikasi access token
function verifyAccessToken(token) {
  const payload = jwt.verify(
    token,
    getSecret('JWT_ACCESS_SECRET'),
    {
      algorithms: ['HS256'],
      issuer: JWT_ISSUER
    }
  );

  if (
    payload.token_use !== 'access' ||
    !payload.sub ||
    !['mahasiswa', 'dosen', 'admin'].includes(payload.role)
  ) {
    throw new Error('Access token tidak valid.');
  }

  return payload;
}

// Membuat refresh token acak yang dapat dicabut
function createRefreshToken() {
  const token = crypto.randomBytes(48).toString('base64url');

  const tokenHash = hashToken(token);

  const expiresAt = new Date(
    Date.now() + 24 * 60 * 60 * 1000
  ).toISOString();

  return {
    token,
    tokenHash,
    expiresAt
  };
}

// Mengubah token menjadi SHA-256 hash
function hashToken(token) {
  return crypto
    .createHash('sha256')
    .update(token)
    .digest('hex');
}

// Membuat token khusus service
function createServiceToken(clientId) {
  if (!clientId) {
    throw new Error('Client ID wajib diisi.');
  }

  return jwt.sign(
    {
      role: 'service',
      token_use: 'service'
    },
    getSecret('JWT_SERVICE_SECRET'),
    {
      subject: String(clientId),
      expiresIn: process.env.SERVICE_TOKEN_EXPIRES_IN || '5m',
      algorithm: 'HS256',
      issuer: JWT_ISSUER
    }
  );
}

// Memverifikasi token service
function verifyServiceToken(token) {
  const payload = jwt.verify(
    token,
    getSecret('JWT_SERVICE_SECRET'),
    {
      algorithms: ['HS256'],
      issuer: JWT_ISSUER
    }
  );

  if (
    payload.token_use !== 'service' ||
    payload.role !== 'service' ||
    !payload.sub
  ) {
    throw new Error('Service token tidak valid.');
  }

  return payload;
}

// Memeriksa apakah request membawa token user atau service
function verifyBearerToken(token) {
  const decoded = jwt.decode(token);

  if (!decoded || typeof decoded !== 'object') {
    throw new Error('Token tidak valid.');
  }

  if (decoded.token_use === 'access') {
    return verifyAccessToken(token);
  }

  if (decoded.token_use === 'service') {
    return verifyServiceToken(token);
  }

  throw new Error('Jenis token tidak dikenali.');
}

// Hash password
function hashPassword(password) {
  return bcrypt.hash(password, 10);
}

// Verifikasi password
function verifyPassword(password, hash) {
  return bcrypt.compare(password, hash);
}

// Membandingkan secret secara aman
function safeCompare(provided, expected) {
  if (typeof provided !== 'string' ||
      typeof expected !== 'string') {
    return false;
  }

  const a = Buffer.from(provided);
  const b = Buffer.from(expected);

  if (a.length !== b.length) {
    return false;
  }

  return crypto.timingSafeEqual(a, b);
}

module.exports = {
  createAccessToken,
  verifyAccessToken,
  createRefreshToken,
  hashToken,
  createServiceToken,
  verifyServiceToken,
  verifyBearerToken,
  hashPassword,
  verifyPassword,
  safeCompare
};
