
const express = require('express');
const path = require('node:path');
const dotenv = require('dotenv');

dotenv.config({
  path: path.resolve(__dirname, '../.env')
});

const db = require('../shared/db');

const {
  verifyBearerToken,
  safeCompare
} = require('../shared/security');

const app = express();

app.disable('x-powered-by');
app.use(express.json({ limit: '32kb' }));

// Health check
app.get('/health', (req, res) => {
  res.json({
    success: true,
    service: 'Service Transkrip',
    status: 'running'
  });
});

// Memeriksa Gateway Secret dan JWT
function requireGatewayAccess(req, res, next) {
  const gatewaySecret = req.get('X-Gateway-Secret');

  if (!safeCompare(
    gatewaySecret,
    process.env.GATEWAY_SECRET
  )) {
    return res.status(403).json({
      success: false,
      message: 'Gateway secret tidak valid.'
    });
  }

  const authorization = req.get('Authorization') || '';
  const match = authorization.match(/^Bearer\s+(.+)$/i);

  if (!match) {
    return res.status(401).json({
      success: false,
      message: 'Authorization token wajib disertakan.'
    });
  }

  try {
    const principal = verifyBearerToken(match[1]);

    req.principal = principal;

    if (principal.token_use === 'access') {
      const user = db.prepare(`
        SELECT id, username, role, nim
        FROM users
        WHERE id = ?
      `).get(Number(principal.sub));

      if (!user || user.role !== principal.role) {
        return res.status(403).json({
          success: false,
          message: 'Identitas pengguna tidak valid.'
        });
      }

      req.user = user;
    }

    next();
  } catch (error) {
    return res.status(401).json({
      success: false,
      message: 'JWT tidak valid atau sudah kedaluwarsa.'
    });
  }
}

// GET /transkrip/:nim
app.get(
  '/transkrip/:nim',
  requireGatewayAccess,
  (req, res) => {
    const user = req.user;
    const targetNim = req.params.nim;

    if (!user || user.role === 'service') {
      return res.status(403).json({
        success: false,
        message: 'Service token tidak boleh melihat transkrip.'
      });
    }

    const student = db.prepare(`
      SELECT id, nim, full_name
      FROM users
      WHERE nim = ?
        AND role = 'mahasiswa'
    `).get(targetNim);

    if (!student) {
      return res.status(404).json({
        success: false,
        message: 'Mahasiswa tidak ditemukan.'
      });
    }

    if (
      user.role !== 'admin' &&
      user.id !== student.id
    ) {
      return res.status(403).json({
        success: false,
        message: 'Kamu hanya boleh melihat transkrip milik sendiri.'
      });
    }

    if (!['admin', 'mahasiswa'].includes(user.role)) {
      return res.status(403).json({
        success: false,
        message: 'Role tidak diizinkan melihat transkrip.'
      });
    }

    const transcripts = db.prepare(`
      SELECT
        t.id,
        c.course_code,
        c.course_name,
        t.score,
        t.finalized_at
      FROM transcripts t
      JOIN courses c ON c.id = t.course_id
      WHERE t.student_id = ?
      ORDER BY c.course_code
    `).all(student.id);

    return res.json({
      success: true,
      student: {
        nim: student.nim,
        name: student.full_name
      },
      total: transcripts.length,
      data: transcripts
    });
  }
);

// Endpoint tidak dikenal
app.use((req, res) => {
  res.status(404).json({
    success: false,
    message: 'Endpoint Service Transkrip tidak ditemukan.'
  });
});

const PORT = Number(process.env.PORT_TRANSKRIP || 3002);

app.listen(PORT, () => {
  console.log(`Service Transkrip berjalan di port ${PORT}`);
});
