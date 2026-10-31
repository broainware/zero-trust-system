
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

app.use(express.json({ limit: '32kb' }));

// Endpoint health check
app.get('/health', (req, res) => {
  res.json({
    success: true,
    service: 'Service Nilai',
    status: 'running'
  });
});

// Memeriksa gateway secret dan JWT
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

    if (principal.token_use !== 'access') {
      return res.status(403).json({
        success: false,
        message: 'Service token tidak diizinkan untuk Service Nilai.'
      });
    }

    const userId = Number(principal.sub);

    const user = db.prepare(`
      SELECT id, username, role, nim
      FROM users
      WHERE id = ?
    `).get(userId);

    if (!user || user.role !== principal.role) {
      return res.status(403).json({
        success: false,
        message: 'Identitas pengguna tidak valid.'
      });
    }

    req.user = user;

    next();
  } catch (error) {
    return res.status(401).json({
      success: false,
      message: 'JWT tidak valid atau sudah kedaluwarsa.'
    });
  }
}

// Memeriksa jam akses
function isWithinAccessWindow() {
  const timezone = process.env.TIMEZONE || 'Asia/Jakarta';
  const start = process.env.ACCESS_WINDOW_START || '07:00';
  const end = process.env.ACCESS_WINDOW_END || '21:00';

  const currentTime = new Intl.DateTimeFormat('en-GB', {
    timeZone: timezone,
    hour: '2-digit',
    minute: '2-digit',
    hourCycle: 'h23'
  }).format(new Date());

  return currentTime >= start && currentTime <= end;
}

// Mengambil token khusus Service Nilai melalui Gateway
async function requestServiceToken() {
  const gatewayUrl = (
    process.env.GATEWAY_URL || 'http://localhost:3000'
  ).replace(/\/+$/, '');

  const response = await fetch(
    `${gatewayUrl}/auth/service`,
    {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        clientId: process.env.SERVICE_CLIENT_ID,
        clientSecret: process.env.SERVICE_CLIENT_SECRET
      })
    }
  );

  const data = await response.json();

  if (!response.ok || !data.accessToken) {
    throw new Error(
      data.message || 'Gagal mendapatkan service token.'
    );
  }

  return data.accessToken;
}

// Mengirim nilai final ke Service Transkrip melalui Gateway
async function synchronizeTranscript(payload) {
  const gatewayUrl = (
    process.env.GATEWAY_URL || 'http://localhost:3000'
  ).replace(/\/+$/, '');

  const serviceToken = await requestServiceToken();

  const response = await fetch(
    `${gatewayUrl}/transkrip/sinkron`,
    {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${serviceToken}`
      },
      body: JSON.stringify(payload)
    }
  );

  const responseText = await response.text();

  let data;

  try {
    data = JSON.parse(responseText);
  } catch {
    data = { message: responseText };
  }

  if (!response.ok) {
    throw new Error(
      data.message || 'Sinkronisasi transkrip gagal.'
    );
  }

  return data;
}

// Semua endpoint selain health wajib melewati verifikasi
app.use(requireGatewayAccess);

// GET /nilai
app.get('/nilai', (req, res) => {
  const user = req.user;

  if (!['mahasiswa', 'dosen'].includes(user.role)) {
    return res.status(403).json({
      success: false,
      message: 'Role tidak diizinkan melihat nilai.'
    });
  }

  let rows;

  if (user.role === 'mahasiswa') {
    rows = db.prepare(`
      SELECT
        g.id,
        g.score,
        g.is_final,
        c.id AS course_id,
        c.course_code,
        c.course_name
      FROM grades g
      JOIN courses c ON c.id = g.course_id
      WHERE g.student_id = ?
      ORDER BY c.course_code
    `).all(user.id);
  } else {
    rows = db.prepare(`
      SELECT
        g.id,
        g.score,
        g.is_final,
        u.nim,
        u.full_name AS student_name,
        c.id AS course_id,
        c.course_code,
        c.course_name
      FROM grades g
      JOIN courses c ON c.id = g.course_id
      JOIN users u ON u.id = g.student_id
      WHERE c.lecturer_id = ?
      ORDER BY c.course_code, u.nim
    `).all(user.id);
  }

  return res.json({
    success: true,
    total: rows.length,
    data: rows
  });
});

// PUT /nilai/:id
app.put('/nilai/:id', (req, res) => {
  const user = req.user;
  const gradeId = Number(req.params.id);
  const score = req.body.score;

  if (user.role !== 'dosen') {
    return res.status(403).json({
      success: false,
      message: 'Hanya dosen yang boleh mengubah nilai.'
    });
  }

  if (
    !Number.isInteger(gradeId) ||
    !Number.isFinite(score) ||
    score < 0 ||
    score > 100
  ) {
    return res.status(400).json({
      success: false,
      message: 'ID atau nilai tidak valid. Nilai harus 0–100.'
    });
  }

  const grade = db.prepare(`
    SELECT
      g.id,
      g.is_final,
      c.lecturer_id
    FROM grades g
    JOIN courses c ON c.id = g.course_id
    WHERE g.id = ?
  `).get(gradeId);

  if (!grade) {
    return res.status(404).json({
      success: false,
      message: 'Data nilai tidak ditemukan.'
    });
  }

  if (grade.lecturer_id !== user.id) {
    return res.status(403).json({
      success: false,
      message: 'Kamu bukan dosen pengampu kelas ini.'
    });
  }

  if (grade.is_final === 1) {
    return res.status(403).json({
      success: false,
      message: 'Nilai sudah difinalisasi.'
    });
  }

  if (!isWithinAccessWindow()) {
    return res.status(403).json({
      success: false,
      message: 'Perubahan nilai hanya diizinkan pukul 07.00–21.00 WIB.'
    });
  }

  db.prepare(`
    UPDATE grades
    SET score = ?, updated_at = CURRENT_TIMESTAMP
    WHERE id = ? AND is_final = 0
  `).run(score, gradeId);

  return res.json({
    success: true,
    message: 'Nilai berhasil diperbarui.',
    data: {
      gradeId,
      score
    }
  });
});

// POST /kelas/:id/finalisasi
app.post('/kelas/:id/finalisasi', async (req, res) => {
  try {
    const user = req.user;
    const courseId = Number(req.params.id);

    if (user.role !== 'dosen') {
      return res.status(403).json({
        success: false,
        message: 'Hanya dosen yang boleh memfinalisasi nilai.'
      });
    }

    if (!Number.isInteger(courseId) || courseId <= 0) {
      return res.status(400).json({
        success: false,
        message: 'ID kelas tidak valid.'
      });
    }

    const course = db.prepare(`
      SELECT id, course_code, course_name, lecturer_id
      FROM courses
      WHERE id = ?
    `).get(courseId);

    if (!course) {
      return res.status(404).json({
        success: false,
        message: 'Kelas tidak ditemukan.'
      });
    }

    if (course.lecturer_id !== user.id) {
      return res.status(403).json({
        success: false,
        message: 'Kamu bukan dosen pengampu kelas ini.'
      });
    }

    if (!isWithinAccessWindow()) {
      return res.status(403).json({
        success: false,
        message: 'Finalisasi hanya diizinkan pukul 07.00–21.00 WIB.'
      });
    }

    // Finalisasi dilakukan secara transaksional
    const finalizeGrades = db.transaction(() => {
      db.prepare(`
        UPDATE grades
        SET is_final = 1,
            updated_at = CURRENT_TIMESTAMP
        WHERE course_id = ?
      `).run(courseId);

      return db.prepare(`
        SELECT
          u.id AS studentId,
          u.nim,
          g.score
        FROM grades g
        JOIN users u ON u.id = g.student_id
        WHERE g.course_id = ?
        ORDER BY u.nim
      `).all(courseId);
    });

    const results = finalizeGrades();

    if (results.length === 0) {
      return res.status(400).json({
        success: false,
        message: 'Belum ada nilai mahasiswa untuk difinalisasi.'
      });
    }

    // Sinkronisasi melalui API Gateway
    const synchronization = await synchronizeTranscript({
      courseId: course.id,
      courseCode: course.course_code,
      courseName: course.course_name,
      results
    });

    return res.json({
      success: true,
      message: 'Nilai berhasil difinalisasi dan disinkronkan.',
      course: course.course_code,
      totalStudents: results.length,
      synchronization
    });
  } catch (error) {
    console.error('Finalization error:', error.message);

    return res.status(502).json({
      success: false,
      finalized: true,
      message: 'Nilai sudah difinalisasi, tetapi sinkronisasi transkrip gagal.',
      detail: error.message
    });
  }
});

// Error handler
app.use((err, req, res, next) => {
  console.error('Service Nilai error:', err.message);

  if (res.headersSent) {
    return next(err);
  }

  res.status(500).json({
    success: false,
    message: 'Terjadi kesalahan pada Service Nilai.'
  });
});

const PORT = Number(process.env.PORT_NILAI || 3001);

app.listen(PORT, () => {
  console.log(`Service Nilai berjalan di port ${PORT}`);
});
