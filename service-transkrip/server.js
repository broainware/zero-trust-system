
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

const {
  isActiveServiceClient
} = require('../shared/service-auth');

const app = express();

app.disable('x-powered-by');
app.use(express.json({ limit: '32kb' }));

// ========================================
// HEALTH CHECK
// ========================================

app.get('/health', (req, res) => {
  res.json({
    success: true,
    service: 'Service Transkrip',
    status: 'running'
  });
});

// ========================================
// GATEWAY SECRET DAN JWT VERIFICATION
// ========================================

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

    // Memverifikasi identitas pengguna
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

// ========================================
// GET /transkrip/:nim
// MELIHAT TRANSKRIP MAHASISWA
// ========================================

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

    // Mahasiswa hanya boleh melihat transkrip sendiri
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

// ========================================
// POST /transkrip/sinkron
// SECURE TRANSCRIPT SYNCHRONIZATION
// ========================================

app.post(
  '/transkrip/sinkron',
  requireGatewayAccess,
  (req, res) => {
    try {
      const principal = req.principal;

      // Hanya Service Nilai yang boleh sinkronisasi
      if (!isActiveServiceClient(principal)) {
        return res.status(403).json({
          success: false,
          message: 'Hanya Service Nilai yang boleh melakukan sinkronisasi.'
        });
      }

      const {
        courseId,
        courseCode,
        courseName,
        results
      } = req.body || {};

      // Validasi data request
      if (
        !Number.isInteger(courseId) ||
        courseId <= 0 ||
        typeof courseCode !== 'string' ||
        !Array.isArray(results) ||
        results.length === 0
      ) {
        return res.status(400).json({
          success: false,
          message: 'Data sinkronisasi tidak lengkap atau tidak valid.'
        });
      }

      // Memastikan kelas tersedia
      const course = db.prepare(`
        SELECT id, course_code, course_name
        FROM courses
        WHERE id = ?
      `).get(courseId);

      if (
        !course ||
        course.course_code !== courseCode ||
        (courseName && course.course_name !== courseName)
      ) {
        return res.status(404).json({
          success: false,
          message: 'Data kelas tidak ditemukan atau tidak sesuai.'
        });
      }

      // Mengambil nilai yang sudah difinalisasi
      const finalizedGrades = db.prepare(`
        SELECT
          g.student_id,
          g.score,
          u.nim
        FROM grades g
        JOIN users u ON u.id = g.student_id
        WHERE g.course_id = ?
          AND g.is_final = 1
          AND u.role = 'mahasiswa'
      `).all(courseId);

      if (finalizedGrades.length !== results.length) {
        return res.status(400).json({
          success: false,
          message: 'Jumlah data sinkronisasi tidak sesuai dengan nilai final.'
        });
      }

      // Membuat pemetaan nilai berdasarkan ID mahasiswa
      const gradeMap = new Map(
        finalizedGrades.map(grade => [
          grade.student_id,
          grade
        ])
      );

      const seenStudents = new Set();

      // Memverifikasi seluruh data yang dikirim service
      for (const item of results) {
        const validItem =
          item &&
          Number.isInteger(item.studentId) &&
          typeof item.nim === 'string' &&
          Number.isFinite(item.score) &&
          item.score >= 0 &&
          item.score <= 100;

        if (
          !validItem ||
          seenStudents.has(item.studentId)
        ) {
          return res.status(400).json({
            success: false,
            message: 'Format data nilai tidak valid atau terdapat data duplikat.'
          });
        }

        seenStudents.add(item.studentId);

        const grade = gradeMap.get(item.studentId);

        if (
          !grade ||
          grade.nim !== item.nim ||
          grade.score !== item.score
        ) {
          return res.status(403).json({
            success: false,
            message: 'Data tidak sesuai dengan nilai final dalam database.'
          });
        }
      }

      // Menyimpan transkrip secara transaksional
      const synchronize = db.transaction(() => {
        const upsert = db.prepare(`
          INSERT INTO transcripts (
            student_id,
            course_id,
            score,
            finalized_at
          )
          VALUES (?, ?, ?, CURRENT_TIMESTAMP)
          ON CONFLICT(student_id, course_id)
          DO UPDATE SET
            score = excluded.score,
            finalized_at = CURRENT_TIMESTAMP
        `);

        for (const item of results) {
          upsert.run(
            item.studentId,
            courseId,
            item.score
          );
        }
      });

      synchronize();

      return res.status(200).json({
        success: true,
        message: 'Sinkronisasi transkrip berhasil.',
        course: course.course_code,
        totalSynchronized: results.length
      });

    } catch (error) {
      console.error(
        'Transcript synchronization error:',
        error.message
      );

      return res.status(500).json({
        success: false,
        message: 'Gagal melakukan sinkronisasi transkrip.'
      });
    }
  }
);

// ========================================
// ENDPOINT TIDAK DITEMUKAN
// ========================================

app.use((req, res) => {
  res.status(404).json({
    success: false,
    message: 'Endpoint Service Transkrip tidak ditemukan.'
  });
});

// ========================================
// MENJALANKAN SERVER
// ========================================

const PORT = Number(
  process.env.PORT_TRANSKRIP || 3002
);

app.listen(PORT, () => {
  console.log('================================');
  console.log(' ZERO TRUST TRANSCRIPT SERVICE');
  console.log('================================');
  console.log(`Service Transkrip berjalan di port ${PORT}`);
  console.log('Gateway Secret Verification : ACTIVE');
  console.log('JWT Verification            : ACTIVE');
  console.log('Service Authentication      : ACTIVE');
  console.log('Transcript Synchronization  : ACTIVE');
  console.log('================================');
});
