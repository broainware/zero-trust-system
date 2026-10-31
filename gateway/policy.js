
const db = require('../shared/db');
require('dotenv').config();

function allow(reason, extra = {}) {
  return {
    allowed: true,
    decision: 'ALLOW',
    reason,
    ...extra
  };
}

function deny(reason) {
  return {
    allowed: false,
    decision: 'DENY',
    reason
  };
}

// Mengambil dan memvalidasi identitas pengguna dari database
function getUser(principal) {
  if (
    !principal ||
    principal.token_use !== 'access' ||
    !['mahasiswa', 'dosen', 'admin'].includes(principal.role)
  ) {
    return null;
  }

  const userId = Number(principal.sub);

  if (!Number.isInteger(userId) || userId <= 0) {
    return null;
  }

  const user = db.prepare(`
    SELECT id, username, role, nim
    FROM users
    WHERE id = ?
  `).get(userId);

  if (!user || user.role !== principal.role) {
    return null;
  }

  return user;
}

// Memeriksa waktu akses berdasarkan zona waktu konfigurasi
function isWithinAccessWindow(date = new Date()) {
  const timezone = process.env.TIMEZONE || 'Asia/Jakarta';
  const start = process.env.ACCESS_WINDOW_START || '07:00';
  const end = process.env.ACCESS_WINDOW_END || '21:00';

  const currentTime = new Intl.DateTimeFormat('en-GB', {
    timeZone: timezone,
    hour: '2-digit',
    minute: '2-digit',
    hourCycle: 'h23'
  }).format(date);

  return currentTime >= start && currentTime <= end;
}

// Memeriksa kepemilikan kelas oleh dosen
function isLecturerOfCourse(lecturerId, courseId) {
  return db.prepare(`
    SELECT id
    FROM courses
    WHERE id = ? AND lecturer_id = ?
  `).get(courseId, lecturerId);
}

// Memeriksa request berdasarkan kebijakan Zero Trust
function evaluatePolicy({
  method,
  path,
  principal
}) {
  const httpMethod = String(method || '').toUpperCase();
  const endpoint = String(path || '/')
    .split('?')[0]
    .replace(/\/+$/, '') || '/';

  // Kebijakan sinkronisasi khusus Service Nilai
  if (
    httpMethod === 'POST' &&
    endpoint === '/transkrip/sinkron'
  ) {
    const clientId =
      process.env.SERVICE_CLIENT_ID || 'service-nilai';

    if (
      !principal ||
      principal.role !== 'service' ||
      principal.token_use !== 'service' ||
      principal.sub !== clientId
    ) {
      return deny(
        'Sinkronisasi transkrip hanya boleh dilakukan Service Nilai.'
      );
    }

    const client = db.prepare(`
      SELECT client_id
      FROM service_clients
      WHERE client_id = ? AND is_active = 1
    `).get(clientId);

    if (!client) {
      return deny('Service client tidak terdaftar atau tidak aktif.');
    }

    return allow('Token Service Nilai valid.');
  }

  // Token service tidak boleh digunakan untuk endpoint pengguna
  if (principal && principal.role === 'service') {
    return deny('Token service tidak diizinkan untuk endpoint ini.');
  }

  // Semua endpoint pengguna memerlukan identitas valid
  const user = getUser(principal);

  if (!user) {
    return deny('Identitas pengguna tidak valid.');
  }

  // Kebijakan GET /nilai
  if (httpMethod === 'GET' && endpoint === '/nilai') {
    if (user.role === 'mahasiswa') {
      return allow(
        'Mahasiswa hanya boleh melihat nilai miliknya.',
        { scope: { studentId: user.id } }
      );
    }

    if (user.role === 'dosen') {
      return allow(
        'Dosen boleh melihat nilai kelas yang diampunya.',
        { scope: { lecturerId: user.id } }
      );
    }

    return deny('Role tidak memiliki izin melihat nilai.');
  }

  // Kebijakan PUT /nilai/:id
  const gradeMatch = endpoint.match(/^\/nilai\/(\d+)$/);

  if (httpMethod === 'PUT' && gradeMatch) {
    if (user.role !== 'dosen') {
      return deny('Hanya dosen yang boleh mengubah nilai.');
    }

    const gradeId = Number(gradeMatch[1]);

    const grade = db.prepare(`
      SELECT g.id, g.is_final, c.id AS course_id,
             c.lecturer_id
      FROM grades g
      JOIN courses c ON c.id = g.course_id
      WHERE g.id = ?
    `).get(gradeId);

    if (!grade) {
      return deny('Data nilai tidak ditemukan.');
    }

    if (grade.lecturer_id !== user.id) {
      return deny('Dosen bukan pengampu kelas tersebut.');
    }

    if (grade.is_final === 1) {
      return deny('Nilai sudah difinalisasi dan tidak dapat diubah.');
    }

    if (!isWithinAccessWindow()) {
      return deny('Perubahan nilai hanya diizinkan pukul 07.00–21.00 WIB.');
    }

    return allow('Dosen berhak mengubah nilai kelas yang diampunya.');
  }

  // Kebijakan POST /kelas/:id/finalisasi
  const classMatch = endpoint.match(
    /^\/kelas\/(\d+)\/finalisasi$/
  );

  if (httpMethod === 'POST' && classMatch) {
    if (user.role !== 'dosen') {
      return deny('Hanya dosen yang boleh memfinalisasi nilai.');
    }

    const courseId = Number(classMatch[1]);

    const course = isLecturerOfCourse(user.id, courseId);

    if (!course) {
      return deny('Dosen bukan pengampu kelas tersebut.');
    }

    if (!isWithinAccessWindow()) {
      return deny('Finalisasi hanya diizinkan pukul 07.00–21.00 WIB.');
    }

    return allow('Dosen berhak memfinalisasi kelas tersebut.');
  }

  // Kebijakan GET /transkrip/:nim
  const transcriptMatch = endpoint.match(
    /^\/transkrip\/([^/]+)$/
  );

  if (httpMethod === 'GET' && transcriptMatch) {
    const targetNim = transcriptMatch[1];

    const student = db.prepare(`
      SELECT id, nim
      FROM users
      WHERE nim = ? AND role = 'mahasiswa'
    `).get(targetNim);

    if (!student) {
      return deny('Mahasiswa dengan NIM tersebut tidak ditemukan.');
    }

    if (user.role === 'admin') {
      return allow('Admin boleh melihat seluruh transkrip.');
    }

    if (user.role === 'mahasiswa') {
      if (user.nim !== targetNim) {
        return deny('Mahasiswa hanya boleh melihat transkrip miliknya.');
      }

      return allow('NIM sesuai dengan identitas mahasiswa.');
    }

    return deny('Dosen tidak memiliki izin melihat transkrip.');
  }

  // Semua endpoint yang tidak memiliki kebijakan akan ditolak
  return deny('Tidak ada kebijakan yang mengizinkan akses ke endpoint ini.');
}

module.exports = {
  evaluatePolicy,
  isWithinAccessWindow
};
