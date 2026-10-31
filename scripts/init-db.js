
const db = require('../shared/db');
const bcrypt = require('bcryptjs');

// Membuat seluruh tabel database
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('mahasiswa', 'dosen', 'admin')),
    full_name TEXT NOT NULL,
    nim TEXT UNIQUE,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    device_id TEXT NOT NULL UNIQUE,
    device_name TEXT,
    is_active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS courses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    course_code TEXT NOT NULL UNIQUE,
    course_name TEXT NOT NULL,
    lecturer_id INTEGER NOT NULL,
    FOREIGN KEY(lecturer_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS enrollments (
    student_id INTEGER NOT NULL,
    course_id INTEGER NOT NULL,
    PRIMARY KEY(student_id, course_id),
    FOREIGN KEY(student_id) REFERENCES users(id),
    FOREIGN KEY(course_id) REFERENCES courses(id)
  );

  CREATE TABLE IF NOT EXISTS grades (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    student_id INTEGER NOT NULL,
    course_id INTEGER NOT NULL,
    score REAL NOT NULL CHECK(score >= 0 AND score <= 100),
    is_final INTEGER NOT NULL DEFAULT 0,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(student_id, course_id),
    FOREIGN KEY(student_id) REFERENCES users(id),
    FOREIGN KEY(course_id) REFERENCES courses(id)
  );

  CREATE TABLE IF NOT EXISTS transcripts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    student_id INTEGER NOT NULL,
    course_id INTEGER NOT NULL,
    score REAL NOT NULL,
    finalized_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(student_id, course_id),
    FOREIGN KEY(student_id) REFERENCES users(id),
    FOREIGN KEY(course_id) REFERENCES courses(id)
  );

  CREATE TABLE IF NOT EXISTS refresh_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at TEXT NOT NULL,
    revoked_at TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS service_clients (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id TEXT NOT NULL UNIQUE,
    client_secret_hash TEXT NOT NULL,
    is_active INTEGER NOT NULL DEFAULT 1
  );

  CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    subject TEXT NOT NULL,
    endpoint TEXT NOT NULL,
    method TEXT,
    device_id TEXT,
    decision TEXT NOT NULL CHECK(decision IN ('ALLOW', 'DENY')),
    reason TEXT NOT NULL
  );

  CREATE INDEX IF NOT EXISTS idx_devices_user
    ON devices(user_id);

  CREATE INDEX IF NOT EXISTS idx_grades_student
    ON grades(student_id);

  CREATE INDEX IF NOT EXISTS idx_courses_lecturer
    ON courses(lecturer_id);

  CREATE INDEX IF NOT EXISTS idx_audit_timestamp
    ON audit_logs(timestamp);
`);

// Data awal pengguna
const users = [
  {
    username: 'admin',
    password: 'Admin123!',
    role: 'admin',
    fullName: 'Administrator',
    nim: null,
    device: 'DEV-ADMIN-001'
  },
  {
    username: 'dosen1',
    password: 'Dosen123!',
    role: 'dosen',
    fullName: 'Dosen Informatika 1',
    nim: null,
    device: 'DEV-DOSEN-001'
  },
  {
    username: 'dosen2',
    password: 'Dosen123!',
    role: 'dosen',
    fullName: 'Dosen Informatika 2',
    nim: null,
    device: 'DEV-DOSEN-002'
  },
  {
    username: 'mhs1',
    password: 'Mahasiswa123!',
    role: 'mahasiswa',
    fullName: 'Mahasiswa 1',
    nim: '227006001',
    device: 'DEV-MHS-001'
  },
  {
    username: 'mhs2',
    password: 'Mahasiswa123!',
    role: 'mahasiswa',
    fullName: 'Mahasiswa 2',
    nim: '227006002',
    device: 'DEV-MHS-002'
  },
  {
    username: 'mhs3',
    password: 'Mahasiswa123!',
    role: 'mahasiswa',
    fullName: 'Mahasiswa 3',
    nim: '227006003',
    device: 'DEV-MHS-003'
  }
];

function seedDatabase() {
  const getUser = db.prepare(
    'SELECT id FROM users WHERE username = ?'
  );

  const insertUser = db.prepare(`
    INSERT INTO users (username, password_hash, role, full_name, nim)
    VALUES (?, ?, ?, ?, ?)
    ON CONFLICT(username) DO UPDATE SET
      password_hash = excluded.password_hash,
      role = excluded.role,
      full_name = excluded.full_name,
      nim = excluded.nim
  `);

  const insertDevice = db.prepare(`
    INSERT INTO devices (user_id, device_id, device_name)
    VALUES (?, ?, ?)
    ON CONFLICT(device_id) DO UPDATE SET
      user_id = excluded.user_id,
      device_name = excluded.device_name,
      is_active = 1
  `);

  const userIds = {};

  for (const user of users) {
    const hash = bcrypt.hashSync(user.password, 10);

    insertUser.run(
      user.username,
      hash,
      user.role,
      user.fullName,
      user.nim
    );

    const userId = getUser.get(user.username).id;
    userIds[user.username] = userId;

    insertDevice.run(
      userId,
      user.device,
      'Registered Device'
    );
  }

  const insertCourse = db.prepare(`
    INSERT INTO courses (course_code, course_name, lecturer_id)
    VALUES (?, ?, ?)
    ON CONFLICT(course_code) DO UPDATE SET
      course_name = excluded.course_name,
      lecturer_id = excluded.lecturer_id
  `);

  insertCourse.run(
    'IF101',
    'Pemrograman Web',
    userIds.dosen1
  );

  insertCourse.run(
    'IF102',
    'Keamanan Informasi',
    userIds.dosen2
  );

  const courses = db.prepare(
    'SELECT id, course_code FROM courses'
  ).all();

  const insertEnrollment = db.prepare(`
    INSERT OR IGNORE INTO enrollments (student_id, course_id)
    VALUES (?, ?)
  `);

  const insertGrade = db.prepare(`
    INSERT OR IGNORE INTO grades (student_id, course_id, score)
    VALUES (?, ?, ?)
  `);

  const students = [
    { id: userIds.mhs1, scores: [85, 90] },
    { id: userIds.mhs2, scores: [80, 88] },
    { id: userIds.mhs3, scores: [90, 78] }
  ];

  const courseIds = {
    IF101: courses.find(c => c.course_code === 'IF101').id,
    IF102: courses.find(c => c.course_code === 'IF102').id
  };

  for (const student of students) {
    const courseCodes = ['IF101', 'IF102'];

    courseCodes.forEach((code, index) => {
      const courseId = courseIds[code];

      insertEnrollment.run(student.id, courseId);
      insertGrade.run(
        student.id,
        courseId,
        student.scores[index]
      );
    });
  }

  // Menyimpan kredensial service dalam bentuk hash
  const clientId = process.env.SERVICE_CLIENT_ID || 'service-nilai';
  const clientSecret =
    process.env.SERVICE_CLIENT_SECRET || 'dev-client-secret-change-me';

  const clientHash = bcrypt.hashSync(clientSecret, 10);

  db.prepare(`
    INSERT INTO service_clients (client_id, client_secret_hash)
    VALUES (?, ?)
    ON CONFLICT(client_id) DO UPDATE SET
      client_secret_hash = excluded.client_secret_hash,
      is_active = 1
  `).run(clientId, clientHash);
}

try {
  const seed = db.transaction(seedDatabase);
  seed();

  console.log('Database berhasil diinisialisasi!');
  console.log('6 pengguna berhasil disiapkan.');
  console.log('2 kelas berhasil disiapkan.');
  console.log('Data enrollment dan nilai berhasil disiapkan.');
} catch (error) {
  console.error('Gagal menginisialisasi database:', error.message);
  process.exitCode = 1;
} finally {
  db.close();
}
