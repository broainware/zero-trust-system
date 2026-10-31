
const Database = require('better-sqlite3');
const path = require('node:path');
const fs = require('node:fs');
require('dotenv').config({
  path: path.resolve(__dirname, '../.env')
});

// Mengambil lokasi database dari environment
const configuredPath =
  process.env.DATABASE_PATH || './database/zero-trust.sqlite';

// Mengubah path menjadi lokasi absolut
const databasePath = path.isAbsolute(configuredPath)
  ? configuredPath
  : path.resolve(process.cwd(), configuredPath);

// Membuat folder database jika belum tersedia
fs.mkdirSync(path.dirname(databasePath), {
  recursive: true
});

// Membuat koneksi database
const db = new Database(databasePath);

// Mengaktifkan konfigurasi keamanan database
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

console.log('Database SQLite berhasil terhubung!');

module.exports = db;
