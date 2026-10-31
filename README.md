
# Zero Trust Security - Sistem Nilai

Implementasi Zero Trust Security pada Sistem Informasi Nilai Mahasiswa menggunakan Node.js, Express.js, SQLite, dan JSON Web Token (JWT).

## 1. Deskripsi Project

Project ini merupakan implementasi konsep Zero Trust Security pada sistem pengelolaan nilai mahasiswa.

Sistem menerapkan prinsip Never Trust, Always Verify dengan memeriksa identitas pengguna, perangkat, hak akses, dan konteks setiap permintaan.

## 2. Teknologi

- Node.js
- Express.js
- SQLite
- JSON Web Token (JWT)
- bcryptjs
- http-proxy-middleware
- dotenv
- Thunder Client / Postman

## 3. Arsitektur Sistem

Sistem terdiri dari tiga aplikasi backend:

| Komponen | Port | Fungsi |
|---|---:|---|
| API Gateway | 3000 | Policy Enforcement Point |
| Service Nilai | 3001 | Pengelolaan nilai |
| Service Transkrip | 3002 | Pengelolaan transkrip |

Database SQLite digunakan bersama oleh kedua service.

Seluruh request pengguna harus melewati API Gateway.

## 4. Struktur Folder

```text
zero-trust-system/
├── gateway/
│   ├── server.js
│   ├── middleware.js
│   ├── auth.js
│   ├── device.js
│   └── policy.js
├── service-nilai/
│   └── server.js
├── service-transkrip/
│   └── server.js
├── shared/
│   ├── db.js
│   ├── security.js
│   ├── audit.js
│   └── service-auth.js
├── database/
├── scripts/
│   └── init-db.js
├── postman/
│   └── zero-trust-system.postman_collection.json
├── .env.example
├── .gitignore
├── package.json
└── README.md
```

## 5. Instalasi

Pastikan Node.js minimal versi 18 sudah terinstal.

Clone repository:

```bash
git clone https://github.com/USERNAME/zero-trust-system.git
cd zero-trust-system
```

Instal dependency:

```bash
npm install
```

Salin file konfigurasi:

Windows PowerShell:

```powershell
Copy-Item .env.example .env
```

Sesuaikan nilai secret di file `.env`.

Inisialisasi database:

```bash
npm run init-db
```

## 6. Menjalankan Aplikasi

Jalankan seluruh aplikasi:

```bash
npm run dev
```

Ketiga service akan berjalan pada:

- Gateway: http://localhost:3000
- Service Nilai: http://localhost:3001
- Service Transkrip: http://localhost:3002

Pemeriksaan Gateway:

```text
GET http://localhost:3000/health
```

## 7. Akun Pengujian

| Role | Username | Password | Device ID |
|---|---|---|---|
| Admin | admin | Admin123! | DEV-ADMIN-001 |
| Dosen 1 | dosen1 | Dosen123! | DEV-DOSEN-001 |
| Dosen 2 | dosen2 | Dosen123! | DEV-DOSEN-002 |
| Mahasiswa 1 | mhs1 | Mahasiswa123! | DEV-MHS-001 |
| Mahasiswa 2 | mhs2 | Mahasiswa123! | DEV-MHS-002 |
| Mahasiswa 3 | mhs3 | Mahasiswa123! | DEV-MHS-003 |

Data akun tersebut hanya digunakan untuk demonstrasi lokal.

## 8. Daftar Endpoint

| Method | Endpoint | Fungsi |
|---|---|---|
| POST | /auth/login | Login pengguna |
| POST | /auth/refresh | Memperbarui token |
| POST | /auth/logout | Mencabut refresh token |
| POST | /auth/service | Autentikasi service |
| GET | /nilai | Melihat nilai |
| PUT | /nilai/:id | Mengubah nilai |
| POST | /kelas/:id/finalisasi | Finalisasi nilai |
| GET | /transkrip/:nim | Melihat transkrip |
| POST | /transkrip/sinkron | Sinkronisasi transkrip |

## 9. Implementasi Keamanan

### Authentication

Menggunakan JWT dengan access token 10 menit dan refresh token 1 hari.

### Least Privilege

Mahasiswa hanya dapat mengakses nilai dan transkrip miliknya sendiri. Dosen hanya dapat mengelola kelas yang diampunya.

### Device Verification

Setiap request pengguna wajib membawa X-Device-ID yang terdaftar.

### Time-Based Access

Perubahan dan finalisasi nilai dibatasi pukul 07.00–21.00 WIB.

### Gateway Secret

Setiap request dari API Gateway menuju service membawa header X-Gateway-Secret.

### Service Authentication

Komunikasi antar-service menggunakan token khusus dengan masa berlaku 5 menit.

### Audit Logging

Setiap keputusan akses dicatat dengan hasil ALLOW atau DENY beserta alasan.

## 10. Pengujian

Pengujian API dapat dilakukan menggunakan Postman atau Thunder Client.

Koleksi pengujian tersedia di folder postman.

Skenario pengujian mencakup:
- Login berhasil dan gagal.
- Device ID terdaftar dan tidak terdaftar.
- Pemeriksaan hak akses mahasiswa.
- Pemeriksaan hak akses dosen.
- Pembatasan perubahan nilai.
- Finalisasi nilai.
- Sinkronisasi transkrip.
- Verifikasi gateway secret.
- Pencabutan refresh token.
- Pemeriksaan audit log.

## 11. Prinsip Zero Trust

Project menerapkan tiga prinsip utama:

1. Verify Explicitly: setiap akses harus diverifikasi.
2. Least Privilege: pengguna hanya memperoleh akses sesuai kewenangannya.
3. Assume Breach: sistem membatasi akses dan mencatat aktivitas untuk mengurangi dampak insiden keamanan.

## 12. Demonstrasi

Video demonstrasi menjelaskan arsitektur sistem, implementasi keamanan, autentikasi, pengujian hak akses, sinkronisasi transkrip, serta audit log.
