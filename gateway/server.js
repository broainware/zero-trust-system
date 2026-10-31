
const express = require('express');
const path = require('node:path');
const dotenv = require('dotenv');

const {
  createProxyMiddleware
} = require('http-proxy-middleware');

// Memuat konfigurasi environment
dotenv.config({
  path: path.resolve(__dirname, '../.env')
});

// Import middleware keamanan
const {
  authenticateToken,
  authorizeRequest
} = require('./middleware');

const {
  verifyRegisteredDevice
} = require('./device');

// Import autentikasi
const authRouter = require('./auth');

// Membuat aplikasi Express
const app = express();

app.disable('x-powered-by');

// Memeriksa konfigurasi gateway secret
const gatewaySecret = process.env.GATEWAY_SECRET;

if (
  !gatewaySecret ||
  gatewaySecret.startsWith('change_this')
) {
  throw new Error(
    'GATEWAY_SECRET belum dikonfigurasi di file .env'
  );
}

// Endpoint pengecekan Gateway
app.get('/health', (req, res) => {
  res.status(200).json({
    success: true,
    service: 'API Gateway',
    status: 'running',
    port: Number(process.env.PORT_GATEWAY || 3000)
  });
});

// Endpoint autentikasi
// POST /auth/login
// POST /auth/refresh
// POST /auth/logout
// POST /auth/service
app.use('/auth', authRouter);

// Middleware keamanan untuk endpoint yang dilindungi
app.use(
  ['/nilai', '/kelas', '/transkrip'],
  authenticateToken,
  verifyRegisteredDevice,
  authorizeRequest
);

// Menentukan tujuan service berdasarkan endpoint
function getServiceTarget(req) {
  const pathname = new URL(
    req.originalUrl,
    'http://localhost'
  ).pathname;

  // Service Nilai
  if (
    pathname === '/nilai' ||
    pathname.startsWith('/nilai/') ||
    pathname === '/kelas' ||
    pathname.startsWith('/kelas/')
  ) {
    return `http://127.0.0.1:${
      process.env.PORT_NILAI || 3001
    }`;
  }

  // Service Transkrip
  if (
    pathname === '/transkrip' ||
    pathname.startsWith('/transkrip/')
  ) {
    return `http://127.0.0.1:${
      process.env.PORT_TRANSKRIP || 3002
    }`;
  }

  return null;
}

// Membuat proxy middleware
const proxy = createProxyMiddleware({
  // Target default, akan ditentukan kembali oleh router
  target: `http://127.0.0.1:${
    process.env.PORT_NILAI || 3001
  }`,

  // Mengarahkan request ke service yang sesuai
  router: (req) => {
    return getServiceTarget(req);
  },

  changeOrigin: true,

  // Menambahkan gateway secret pada setiap request
  on: {
    proxyReq: (proxyReq, req) => {
      proxyReq.setHeader(
        'X-Gateway-Secret',
        gatewaySecret
      );
    },

    // Menangani kesalahan komunikasi dengan service
    error: (error, req, res) => {
      console.error(
        'Gateway proxy error:',
        error.message
      );

      if (res && !res.headersSent) {
        res.writeHead(502, {
          'Content-Type': 'application/json'
        });

        res.end(JSON.stringify({
          success: false,
          message: 'Service tujuan tidak dapat dihubungi.'
        }));
      }
    }
  }
});

// Meneruskan request ke service tujuan
app.use((req, res, next) => {
  const pathname = new URL(
    req.originalUrl,
    'http://localhost'
  ).pathname;

  const protectedPath =
    pathname === '/nilai' ||
    pathname.startsWith('/nilai/') ||
    pathname === '/kelas' ||
    pathname.startsWith('/kelas/') ||
    pathname === '/transkrip' ||
    pathname.startsWith('/transkrip/');

  // Endpoint di luar daftar tidak diteruskan
  if (!protectedPath) {
    return res.status(404).json({
      success: false,
      message: 'Endpoint tidak ditemukan.'
    });
  }

  // Meneruskan request melalui proxy
  return proxy(req, res, next);
});

// Menjalankan API Gateway
const PORT = Number(
  process.env.PORT_GATEWAY || 3000
);

app.listen(PORT, () => {
  console.log('================================');
  console.log(' ZERO TRUST API GATEWAY');
  console.log('================================');
  console.log(`Gateway berjalan di port ${PORT}`);
  console.log('Policy Engine       : ACTIVE');
  console.log('Authentication     : ACTIVE');
  console.log('Device Verification: ACTIVE');
  console.log('Gateway Secret     : ACTIVE');
  console.log('================================');
});
