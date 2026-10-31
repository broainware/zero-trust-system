const express = require('express');
const path = require('node:path');
const dotenv = require('dotenv');
const {
  createProxyMiddleware
} = require('http-proxy-middleware');

dotenv.config({
  path: path.resolve(__dirname, '../.env')
});

const {
  authenticateToken,
  authorizeRequest
} = require('./middleware');

const app = express();

// Endpoint pengecekan Gateway
app.get('/health', (req, res) => {
  res.json({
    success: true,
    service: 'API Gateway',
    status: 'running'
  });
});

// Middleware autentikasi dan otorisasi
app.use(
  ['/nilai', '/kelas', '/transkrip'],
  authenticateToken,
  authorizeRequest
);

// Proxy ke masing-masing service
const proxy = createProxyMiddleware({
  router: (req) => {
    const pathname = new URL(
      req.originalUrl,
      'http://localhost'
    ).pathname;

    if (
      pathname === '/nilai' ||
      pathname.startsWith('/nilai/') ||
      pathname === '/kelas' ||
      pathname.startsWith('/kelas/')
    ) {
      return `http://127.0.0.1:${process.env.PORT_NILAI || 3001}`;
    }

    if (
      pathname === '/transkrip' ||
      pathname.startsWith('/transkrip/')
    ) {
      return `http://127.0.0.1:${process.env.PORT_TRANSKRIP || 3002}`;
    }

    return `http://127.0.0.1:${process.env.PORT_NILAI || 3001}`;
  },

  changeOrigin: true,

  on: {
    proxyReq: (proxyReq) => {
      const secret = process.env.GATEWAY_SECRET;

      if (!secret || secret.startsWith('change_this')) {
        throw new Error('Gateway secret belum dikonfigurasi.');
      }

      proxyReq.setHeader('X-Gateway-Secret', secret);
    },

    error: (error, req, res) => {
      console.error('Gateway proxy error:', error.message);

      if (!res.headersSent) {
        res.status(502).json({
          success: false,
          message: 'Service tujuan tidak dapat dihubungi.'
        });
      }
    }
  }
});

// Meneruskan request sesuai tujuan
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

  if (protectedPath) {
    return proxy(req, res, next);
  }

  return res.status(404).json({
    success: false,
    message: 'Endpoint tidak ditemukan.'
  });
});

const PORT = Number(process.env.PORT_GATEWAY || 3000);

app.listen(PORT, () => {
  console.log(`API Gateway berjalan di port ${PORT}`);
});