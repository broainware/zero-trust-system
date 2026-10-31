
const path = require('node:path');
const dotenv = require('dotenv');

dotenv.config({
  path: path.resolve(__dirname, '../.env')
});

const db = require('./db');

// Memeriksa apakah service mempunyai izin aktif
function isActiveServiceClient(principal) {
  if (
    !principal ||
    principal.token_use !== 'service' ||
    principal.role !== 'service'
  ) {
    return false;
  }

  const expectedClientId =
    process.env.SERVICE_CLIENT_ID || 'service-nilai';

  if (principal.sub !== expectedClientId) {
    return false;
  }

  const client = db.prepare(`
    SELECT client_id
    FROM service_clients
    WHERE client_id = ?
      AND is_active = 1
  `).get(principal.sub);

  return Boolean(client);
}

module.exports = {
  isActiveServiceClient
};
