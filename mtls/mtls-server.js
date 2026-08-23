import https from 'https';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const CERT_DIR = process.env.MTLS_CERT_DIR || path.join(__dirname, '..', 'mtls', 'certs');

/**
 * Wraps an Express app in a real mTLS HTTPS server. `requestCert: true` +
 * `rejectUnauthorized: true` means Node's TLS stack itself refuses the
 * TLS handshake for any client that doesn't present a certificate signed
 * by our CA - the request never reaches Express or any application code
 * for unauthorized clients. This is the real mechanism, not an
 * application-layer header check that could be bypassed.
 */
export function startMtlsServer(app, port) {
  const options = {
    key: fs.readFileSync(path.join(CERT_DIR, 'server.key')),
    cert: fs.readFileSync(path.join(CERT_DIR, 'server.crt')),
    ca: fs.readFileSync(path.join(CERT_DIR, 'ca.crt')),
    requestCert: true,
    rejectUnauthorized: true, // TLS handshake itself fails for untrusted/missing client certs
    minVersion: 'TLSv1.3',
  };

  const server = https.createServer(options, (req, res) => {
    // At this point the TLS handshake already succeeded, meaning the
    // client presented a cert signed by our CA. We still expose the
    // client's identity (CN) to the app for authorization decisions.
    const cert = req.socket.getPeerCertificate();
    req.mtlsClientCN = cert?.subject?.CN || null;
    app(req, res);
  });

  server.listen(port, () => {
    console.log(`[mTLS] HTTPS+client-cert-required listening on :${port}`);
  });

  return server;
}
