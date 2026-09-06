import express from 'express';
import crypto from 'node:crypto';
import { app } from './server.js';
import { createIbanPaymentRouter } from './commercial-extensions/iban-payment.js';
import { issueSignedLicense } from './commercial-extensions/signed-license.js';
import { createLicenseRouter } from './commercial-extensions/license-router.js';

const requireAdmin = (req, res, next) => {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : '';
  const configured = process.env.ADMIN_TOKEN?.trim();
  if (process.env.STRICT_MODE === 'true') {
    if (req.userRole !== 'admin') return res.status(403).json({ error: 'Admin session required' });
    return next();
  }
  if (!configured) {
    if (process.env.DISABLE_FALLBACKS === 'true') return res.status(503).json({ error: 'Admin authentication is not configured' });
    return next();
  }
  if (token.length !== configured.length) return res.status(401).json({ error: 'Invalid or missing admin token' });
  if (!crypto.timingSafeEqual(Buffer.from(token), Buffer.from(configured))) return res.status(401).json({ error: 'Invalid or missing admin token' });
  next();
};

app.use(createIbanPaymentRouter({ express, requireAdmin, issueLicense: issueSignedLicense }));
app.use(createLicenseRouter({ express }));

export { app };
