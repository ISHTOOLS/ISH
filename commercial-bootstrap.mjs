import express from 'express';
import crypto from 'node:crypto';

process.env.ISHV4_NO_LISTEN = 'true';
const { app: baseApp } = await import('./server.js');
import { createIbanPaymentRouter, createPaymentOrder, getCommercialPlan, getPaymentOrder, getPaymentOrderInternal, listPaymentOrders, confirmPayment, rejectPayment } from './commercial-extensions/iban-payment.js';
import { issueSignedLicense, verifySignedLicense } from './commercial-extensions/signed-license.js';
import { getCommercialPlans } from './commercial-extensions/sales-config.js';

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
  if (token.length !== configured.length || !crypto.timingSafeEqual(Buffer.from(token), Buffer.from(configured))) return res.status(401).json({ error: 'Invalid or missing admin token' });
  next();
};

const app = express();
app.use(express.json({ limit: process.env.BODY_LIMIT || '2mb' }));

app.get('/api/commercial/plans', (req, res) => {
  try {
    const plans = getCommercialPlans();
    if (!plans.length) return res.status(503).json({ error: 'Commercial plans are not configured' });
    res.json({ plans });
  } catch (error) {
    res.status(503).json({ error: error.message });
  }
});

app.post('/api/payments/iban/orders', (req, res) => {
  try {
    const body = req.body || {};
    const plan = getCommercialPlan(body.planId);
    if (!plan) return res.status(503).json({ error: 'Selected commercial plan is not configured' });
    const order = createPaymentOrder({ ...body, amount: plan.amount, durationDays: plan.durationDays });
    res.status(201).json({ order, instructions: 'Transfer the exact amount using the displayed reference in the bank transfer description.' });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.get('/api/payments/iban/orders/:id', (req, res) => {
  const order = getPaymentOrder(req.params.id);
  if (!order) return res.status(404).json({ error: 'payment order not found' });
  res.json(order);
});

app.get('/api/admin/payments/iban/orders', requireAdmin, (req, res) => {
  res.json({ orders: listPaymentOrders({ status: req.query.status || undefined }) });
});

app.post('/api/payments/iban/orders/:id/confirm', requireAdmin, (req, res) => {
  try {
    const adminId = req.actorId || req.adminId || req.user?.id;
    const order = confirmPayment({ id: req.params.id, adminId, receivedAmount: req.body?.receivedAmount });
    const license = issueSignedLicense({ order: getPaymentOrderInternal(req.params.id) });
    res.json({ order, license });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.post('/api/payments/iban/orders/:id/reject', requireAdmin, (req, res) => {
  try {
    res.json(rejectPayment({ id: req.params.id, adminId: req.actorId || req.adminId || req.user?.id, reason: req.body?.reason }));
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.post('/api/licenses/verify', (req, res) => {
  try {
    const { token, hwid } = req.body || {};
    if (!token) return res.status(400).json({ valid: false, reason: 'token is required' });
    const result = verifySignedLicense(token);
    if (!result.valid) return res.json(result);
    if (hwid && result.payload.hwid !== hwid) return res.json({ valid: false, reason: 'HWID mismatch' });
    res.json(result);
  } catch {
    res.status(503).json({ valid: false, reason: 'License verification is not configured' });
  }
});

app.use(createIbanPaymentRouter({ express, requireAdmin, issueLicense: issueSignedLicense }));
app.use(baseApp);

let httpServer = null;
if (process.env.ISHV4_NO_LISTEN !== 'true') {
  const port = Number(process.env.PORT || 4000);
  httpServer = app.listen(port, () => console.log(`ISH commercial runtime listening on http://localhost:${port}`));
}

export { app, baseApp, httpServer };
