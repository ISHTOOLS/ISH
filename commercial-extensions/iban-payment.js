import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { getCommercialPlan, getCommercialPlans, getPaymentAccount } from './sales-config.js';

const STATUSES = Object.freeze({
  PENDING: 'PENDING',
  PAID: 'PAID',
  REJECTED: 'REJECTED',
  CANCELLED: 'CANCELLED',
  EXPIRED: 'EXPIRED'
});

function required(name) {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`${name} is required`);
  return value;
}

function dataFile() {
  const dir = process.env.ISH_PAYMENT_DATA_DIR || path.join(process.cwd(), 'data');
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  return path.join(dir, 'iban-payment-orders.json');
}

function readOrders() {
  const file = dataFile();
  if (!fs.existsSync(file)) return {};
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

function writeOrders(orders) {
  const file = dataFile();
  const temp = `${file}.${process.pid}.tmp`;
  fs.writeFileSync(temp, JSON.stringify(orders, null, 2), { mode: 0o600 });
  fs.renameSync(temp, file);
}

function normalizeAmount(value) {
  const amount = Number(value);
  if (!Number.isFinite(amount) || amount <= 0) throw new Error('amount must be a positive number');
  return Math.round(amount * 100) / 100;
}

function reference() {
  return `ISH-${crypto.randomBytes(6).toString('hex').toUpperCase()}`;
}

function safePublicOrder(order) {
  const { customerEmail, hwid, license, ...publicOrder } = order;
  return publicOrder;
}

export function getIbanPaymentConfig(currency = process.env.ISH_PAYMENT_CURRENCY || 'TRY') {
  const account = getPaymentAccount(currency);
  if (account) return account;
  if (String(currency).toUpperCase() === 'TRY') {
    return {
      currency: 'TRY',
      bank: required('ISH_PAYMENT_BANK'),
      accountName: required('ISH_PAYMENT_ACCOUNT_NAME'),
      iban: required('ISH_PAYMENT_IBAN'),
      bic: process.env.ISH_PAYMENT_BIC?.trim() || null,
      method: 'BANK_TRANSFER',
      country: process.env.ISH_PAYMENT_COUNTRY?.trim() || 'TR'
    };
  }
  throw new Error(`Payment account is not configured for ${String(currency).toUpperCase()}`);
}

export function createPaymentOrder({ customerId, customerEmail, planId, amount, hwid, durationDays, currency }) {
  if (!customerId || !planId || !hwid) throw new Error('customerId, planId and hwid are required');
  const configuredPlan = getCommercialPlan(planId);
  if (!configuredPlan) throw new Error('commercial plan is not configured');
  const orderCurrency = String(currency || configuredPlan.currency).toUpperCase();
  if (orderCurrency !== configuredPlan.currency) throw new Error('currency does not match the configured plan');
  const payment = getIbanPaymentConfig(orderCurrency);
  const normalizedAmount = normalizeAmount(configuredPlan?.amount ?? amount);
  const days = Number(configuredPlan?.durationDays ?? durationDays);
  if (!Number.isInteger(days) || days <= 0) throw new Error('durationDays must be a positive integer');
  if (configuredPlan && normalizeAmount(amount ?? configuredPlan.amount) !== configuredPlan.amount) throw new Error('amount does not match the configured plan');

  const now = new Date();
  const order = {
    id: crypto.randomUUID(),
    reference: reference(),
    customerId,
    customerEmail: customerEmail || null,
    planId,
    amount: normalizedAmount,
    currency: orderCurrency,
    hwid,
    durationDays: days,
    paymentAccount: orderCurrency,
    status: STATUSES.PENDING,
    createdAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + 24 * 60 * 60 * 1000).toISOString(),
    paidAt: null,
    confirmedBy: null,
    confirmedAt: null,
    rejectedReason: null,
    license: null
  };

  const orders = readOrders();
  orders[order.id] = order;
  writeOrders(orders);
  return safePublicOrder({ ...order, payment });
}

export function getPaymentOrder(id) {
  const order = readOrders()[id];
  if (!order) return null;
  return safePublicOrder({ ...order, payment: getIbanPaymentConfig(order.currency) });
}

export function getPaymentOrderInternal(id) {
  return readOrders()[id] || null;
}

export function listPaymentOrders({ status } = {}) {
  return Object.values(readOrders()).filter((order) => !status || order.status === status).sort((a, b) => b.createdAt.localeCompare(a.createdAt)).map(safePublicOrder);
}

export function confirmPayment({ id, adminId, receivedAmount }) {
  if (!adminId) throw new Error('adminId is required');
  const orders = readOrders();
  const order = orders[id];
  if (!order) throw new Error('payment order not found');
  if (order.status === STATUSES.PAID) return safePublicOrder(order);
  if (order.status !== STATUSES.PENDING) throw new Error(`order cannot be confirmed from ${order.status}`);
  const amount = normalizeAmount(receivedAmount);
  if (amount !== order.amount) throw new Error('received amount does not match order amount');
  const now = new Date().toISOString();
  order.status = STATUSES.PAID;
  order.paidAt = now;
  order.confirmedAt = now;
  order.confirmedBy = adminId;
  writeOrders(orders);
  return safePublicOrder(order);
}

export function rejectPayment({ id, adminId, reason }) {
  if (!adminId) throw new Error('adminId is required');
  const orders = readOrders();
  const order = orders[id];
  if (!order) throw new Error('payment order not found');
  if (order.status !== STATUSES.PENDING) throw new Error(`order cannot be rejected from ${order.status}`);
  order.status = STATUSES.REJECTED;
  order.confirmedBy = adminId;
  order.confirmedAt = new Date().toISOString();
  order.rejectedReason = reason || 'Payment could not be verified';
  writeOrders(orders);
  return safePublicOrder(order);
}

export function createIbanPaymentRouter({ express, requireAdmin, issueLicense }) {
  if (!express?.Router) throw new Error('express Router is required');
  const router = express.Router();
  router.get('/commercial/plans', (req, res) => {
    try { const plans = getCommercialPlans(); if (!plans.length) return res.status(503).json({ error: 'Commercial plans are not configured' }); res.json({ plans }); }
    catch (error) { res.status(503).json({ error: error.message }); }
  });
  router.post('/payments/iban/orders', (req, res) => {
    try { const body = req.body || {}; const plan = getCommercialPlan(body.planId); if (!plan) return res.status(503).json({ error: 'Selected commercial plan is not configured' }); const order = createPaymentOrder({ ...body, amount: plan.amount, durationDays: plan.durationDays, currency: plan.currency }); res.status(201).json({ order, instructions: 'Transfer the exact amount in the order currency using the displayed reference in the bank transfer description.' }); }
    catch (error) { res.status(400).json({ error: error.message }); }
  });
  router.get('/payments/iban/orders/:id', (req, res) => { const order = getPaymentOrder(req.params.id); if (!order) return res.status(404).json({ error: 'payment order not found' }); res.json(order); });
  router.get('/admin/payments/iban/orders', requireAdmin, (req, res) => { res.json({ orders: listPaymentOrders({ status: req.query.status || undefined }) }); });
  router.post('/payments/iban/orders/:id/confirm', requireAdmin, (req, res) => { try { const adminId = req.actorId || req.adminId || req.user?.id; const publicOrder = confirmPayment({ id: req.params.id, adminId, receivedAmount: req.body?.receivedAmount }); const internalOrder = getPaymentOrderInternal(req.params.id); const license = issueLicense(internalOrder); res.json({ order: publicOrder, license }); } catch (error) { res.status(400).json({ error: error.message }); } });
  router.post('/payments/iban/orders/:id/reject', requireAdmin, (req, res) => { try { res.json(rejectPayment({ id: req.params.id, adminId: req.actorId || req.adminId || req.user?.id, reason: req.body?.reason })); } catch (error) { res.status(400).json({ error: error.message }); } });
  return router;
}

export { STATUSES as IBAN_PAYMENT_STATUSES };
