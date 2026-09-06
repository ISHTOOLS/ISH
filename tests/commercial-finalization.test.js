import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

process.env.ISH_PAYMENT_IBAN_TRY = 'TR000000000000000000000000';
process.env.ISH_PAYMENT_IBAN_EUR = 'TR000000000000000000000001';
process.env.ISH_PAYMENT_IBAN_USD = 'TR000000000000000000000002';

const { getCommercialPlans, getCommercialPlan, getPaymentAccount } = await import('../commercial-extensions/sales-config.js');
const { createPaymentOrder, getPaymentOrder } = await import('../commercial-extensions/iban-payment.js');

test('commercial catalog exposes TRY EUR USD plans', () => {
  const plans = getCommercialPlans();
  assert.equal(plans.length, 9);
  assert.deepEqual(new Set(plans.map((p) => p.currency)), new Set(['TRY', 'EUR', 'USD']));
  for (const plan of plans) {
    assert.ok(plan.amount > 0);
    assert.ok(plan.durationDays > 0);
  }
});

test('payment accounts expose the expected currency routing', () => {
  assert.equal(getPaymentAccount('TRY').currency, 'TRY');
  assert.equal(getPaymentAccount('EUR').currency, 'EUR');
  assert.equal(getPaymentAccount('USD').currency, 'USD');
  assert.equal(getPaymentAccount('TRY').swift, null);
  assert.equal(getPaymentAccount('EUR').swift, 'ENASTRISXXX');
  assert.equal(getPaymentAccount('USD').swift, 'ENASTRISXXX');
});

test('payment order binds exact plan amount, currency and payment account', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ish-commercial-final-'));
  const previous = process.env.ISH_PAYMENT_DATA_DIR;
  process.env.ISH_PAYMENT_DATA_DIR = dir;
  try {
    const plan = getCommercialPlan('professional-eur');
    const order = createPaymentOrder({
      customerId: 'customer-test',
      customerEmail: 'test@example.invalid',
      planId: plan.id,
      amount: plan.amount,
      hwid: 'hwid-test'
    });
    assert.equal(order.amount, plan.amount);
    assert.equal(order.currency, 'EUR');
    assert.equal(order.payment.currency, 'EUR');
    assert.equal(order.payment.swift, 'ENASTRISXXX');
    assert.equal(order.payment.iban, 'TR000000000000000000000001');
    const loaded = getPaymentOrder(order.id);
    assert.equal(loaded.currency, 'EUR');
    assert.equal(loaded.payment.swift, 'ENASTRISXXX');
  } finally {
    if (previous === undefined) delete process.env.ISH_PAYMENT_DATA_DIR;
    else process.env.ISH_PAYMENT_DATA_DIR = previous;
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
