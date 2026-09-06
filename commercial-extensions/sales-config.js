const DEFAULT_PLANS = Object.freeze([
  { id: 'starter-try', name: 'Starter', amount: 2490, durationDays: 30, currency: 'TRY' },
  { id: 'professional-try', name: 'Professional', amount: 5990, durationDays: 365, currency: 'TRY' },
  { id: 'enterprise-try', name: 'Enterprise', amount: 14990, durationDays: 365, currency: 'TRY' },
  { id: 'starter-eur', name: 'Starter', amount: 79, durationDays: 30, currency: 'EUR' },
  { id: 'professional-eur', name: 'Professional', amount: 199, durationDays: 365, currency: 'EUR' },
  { id: 'enterprise-eur', name: 'Enterprise', amount: 499, durationDays: 365, currency: 'EUR' },
  { id: 'starter-usd', name: 'Starter', amount: 89, durationDays: 30, currency: 'USD' },
  { id: 'professional-usd', name: 'Professional', amount: 219, durationDays: 365, currency: 'USD' },
  { id: 'enterprise-usd', name: 'Enterprise', amount: 549, durationDays: 365, currency: 'USD' }
]);

function parsePlans() {
  const raw = process.env.ISH_PLANS_JSON?.trim();
  const parsed = raw ? JSON.parse(raw) : DEFAULT_PLANS;
  if (!Array.isArray(parsed) || parsed.length === 0) {
    throw new Error('ISH_PLANS_JSON must be a non-empty JSON array');
  }
  return parsed.map((plan) => {
    if (!plan?.id || !Number.isFinite(Number(plan.amount)) || Number(plan.amount) <= 0 || !Number.isInteger(Number(plan.durationDays)) || Number(plan.durationDays) <= 0) {
      throw new Error('Each commercial plan requires id, positive amount and positive integer durationDays');
    }
    return {
      id: String(plan.id),
      name: String(plan.name || plan.id),
      amount: Math.round(Number(plan.amount) * 100) / 100,
      durationDays: Number(plan.durationDays),
      currency: String(plan.currency || process.env.ISH_PAYMENT_CURRENCY || 'TRY').toUpperCase()
    };
  });
}

const PAYMENT_ACCOUNTS = {
  TRY: {
    currency: 'TRY',
    bank: 'Enpara',
    iban: 'TR800015700000000112391220',
    swift: null
  },
  EUR: {
    currency: 'EUR',
    bank: 'Enpara',
    iban: 'TR490015700000000201437778',
    swift: 'ENASTRISXXX'
  },
  USD: {
    currency: 'USD',
    bank: 'Enpara',
    iban: 'TR980015700000000205191087',
    swift: 'ENASTRISXXX'
  }
};

export function getPaymentAccounts() {
  return PAYMENT_ACCOUNTS;
}

export function getPaymentAccount(currency) {
  return PAYMENT_ACCOUNTS[String(currency).toUpperCase()] || null;
}

export function getCommercialPlans() {
  return parsePlans();
}

export function getCommercialPlan(planId) {
  return getCommercialPlans().find((plan) => plan.id === String(planId)) || null;
}
