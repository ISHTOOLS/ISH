function parsePlans() {
  const raw = process.env.ISH_PLANS_JSON?.trim();
  if (!raw) return [];

  const parsed = JSON.parse(raw);

  if (!Array.isArray(parsed) || parsed.length === 0) {
    throw new Error('ISH_PLANS_JSON must be a non-empty JSON array');
  }

  return parsed.map((plan) => {
    if (
      !plan?.id ||
      !Number.isFinite(Number(plan.amount)) ||
      Number(plan.amount) <= 0 ||
      !Number.isInteger(Number(plan.durationDays)) ||
      Number(plan.durationDays) <= 0
    ) {
      throw new Error(
        'Each commercial plan requires id, positive amount and positive integer durationDays'
      );
    }

    return {
      id: String(plan.id),
      name: String(plan.name || plan.id),
      amount: Math.round(Number(plan.amount) * 100) / 100,
      durationDays: Number(plan.durationDays),
      currency: String(
        plan.currency || process.env.ISH_PAYMENT_CURRENCY || 'TRY'
      )
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
  return getCommercialPlans().find(
    (plan) => plan.id === String(planId)
  ) || null;
}
