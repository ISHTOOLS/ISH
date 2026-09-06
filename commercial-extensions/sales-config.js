function parsePlans() {
  const raw = process.env.ISH_PLANS_JSON?.trim();
  if (!raw) return [];
  const parsed = JSON.parse(raw);
  if (!Array.isArray(parsed) || parsed.length === 0) throw new Error('ISH_PLANS_JSON must be a non-empty JSON array');
  return parsed.map((plan) => {
    if (!plan?.id || !Number.isFinite(Number(plan.amount)) || Number(plan.amount) <= 0 || !Number.isInteger(Number(plan.durationDays)) || Number(plan.durationDays) <= 0) {
      throw new Error('Each commercial plan requires id, positive amount and positive integer durationDays');
    }
    const currency = String(plan.currency || process.env.ISH_PAYMENT_CURRENCY || 'TRY').toUpperCase();
    if (!['TRY', 'EUR', 'USD'].includes(currency)) throw new Error(`Unsupported commercial currency: ${currency}`);
    return {
      id: String(plan.id),
      name: String(plan.name || plan.id),
      amount: Math.round(Number(plan.amount) * 100) / 100,
      durationDays: Number(plan.durationDays),
      currency
    };
  });
}

export function getCommercialPlans() {
  return parsePlans();
}

export function getCommercialPlan(planId) {
  return getCommercialPlans().find((plan) => plan.id === String(planId)) || null;
}

function parsePaymentAccounts() {
  const raw = process.env.ISH_PAYMENT_ACCOUNTS_JSON?.trim();
  if (!raw) return {};
  const parsed = JSON.parse(raw);
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('ISH_PAYMENT_ACCOUNTS_JSON must be an object');
  const accounts = {};
  for (const [currency, account] of Object.entries(parsed)) {
    const code = String(currency).toUpperCase();
    if (!['TRY', 'EUR', 'USD'].includes(code)) throw new Error(`Unsupported payment account currency: ${code}`);
    if (!account?.bank || !account?.accountName || !account?.iban) throw new Error(`${code} payment account requires bank, accountName and iban`);
    accounts[code] = {
      currency: code,
      bank: String(account.bank),
      accountName: String(account.accountName),
      iban: String(account.iban),
      bic: account.bic ? String(account.bic) : null,
      method: String(account.method || (code === 'TRY' ? 'BANK_TRANSFER' : 'SWIFT')),
      country: account.country ? String(account.country) : null
    };
  }
  return accounts;
}

export function getPaymentAccounts() {
  return parsePaymentAccounts();
}

export function getPaymentAccount(currency) {
  return getPaymentAccounts()[String(currency).toUpperCase()] || null;
}
