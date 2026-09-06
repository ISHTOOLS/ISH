function parsePlans() {
  const raw = process.env.ISH_PLANS_JSON?.trim();
  if (!raw) return [];
  const parsed = JSON.parse(raw);
  if (!Array.isArray(parsed) || parsed.length === 0) throw new Error('ISH_PLANS_JSON must be a non-empty JSON array');
  return parsed.map((plan) => {
    if (!plan?.id || !Number.isFinite(Number(plan.amount)) || Number(plan.amount) <= 0 || !Number.isInteger(Number(plan.durationDays)) || Number(plan.durationDays) <= 0) {
      throw new Error('Each commercial plan requires id, positive amount and positive integer durationDays');
    }
    return {
      id: String(plan.id),
      name: String(plan.name || plan.id),
      amount: Math.round(Number(plan.amount) * 100) / 100,
      durationDays: Number(plan.durationDays),
      currency: String(plan.currency || process.env.ISH_PAYMENT_CURRENCY || 'TRY')
    };
  });
}

export function getCommercialPlans() {
  return parsePlans();
}

export function getCommercialPlan(planId) {
  return getCommercialPlans().find((plan) => plan.id === String(planId)) || null;
}
