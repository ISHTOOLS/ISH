import { TenantError } from './errors.js';
import { getRequestContext } from './request-context.js';
import { logEvent } from './audit.js';

function deny(req, code, message) {
  const context = getRequestContext();
  logEvent({
    action: 'TENANT_ACCESS_DENIED',
    status: 'FAIL',
    resourcePath: req.originalUrl || req.path || 'tenant-context',
    tenantId: context.tenantId || '',
    userId: context.userId || 'system',
    errorCode: code,
    details: message,
  });
  return new TenantError(message, code);
}

export function assertTenantAccess(requestedTenantId, { resourcePath = 'vault', allowMissingContext = false } = {}) {
  const context = getRequestContext();
  const trustedTenant = context.tenantId == null ? null : String(context.tenantId);
  const requested = String(requestedTenantId ?? '').trim();

  if (!trustedTenant) {
    if (allowMissingContext && requested && context.requestId === 'system') return requested;
    const error = new TenantError('Trusted tenant context is required', 'TENANT_CONTEXT_REQUIRED');
    logEvent({
      action: 'TENANT_ACCESS_DENIED',
      status: 'FAIL',
      resourcePath,
      tenantId: '',
      userId: context.userId || 'system',
      errorCode: error.code,
      details: 'trusted tenant context required',
    });
    throw error;
  }

  if (!requested || requested !== trustedTenant) {
    const error = new TenantError('Tenant context mismatch', 'TENANT_CONTEXT_MISMATCH');
    logEvent({
      action: 'TENANT_ACCESS_DENIED',
      status: 'FAIL',
      resourcePath,
      tenantId: trustedTenant,
      userId: context.userId || 'system',
      errorCode: error.code,
      details: 'tenant access denied',
    });
    throw error;
  }

  return trustedTenant;
}

export function tenantGuard(req, res, next) {
  const context = getRequestContext();
  const trustedTenant = context.tenantId == null ? null : String(context.tenantId);
  const requested = String(req.headers?.['x-tenant-id'] || '').trim();

  if (!trustedTenant) {
    return next(deny(req, 'TENANT_CONTEXT_REQUIRED', 'Trusted tenant context is required'));
  }

  if (requested && requested !== trustedTenant) {
    return next(deny(req, 'TENANT_CONTEXT_MISMATCH', 'Requested tenant does not match trusted tenant context'));
  }

  if (req.sessionTenantId && req.sessionTenantId !== trustedTenant) {
    return next(deny(req, 'TENANT_CONTEXT_MISMATCH', 'Authenticated tenant does not match trusted tenant context'));
  }

  req.tenantId = trustedTenant;
  next();
}
