import { ValidationError } from './errors.js';
import { logEvent } from './audit.js';
import { getRequestContext } from './request-context.js';
import { assertTenantAccess } from './tenant-guard.js';

/**
 * Lightweight request orchestration for critical routes.
 *
 * This utility deliberately contains no business logic. It only verifies
 * request context/tenant preconditions, delegates to the supplied handler,
 * and records a sanitized failure event before rethrowing to the existing
 * route error handler.
 *
 * Backward compatibility: when used as ordinary Express middleware, the
 * optional `next` callback is still supported. When wrapped by the existing
 * `handle()` helper, errors are rethrown so that helper retains response
 * formatting and status-code behavior.
 */
export function orchestrate(name, fn, { validate, requireTenant = false } = {}) {
  return async (req, res, next) => {
    try {
      const context = getRequestContext();
      if (!context.requestId) {
        throw new ValidationError('Request context is required', 'REQUEST_CONTEXT_REQUIRED');
      }

      if (requireTenant) {
        const requestedTenant = req.tenantId;
        assertTenantAccess(requestedTenant, { resourcePath: req.originalUrl || name });
      }

      if (validate) validate(req);
      return await fn(req, res);
    } catch (err) {
      logEvent({
        action: 'ORCHESTRATOR_ERROR',
        status: 'FAIL',
        tenantId: getRequestContext().tenantId || '',
        userId: getRequestContext().userId || 'system',
        resourcePath: req.originalUrl || name,
        errorCode: err.code || 'ORCHESTRATOR_ERROR',
      });
      if (typeof next === 'function') return next(err);
      throw err;
    }
  };
}

export function requireFields(fields) {
  return req => {
    for (const field of fields) {
      if (req.body?.[field] === undefined || req.body?.[field] === null || req.body?.[field] === '') {
        throw new ValidationError(`${field} is required`, 'REQUEST_FIELD_REQUIRED');
      }
    }
  };
}
