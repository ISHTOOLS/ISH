import { AsyncLocalStorage } from 'node:async_hooks';
import crypto from 'node:crypto';

const storage = new AsyncLocalStorage();

function createRequestId() {
  return crypto.randomUUID();
}

export function createRequestContext(req) {
  const requestId = createRequestId();
  const tenantId = req.tenantId == null ? null : String(req.tenantId);
  const userId = req.actorId == null ? null : String(req.actorId);
  return Object.freeze({ requestId, tenantId, userId });
}

export function requestContextMiddleware(req, res, next) {
  const ctx = createRequestContext(req);
  req.requestId = ctx.requestId;
  res.setHeader('X-Request-ID', ctx.requestId);
  storage.run(ctx, next);
}

export function getRequestContext() {
  return storage.getStore() || { requestId: 'system', tenantId: null, userId: 'system' };
}
