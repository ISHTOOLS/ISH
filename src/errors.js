/**
 * Structured error hierarchy for ISHv4-Real.
 *
 * Backward-compatible by design: the existing route wrapper in
 * server.js (`handle()`) already reads `err.statusCode` when present
 * and falls back to 400 otherwise. Every error class here sets
 * `statusCode` to the same value as `httpStatus`, so NO changes to
 * server.js's routing/response logic are required for these to work
 * correctly - existing plain `throw new Error(...)` call sites keep
 * behaving exactly as before (400, generic message), and the newly
 * wrapped ones in auth/vault/crypto-engine now carry real HTTP status
 * codes and machine-readable error codes without changing WHEN or WHY
 * an error is thrown - only WHAT it carries.
 */

export class AppError extends Error {
  constructor(message, { code = 'INTERNAL_ERROR', httpStatus = 500, isOperational = true } = {}) {
    super(message);
    this.name = this.constructor.name;
    this.code = code;
    this.httpStatus = httpStatus;
    this.statusCode = httpStatus; // alias - matches the property name server.js's handle() already reads
    this.isOperational = isOperational; // true = expected/handled condition, false = unexpected bug
    Error.captureStackTrace?.(this, this.constructor);
  }

  toJSON() {
    return { error: this.message, code: this.code };
  }
}

export class AuthError extends AppError {
  constructor(message, code = 'AUTH_ERROR') {
    super(message, { code, httpStatus: 401, isOperational: true });
  }
}

export class TenantError extends AppError {
  constructor(message, code = 'TENANT_ERROR') {
    super(message, { code, httpStatus: 403, isOperational: true });
  }
}

export class VaultError extends AppError {
  constructor(message, code = 'VAULT_ERROR', httpStatus = 400) {
    super(message, { code, httpStatus, isOperational: true });
  }
}

export class CryptoError extends AppError {
  constructor(message, code = 'CRYPTO_ERROR') {
    super(message, { code, httpStatus: 400, isOperational: true });
  }
}

export class ValidationError extends AppError {
  constructor(message, code = 'VALIDATION_ERROR') {
    super(message, { code, httpStatus: 400, isOperational: true });
  }
}

export class SystemError extends AppError {
  constructor(message, code = 'SYSTEM_ERROR') {
    super(message, { code, httpStatus: 500, isOperational: false });
  }
}
