# Verification

Run on a clean machine with Node.js >=18:

```bash
npm ci
npm test
npm run check
```

For live service verification:

```bash
npm start
```

Then check `/health`, `/ready`, `/metrics`, `/api/audit/verify` and the configured ISHLOCK/security endpoints.
