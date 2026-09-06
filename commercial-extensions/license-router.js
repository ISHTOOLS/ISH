import { verifySignedLicense } from './signed-license.js';

export function createLicenseRouter({ express }) {
  if (!express?.Router) throw new Error('express Router is required');
  const router = express.Router();

  router.post('/licenses/verify', (req, res) => {
    try {
      const { token, hwid } = req.body || {};
      if (!token) return res.status(400).json({ valid: false, reason: 'token is required' });
      const result = verifySignedLicense(token);
      if (!result.valid) return res.status(200).json(result);
      if (hwid && result.payload.hwid !== hwid) return res.status(200).json({ valid: false, reason: 'HWID mismatch' });
      res.json({ valid: true, payload: result.payload });
    } catch (error) {
      res.status(503).json({ valid: false, reason: 'License verification is not configured' });
    }
  });

  return router;
}
