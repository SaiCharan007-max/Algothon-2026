import express from 'express';
import cors from 'cors';
import path from 'node:path';
import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { query } from './db.js';
import { uploadsRouter, SAMPLES } from './routes/uploads.js';
import { RULES } from './detectors/index.js';
import { DEFAULT_CONFIG } from './detectors/config.js';

export function createApp() {
  const app = express();

  const origins = (process.env.CORS_ORIGIN || '*').split(',').map((s) => s.trim());
  app.use(cors({ origin: origins.includes('*') ? true : origins }));
  app.use(express.json());

  app.get('/api/health', async (_req, res) => {
    await query('SELECT 1');
    res.json({ ok: true });
  });

  // exposes which rules exist and their thresholds (shown on the "how it works" panel)
  app.get('/api/rules', (_req, res) => {
    res.json({ rules: RULES.map((r) => r.id), config: DEFAULT_CONFIG });
  });

  // sample log files to download and try uploading by hand
  app.get('/api/samples/:name', (req, res) => {
    const make = SAMPLES[req.params.name];
    if (!make) return res.status(404).json({ error: 'Unknown sample' });
    res.type('text/plain').attachment(req.params.name).send(make());
  });

  app.use('/api/uploads', uploadsRouter);

  app.use('/api', (_req, res) => res.status(404).json({ error: 'Not found' }));

  // in production the built React app (client/dist) is served from here too,
  // so the whole thing runs as one service on one URL
  const webDir = fileURLToPath(new URL('../../client/dist/', import.meta.url));
  if (existsSync(webDir)) {
    app.use(express.static(webDir, { index: false, maxAge: '1h' }));
    // any other GET is a React route (/analysis/12 etc) -> index.html
    app.use((req, res, next) => {
      if (req.method !== 'GET') return next();
      res.sendFile(path.join(webDir, 'index.html'));
    });
  }

  app.use((err, _req, res, _next) => {
    if (!err.expose) console.error(err);
    res.status(err.status || 500).json({ error: err.expose ? err.message : 'Internal server error' });
  });

  return app;
}
