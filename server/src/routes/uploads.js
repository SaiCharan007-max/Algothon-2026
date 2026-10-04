import { Router } from 'express';
import multer from 'multer';
import { parseFiles, FORMATS } from '../parsers/index.js';
import { analyze } from '../analyze.js';
import { saveAnalysis, listUploads, getUpload, getIncident, searchEvents, deleteUpload } from '../store.js';
import { generate } from '../../scripts/generate-logs.js';

const MAX_FILE_MB = 25;
const MAX_EVENTS = 250_000;

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: MAX_FILE_MB * 1024 * 1024, files: 10 },
});

function httpError(status, message) {
  const err = new Error(message);
  err.status = status;
  err.expose = true;
  return err;
}

const idParam = (req) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id <= 0) throw httpError(400, 'Invalid upload id');
  return id;
};

async function runAndSave(name, files, year) {
  const { events, files: fileInfo } = parseFiles(files, { year });
  if (!events.length) {
    const detail = fileInfo.map((f) => `${f.name}: ${f.format ?? 'unknown format'}, ${f.skipped} unreadable line(s)`).join('; ');
    throw httpError(422, `No log events could be parsed. ${detail}`);
  }
  if (events.length > MAX_EVENTS) throw httpError(413, `Too many events (${events.length}); limit is ${MAX_EVENTS}`);

  const started = Date.now();
  const result = analyze(events);
  const analysisMs = Date.now() - started;
  const id = await saveAnalysis({ name, files: fileInfo, events, result });
  return { id, files: fileInfo, stats: result.stats, analysisMs };
}

export const uploadsRouter = Router();

uploadsRouter.get('/', async (_req, res) => {
  res.json(await listUploads());
});

uploadsRouter.post('/', upload.array('files', 10), async (req, res) => {
  if (!req.files?.length) throw httpError(400, 'Attach at least one log file in the "files" field');

  // optional per-file format override: formats=auth,web
  const overrides = String(req.body.formats || '').split(',');
  const files = req.files.map((f, i) => {
    const text = f.buffer.toString('utf8');
    if (text.includes('\u0000')) throw httpError(415, `${f.originalname} looks like a binary file`);
    const fmt = overrides[i]?.trim();
    return { name: f.originalname, text, format: FORMATS.includes(fmt) ? fmt : undefined };
  });

  const year = Number(req.body.year) || new Date().getUTCFullYear();
  const name = (req.body.name || files.map((f) => f.name).join(' + ')).slice(0, 200);
  res.status(201).json(await runAndSave(name, files, year));
});

// one click demo data for judges / first time users
uploadsRouter.post('/sample', async (_req, res) => {
  const { auth, access } = generate();
  const files = [
    { name: 'auth.log', text: auth, format: 'auth' },
    { name: 'access.log', text: access, format: 'web' },
  ];
  res.status(201).json(await runAndSave('Sample: web01 auth.log + access.log', files, 2026));
});

uploadsRouter.get('/:id', async (req, res) => {
  const data = await getUpload(idParam(req));
  if (!data) throw httpError(404, 'Upload not found');
  res.json(data);
});

uploadsRouter.get('/:id/incidents/:ref', async (req, res) => {
  const data = await getIncident(idParam(req), req.params.ref);
  if (!data) throw httpError(404, 'Incident not found');
  res.json(data);
});

uploadsRouter.get('/:id/events', async (req, res) => {
  res.json(await searchEvents(idParam(req), req.query));
});

uploadsRouter.delete('/:id', async (req, res) => {
  const ok = await deleteUpload(idParam(req));
  if (!ok) throw httpError(404, 'Upload not found');
  res.status(204).end();
});

// multer errors (file too big etc) -> 4xx instead of 500
uploadsRouter.use((err, _req, _res, next) => {
  if (err instanceof multer.MulterError) return next(httpError(413, err.message));
  next(err);
});
