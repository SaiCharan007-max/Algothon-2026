import { withTransaction, query } from './db.js';

const CHUNK = 2000;

async function insertEvents(client, uploadId, events) {
  for (let i = 0; i < events.length; i += CHUNK) {
    const part = events.slice(i, i + CHUNK);
    const col = (fn) => part.map(fn);
    await client.query(
      `INSERT INTO events (upload_id, seq, ts, source, file, line_no, ip, username, action, outcome, method, path, status_code, bytes, detail, raw)
       SELECT $1, * FROM unnest($2::int[], $3::timestamptz[], $4::text[], $5::text[], $6::int[], $7::text[], $8::text[],
                                $9::text[], $10::text[], $11::text[], $12::text[], $13::int[], $14::bigint[], $15::text[], $16::text[])`,
      [
        uploadId,
        col((e) => e.seq),
        col((e) => e.ts.toISOString()),
        col((e) => e.source),
        col((e) => e.file),
        col((e) => e.lineNo),
        col((e) => e.ip),
        col((e) => e.user),
        col((e) => e.action),
        col((e) => e.outcome),
        col((e) => e.method),
        col((e) => e.path),
        col((e) => e.status),
        col((e) => e.bytes),
        col((e) => e.detail),
        col((e) => e.raw),
      ],
    );
  }
}

export async function saveAnalysis({ name, files, events, result }) {
  return withTransaction(async (client) => {
    const { stats, histogram, entities, incidents, alerts, evaluation } = result;
    const { rows } = await client.query(
      `INSERT INTO uploads (name, files, event_count, first_event, last_event, summary)
       VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`,
      [name, JSON.stringify(files), events.length, stats.firstEvent, stats.lastEvent, JSON.stringify({ stats, histogram, entities: entities.slice(0, 300), evaluation: evaluation || null })],
    );
    const uploadId = rows[0].id;

    await insertEvents(client, uploadId, events);

    const incidentIds = new Map();
    for (const inc of incidents) {
      const r = await client.query(
        `INSERT INTO incidents (upload_id, ref, title, severity, score, ips, users, stages, story, first_seen, last_seen)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING id`,
        [uploadId, inc.ref, inc.title, inc.severity, inc.score, inc.ips, inc.users, inc.stages, JSON.stringify(inc.story), inc.firstSeen, inc.lastSeen],
      );
      incidentIds.set(inc.ref, r.rows[0].id);
    }

    if (alerts.length) {
      const col = (fn) => alerts.map(fn);
      await client.query(
        `INSERT INTO alerts (upload_id, incident_id, rule, stage, severity, entity_type, entity, title, description, first_seen, last_seen, evidence, meta)
         SELECT $1, a.incident_id, a.rule, a.stage, a.severity, a.entity_type, a.entity, a.title, a.description, a.first_seen, a.last_seen,
                ARRAY(SELECT jsonb_array_elements_text(a.evidence)::int), a.meta
         FROM unnest($2::int[], $3::text[], $4::text[], $5::text[], $6::text[], $7::text[], $8::text[], $9::text[],
                     $10::timestamptz[], $11::timestamptz[], $12::jsonb[], $13::jsonb[])
           AS a(incident_id, rule, stage, severity, entity_type, entity, title, description, first_seen, last_seen, evidence, meta)`,
        [
          uploadId,
          col((a) => incidentIds.get(a.incidentRef) ?? null),
          col((a) => a.rule),
          col((a) => a.stage),
          col((a) => a.severity),
          col((a) => a.entityType),
          col((a) => a.entity),
          col((a) => a.title),
          col((a) => a.description),
          col((a) => a.firstSeen.toISOString()),
          col((a) => a.lastSeen.toISOString()),
          col((a) => JSON.stringify(a.evidence)),
          col((a) => JSON.stringify({ ...a.meta, eventCount: a.eventCount })),
        ],
      );
    }
    return uploadId;
  });
}

export async function listUploads() {
  const { rows } = await query(
    `SELECT u.id, u.name, u.files, u.event_count, u.first_event, u.last_event, u.created_at,
            u.summary->'stats'->'bySeverity' AS by_severity,
            (u.summary->'stats'->>'incidents')::int AS incidents
     FROM uploads u ORDER BY u.created_at DESC LIMIT 50`,
  );
  return rows;
}

export async function getUpload(id) {
  const { rows } = await query('SELECT * FROM uploads WHERE id = $1', [id]);
  if (!rows.length) return null;
  const upload = rows[0];
  const [incidents, alerts] = await Promise.all([
    query(
      `SELECT i.*, (SELECT count(*)::int FROM alerts a WHERE a.incident_id = i.id) AS alert_count
       FROM incidents i WHERE upload_id = $1 ORDER BY score DESC, first_seen`,
      [id],
    ),
    query(
      `SELECT a.id, a.rule, a.stage, a.severity, a.entity_type, a.entity, a.title, a.description, a.first_seen, a.last_seen,
              a.meta, i.ref AS incident_ref
       FROM alerts a LEFT JOIN incidents i ON i.id = a.incident_id
       WHERE a.upload_id = $1 ORDER BY a.first_seen`,
      [id],
    ),
  ]);
  return { ...upload, incidents: incidents.rows, alerts: alerts.rows };
}

export async function getIncident(uploadId, ref) {
  const inc = await query('SELECT * FROM incidents WHERE upload_id = $1 AND ref = $2', [uploadId, ref]);
  if (!inc.rows.length) return null;
  const incident = inc.rows[0];
  const alerts = await query('SELECT * FROM alerts WHERE incident_id = $1 ORDER BY first_seen', [incident.id]);
  const seqs = [...new Set(alerts.rows.flatMap((a) => a.evidence))];
  const evidence = await query(
    `SELECT seq, ts, source, file, line_no, ip, username, action, outcome, method, path, status_code, bytes, detail, raw
     FROM events WHERE upload_id = $1 AND seq = ANY($2::int[]) ORDER BY seq`,
    [uploadId, seqs],
  );
  return { ...incident, alerts: alerts.rows, evidence: evidence.rows };
}

// Log lines for the "annotated file" view: every flagged line plus a couple of
// lines of context around it. Long runs of normal lines are collapsed into gaps.
export async function getAnnotated(uploadId, context = 2) {
  const up = await query('SELECT files FROM uploads WHERE id = $1', [uploadId]);
  if (!up.rows.length) return null;

  const [ev, al] = await Promise.all([
    query('SELECT seq, file, line_no, raw FROM events WHERE upload_id = $1 ORDER BY file, line_no', [uploadId]),
    query(
      `SELECT a.id, a.rule, a.stage, a.severity, a.title, a.description, a.evidence, a.first_seen, a.meta->'mitre' AS mitre,
              i.ref AS incident_ref, i.title AS incident_title, i.severity AS incident_severity
       FROM alerts a LEFT JOIN incidents i ON i.id = a.incident_id
       WHERE a.upload_id = $1 ORDER BY a.first_seen, a.id`,
      [uploadId],
    ),
  ]);

  // step number of each alert inside its incident (same order as the incident page)
  const stepCounter = new Map();
  const alerts = {};
  const flagged = new Map(); // seq -> [alert ids]
  for (const a of al.rows) {
    const n = (stepCounter.get(a.incident_ref) || 0) + 1;
    stepCounter.set(a.incident_ref, n);
    const { evidence, ...rest } = a;
    alerts[a.id] = { ...rest, step: n, lines: evidence.length };
    for (const seq of evidence) {
      if (!flagged.has(seq)) flagged.set(seq, []);
      flagged.get(seq).push(a.id);
    }
  }
  for (const a of Object.values(alerts)) a.steps = stepCounter.get(a.incident_ref);

  const byFile = new Map();
  for (const e of ev.rows) {
    if (!byFile.has(e.file)) byFile.set(e.file, []);
    byFile.get(e.file).push(e);
  }

  const files = up.rows[0].files.map((f) => {
    const lines = byFile.get(f.name) || [];
    const anyFlagged = lines.some((l) => flagged.has(l.seq));
    // a clean, small file is shown in full so you can see there's nothing wrong in it
    const keep = new Array(lines.length).fill(!anyFlagged && lines.length <= 500);
    lines.forEach((l, i) => {
      if (!flagged.has(l.seq)) return;
      for (let j = Math.max(0, i - context); j <= Math.min(lines.length - 1, i + context); j++) keep[j] = true;
    });
    // don't bother folding tiny runs ("3 lines hidden" is just noise)
    for (let i = 0; i < lines.length; ) {
      if (keep[i]) {
        i++;
        continue;
      }
      let j = i;
      while (j < lines.length && !keep[j]) j++;
      if (j - i <= 5) for (let k = i; k < j; k++) keep[k] = true;
      i = j;
    }

    const items = [];
    let gap = null;
    lines.forEach((l, i) => {
      if (keep[i]) {
        if (gap) items.push(gap);
        gap = null;
        items.push({ type: 'line', seq: l.seq, line: l.line_no, raw: l.raw, alerts: flagged.get(l.seq) || [] });
      } else {
        if (!gap) gap = { type: 'gap', count: 0, fromLine: l.line_no, toLine: l.line_no };
        gap.count++;
        gap.toLine = l.line_no;
      }
    });
    if (gap) items.push(gap);

    return { name: f.name, format: f.format, totalLines: lines.length, flaggedLines: lines.filter((l) => flagged.has(l.seq)).length, items };
  });

  return { files, alerts };
}

// plain lines of one file between two line numbers (used to expand a collapsed gap)
export async function getLines(uploadId, file, fromLine, toLine, limit = 500) {
  const { rows } = await query(
    `SELECT seq, line_no, raw FROM events
     WHERE upload_id = $1 AND file = $2 AND line_no BETWEEN $3 AND $4
     ORDER BY line_no LIMIT $5`,
    [uploadId, file, fromLine, toLine, limit],
  );
  return rows.map((r) => ({ type: 'line', seq: r.seq, line: r.line_no, raw: r.raw, alerts: [] }));
}

export async function searchEvents(uploadId, { ip, user, source, outcome, action, q, limit = 100, offset = 0 }) {
  const where = ['upload_id = $1'];
  const params = [uploadId];
  const add = (sql, value) => {
    params.push(value);
    where.push(sql.replace('?', `$${params.length}`));
  };
  if (ip) add('ip = ?', ip);
  if (user) add('username = ?', user);
  if (source) add('source = ?', source);
  if (outcome) add('outcome = ?', outcome);
  if (action) add('action = ?', action);
  if (q) add('raw ILIKE ?', `%${q.replace(/[%_\\]/g, (c) => '\\' + c)}%`);

  const lim = Math.min(Math.max(Number(limit) || 100, 1), 500);
  const off = Math.max(Number(offset) || 0, 0);
  const whereSql = where.join(' AND ');
  const [rows, count] = await Promise.all([
    query(
      `SELECT seq, ts, source, file, line_no, ip, username, action, outcome, method, path, status_code, bytes, detail, raw
       FROM events WHERE ${whereSql} ORDER BY seq LIMIT ${lim} OFFSET ${off}`,
      params,
    ),
    query(`SELECT count(*)::int AS n FROM events WHERE ${whereSql}`, params),
  ]);
  return { total: count.rows[0].n, events: rows.rows };
}

export async function deleteUpload(id) {
  const { rowCount } = await query('DELETE FROM uploads WHERE id = $1', [id]);
  return rowCount > 0;
}
