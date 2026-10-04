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
    const { stats, histogram, entities, incidents, alerts } = result;
    const { rows } = await client.query(
      `INSERT INTO uploads (name, files, event_count, first_event, last_event, summary)
       VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`,
      [name, JSON.stringify(files), events.length, stats.firstEvent, stats.lastEvent, JSON.stringify({ stats, histogram, entities: entities.slice(0, 300) })],
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
