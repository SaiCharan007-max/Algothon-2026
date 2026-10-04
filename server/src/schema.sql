-- one row per analysis run (an upload can contain several log files)
CREATE TABLE IF NOT EXISTS uploads (
  id            SERIAL PRIMARY KEY,
  name          TEXT NOT NULL,
  files         JSONB NOT NULL DEFAULT '[]',   -- [{name, format, lines, parsed, skipped}]
  event_count   INTEGER NOT NULL DEFAULT 0,
  first_event   TIMESTAMPTZ,
  last_event    TIMESTAMPTZ,
  summary       JSONB NOT NULL DEFAULT '{}',   -- cached stats for the dashboard
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- normalized events from every parser
CREATE TABLE IF NOT EXISTS events (
  id          BIGSERIAL PRIMARY KEY,
  upload_id   INTEGER NOT NULL REFERENCES uploads(id) ON DELETE CASCADE,
  seq         INTEGER NOT NULL,           -- index inside the upload, used as evidence ref
  ts          TIMESTAMPTZ NOT NULL,
  source      TEXT NOT NULL,              -- auth | web | generic
  file        TEXT,
  line_no     INTEGER,
  ip          TEXT,
  username    TEXT,
  action      TEXT NOT NULL,              -- login | sudo | http | session | other
  outcome     TEXT,                       -- success | failure
  method      TEXT,
  path        TEXT,
  status_code INTEGER,
  bytes       BIGINT,
  detail      TEXT,
  raw         TEXT
);
CREATE INDEX IF NOT EXISTS events_upload_seq ON events (upload_id, seq);
CREATE INDEX IF NOT EXISTS events_upload_ip ON events (upload_id, ip);
CREATE INDEX IF NOT EXISTS events_upload_user ON events (upload_id, username);
CREATE INDEX IF NOT EXISTS events_upload_ts ON events (upload_id, ts);

CREATE TABLE IF NOT EXISTS incidents (
  id          SERIAL PRIMARY KEY,
  upload_id   INTEGER NOT NULL REFERENCES uploads(id) ON DELETE CASCADE,
  ref         TEXT NOT NULL,              -- INC-001 style id inside the upload
  title       TEXT NOT NULL,
  severity    TEXT NOT NULL,
  score       INTEGER NOT NULL,
  ips         TEXT[] NOT NULL DEFAULT '{}',
  users       TEXT[] NOT NULL DEFAULT '{}',
  stages      TEXT[] NOT NULL DEFAULT '{}',
  story       JSONB NOT NULL DEFAULT '[]',
  first_seen  TIMESTAMPTZ,
  last_seen   TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS incidents_upload ON incidents (upload_id);

CREATE TABLE IF NOT EXISTS alerts (
  id           SERIAL PRIMARY KEY,
  upload_id    INTEGER NOT NULL REFERENCES uploads(id) ON DELETE CASCADE,
  incident_id  INTEGER REFERENCES incidents(id) ON DELETE SET NULL,
  rule         TEXT NOT NULL,
  stage        TEXT NOT NULL,
  severity     TEXT NOT NULL,
  entity_type  TEXT NOT NULL,             -- ip | user
  entity       TEXT NOT NULL,
  title        TEXT NOT NULL,
  description  TEXT NOT NULL,
  first_seen   TIMESTAMPTZ NOT NULL,
  last_seen    TIMESTAMPTZ NOT NULL,
  evidence     INTEGER[] NOT NULL DEFAULT '{}',  -- event seq numbers
  meta         JSONB NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS alerts_upload ON alerts (upload_id);
CREATE INDEX IF NOT EXISTS alerts_incident ON alerts (incident_id);
