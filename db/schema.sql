-- Run with: wrangler d1 execute second-brain-db --file=db/schema.sql

CREATE TABLE IF NOT EXISTS entries (
  id          TEXT PRIMARY KEY,
  content     TEXT NOT NULL,
  tags        TEXT NOT NULL DEFAULT '[]',
  source      TEXT NOT NULL DEFAULT 'api',
  created_at  INTEGER NOT NULL,
  vector_ids  TEXT NOT NULL DEFAULT '[]',
  namespace   TEXT NOT NULL DEFAULT 'default'
);

CREATE INDEX IF NOT EXISTS idx_entries_created_at ON entries(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_entries_source ON entries(source);
CREATE INDEX IF NOT EXISTS idx_entries_namespace ON entries(namespace);
CREATE INDEX IF NOT EXISTS idx_entries_namespace_created_at ON entries(namespace, created_at DESC);

CREATE TABLE IF NOT EXISTS auth_tokens (
  id                 TEXT PRIMARY KEY,
  label              TEXT NOT NULL,
  token_hash         TEXT NOT NULL UNIQUE,
  token_ciphertext   TEXT,
  role               TEXT NOT NULL DEFAULT 'user',
  default_namespace  TEXT NOT NULL DEFAULT 'default',
  read_namespaces    TEXT NOT NULL DEFAULT '["default"]',
  write_namespaces   TEXT NOT NULL DEFAULT '["default"]',
  delete_namespaces  TEXT NOT NULL DEFAULT '[]',
  created_at         INTEGER NOT NULL,
  last_used_at       INTEGER,
  revoked_at         INTEGER
);

CREATE INDEX IF NOT EXISTS idx_auth_tokens_hash ON auth_tokens(token_hash);
CREATE INDEX IF NOT EXISTS idx_auth_tokens_default_namespace ON auth_tokens(default_namespace);

-- Existing installs are upgraded by initializeDatabase() in src/index.ts because
-- SQLite/D1 does not support fully idempotent ALTER COLUMN statements here.
