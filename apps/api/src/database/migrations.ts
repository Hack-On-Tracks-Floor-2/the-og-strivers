export const migrations = [
  {
    version: 1,
    sql: `
CREATE TABLE users (id UUID PRIMARY KEY, email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, document JSONB NOT NULL);
CREATE TABLE sessions (token_hash TEXT PRIMARY KEY, user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE, expires_at TIMESTAMPTZ NOT NULL);
CREATE INDEX sessions_expiry ON sessions(expires_at);
CREATE TABLE repositories (id UUID PRIMARY KEY, owner_id UUID NOT NULL REFERENCES users(id), canonical_url TEXT NOT NULL, document JSONB NOT NULL, UNIQUE(owner_id, canonical_url));
CREATE TABLE runs (id UUID PRIMARY KEY, repository_id UUID NOT NULL REFERENCES repositories(id), owner_id UUID NOT NULL REFERENCES users(id), document JSONB NOT NULL);
CREATE TABLE findings (id UUID PRIMARY KEY, run_id UUID NOT NULL REFERENCES runs(id), owner_id UUID NOT NULL REFERENCES users(id), document JSONB NOT NULL);
CREATE TABLE patches (id UUID PRIMARY KEY, run_id UUID NOT NULL REFERENCES runs(id), finding_id UUID NOT NULL REFERENCES findings(id), owner_id UUID NOT NULL REFERENCES users(id), document JSONB NOT NULL);
CREATE TABLE verifications (id UUID PRIMARY KEY, run_id UUID NOT NULL REFERENCES runs(id), patch_id UUID NOT NULL REFERENCES patches(id), owner_id UUID NOT NULL REFERENCES users(id), document JSONB NOT NULL);
CREATE TABLE events (id UUID PRIMARY KEY, run_id UUID NOT NULL REFERENCES runs(id), owner_id UUID NOT NULL REFERENCES users(id), document JSONB NOT NULL);
CREATE TABLE decisions (id UUID PRIMARY KEY, run_id UUID NOT NULL REFERENCES runs(id), patch_id UUID NOT NULL UNIQUE REFERENCES patches(id), reviewer_id UUID NOT NULL REFERENCES users(id), document JSONB NOT NULL);
CREATE INDEX repositories_owner ON repositories(owner_id);
CREATE INDEX runs_owner ON runs(owner_id);
CREATE INDEX runs_repository ON runs(repository_id);
CREATE INDEX findings_run ON findings(run_id);
CREATE INDEX patches_run ON patches(run_id);
CREATE INDEX verifications_run ON verifications(run_id);
CREATE INDEX events_run ON events(run_id);
`,
  },
  {
    // Bounded execution evidence (logs, JUnit XML, diffs, generated security tests).
    // The id is the content SHA-256: a stable identifier, not a cryptographic attestation.
    version: 2,
    sql: `
CREATE TABLE artifacts (id TEXT PRIMARY KEY, run_id UUID NOT NULL REFERENCES runs(id), owner_id UUID NOT NULL REFERENCES users(id), document JSONB NOT NULL, content TEXT NOT NULL);
CREATE INDEX artifacts_run ON artifacts(run_id);
`,
  },
  {
    version: 3,
    sql: `
CREATE TABLE finding_ml (finding_id UUID PRIMARY KEY REFERENCES findings(id) ON DELETE CASCADE, run_id UUID NOT NULL REFERENCES runs(id), repository_id UUID NOT NULL REFERENCES repositories(id), owner_id UUID NOT NULL REFERENCES users(id), document JSONB NOT NULL);
CREATE INDEX finding_ml_run ON finding_ml(run_id);
`,
  },
];
