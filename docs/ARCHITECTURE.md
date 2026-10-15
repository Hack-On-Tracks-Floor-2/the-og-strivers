# ProofPatch AI — Foundation 01

The application is a local npm-workspaces monorepo. React/Vite serves a single role-aware application. Express is the only backend. PGlite runs PostgreSQL in-process and persists to `.data/proofpatch`; no separate database service is required. Run one API process per database directory.

## Request path

Browser → Vite `/api` proxy → Express origin check → session authentication → server role/ownership check → Zod input validation → domain service → parameterized SQL → versioned JSON envelope → Zod-validated browser API client.

The shared package defines the v1 contract. Its build produces runtime JavaScript. Services must consume shared types rather than redefining entities. JSONB documents contain domain fields; relational columns enforce ownership relationships, unique repository URLs, sessions, foreign keys, and one decision per patch. `database/migrations.ts` contains numbered migrations applied transactionally at startup. Future schema changes add a migration rather than editing an applied one.

## Current capabilities

Authentication, repository registration, job creation, events, lists, overview counts, submitted-review visibility, and review decisions are implemented. Registering a URL does not verify its existence or public visibility. Analysis registration creates a `not_configured` job and two honest events in a single transaction. It does not clone, inspect, scan, patch or execute repository code. No findings, patches or passing test results are seeded.

## Pipeline extension points

1. `RepositoryIngestionService.ingest(repository, signal)` → capability result containing an opaque workspace ID and inspected commit SHA.
2. `RepositoryIntelligenceAgent.inspect(workspace, signal)` → languages, frameworks, entry points and argument-array test commands.
3. `VulnerabilityDetectionAgent.detect({run, workspace, map}, signal)` → real findings from multiple vulnerability classes.
4. `PatchGenerationAgent.generate({finding, workspace}, signal)` → file changes and actual unified diff.
5. `VerificationEngine.verify({patch, workspace}, signal)` → baseline, reproduction, application, security-retest and regression execution records.
6. `EvidenceService.recordEvent(input)` → persisted, traceable event ID.

Each adapter returns `{state:'completed', data}` or the shared `CAPABILITY_UNAVAILABLE` discriminated result. The sandbox adapter intentionally returns `not_configured`; it has no host-execution fallback. Future orchestration must own job transitions and record every transition. A database status or reviewer approval alone is insufficient to declare a run verified. Phase 1 never transitions a run to verified.

## Frontend boundaries

`features/auth.tsx` owns identity. `lib/api.ts` owns cookie-based transport and response validation. `layouts/Dashboard.tsx` owns navigation and role guards. Pages consume real API records. `components/artifacts.tsx` provides reusable findings, original/proposed source, diff and traceable timeline views. Loading, API failure, unavailable capability and empty data are separate states.

## Deployment boundary

Development uses `http://127.0.0.1:5173` and a loopback API on port 3001. The production API build can be started with `npm start`; serving `apps/web/dist` and proxying `/api` behind one HTTPS origin are deployment responsibilities. Configure `APP_ORIGIN` and `NODE_ENV=production`. The Vite development proxy is not a production deployment. Horizontal scaling and concurrent PGlite writers are out of scope.
