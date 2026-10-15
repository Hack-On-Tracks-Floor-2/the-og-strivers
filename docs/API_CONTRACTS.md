# API contracts — v1

All routes are under `/api`. Successful responses are `{ "data": ..., "version": "v1" }`. Errors are `{ "error": { "code": "...", "message": "...", "issues": ... }, "version": "v1" }`. `issues` is optional validation detail. Shared Zod schemas and TypeScript exports live in `packages/shared/src/index.ts`. IDs are UUIDs; timestamps are UTC ISO strings. Password hashes and session tokens are never returned in JSON.

Mutations must include `Origin` equal to `APP_ORIGIN`, JSON content type, and the session cookie where required. The browser sets Origin automatically. Invalid input returns 400; unauthenticated requests 401; role violations 403; inaccessible or missing owned records 404; duplicates and invalid review transitions 409; rate limits 429. Unsupported route names return 404.

## Authentication

- `GET /health`: database readiness and `analysis: not_configured`.
- `POST /auth/register`: strict `RegisterSchema` input `{name,email,password}`. Creates developer only; 201 User and HttpOnly cookie. Password length 12–128. Extra role fields rejected.
- `POST /auth/login`: strict `LoginSchema` input `{email,password,role}`. 200 User and rotated session cookie. Portal role must match account.
- `POST /auth/logout`: invalidates current session; 200 `{loggedOut:true}`. Idempotent.
- `GET /auth/me`: authenticated User.

## Developer records

- `GET /repositories`: owned Repository array. Reviewer forbidden.
- `POST /repositories`: `{url}` in strict GitHub HTTPS owner/repo format. Canonicalizes trailing slash and `.git`, rejects query, fragment, credentials, alternate hosts, subpaths and traversal names. 201 Repository with null language/framework. Case-insensitive duplicate URL per owner returns 409. This endpoint registers metadata and makes no network request.
- `GET /repositories/:id`: owned Repository, 404 for another owner.
- `POST /runs`: `{repositoryId}` for owned repository. 201 AnalysisRun with `status: not_configured`, plus explicit `capability: {code:'CAPABILITY_UNAVAILABLE',state:'not_configured',message}`. The 201 acknowledges job registration only. No execution is scheduled. Future direct execution endpoints must return 503 with capability detail when unavailable.
- `GET /runs`: owned AnalysisRun array; reviewer sees runs with submitted patches only.
- `GET /runs/:id`: accessible AnalysisRun.
- `GET /runs/:id/events`: RunEvent array.
- `GET /runs/:id/findings`: Finding array.
- `GET /runs/:id/patches`: Patch array.
- `GET /runs/:id/verification`: VerificationRun array.
- `GET /overview`: persisted `{repositories,runs,findings,patches,verified,awaitingReview}` counts. Reviewer counts use submitted runs; repository count is 0 because reviewer has no repository registry.

Developers can read only their own runs. Reviewers can read runs only when they contain a patch in `needs_review`, `approved` or `rejected`. Per-run array endpoints return empty arrays when no records exist, never example artifacts. Arrays are currently unpaginated; pagination is a follow-up before large datasets.

## Reviewer workflow

- `GET /reviews/queue`: reviewer only. Actual Patch records with status `needs_review`.
- `GET /reviews/decisions`: reviewer only. Recorded ReviewDecision array.
- `POST /reviews/:id/decision`: `:id` is the **patch ID**. Strict `{decision:'approved'|'rejected',reason}` with 10–4000 character rationale. Requires patch `needs_review`; returns 201 ReviewDecision. Writes decision, updates patch status, and appends run event atomically. One decision per patch; resubmission requires a new patch ID.

Approval requires latest recorded evidence for each of baseline, reproduction, patch_application, security_retest and regression, tied to the same run and patch. Every stage must have passed, exit code 0, nonempty logs, artifact reference and completion timestamp. Missing proof returns 409 `EVIDENCE_REQUIRED`. Approval updates patch review status, and does not automatically mark the run verified. The eventual verification engine owns verification status. Reproduction records must explicitly document the expected pre-patch vulnerable behavior, not imply baseline security.

## Schema extension policy

Core entities: User, Repository, AnalysisRun, Finding, Patch, VerificationRun, RunEvent, ReviewDecision. All carry IDs and timestamps plus explicit relationships. Use additive optional fields or new exported schemas for compatible extensions. Coordinate enum or required-field changes in one contract PR; bump API version for incompatible external semantics. New adapters belong in their owned module and use `CapabilityResult<T>`. Frontend data must pass a shared schema before rendering.
