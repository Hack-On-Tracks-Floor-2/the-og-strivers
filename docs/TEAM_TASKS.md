# Parallel team work

Foundation contract owner: designate one integration lead before starting work. All branches begin from the same foundation commit. Module owners can work independently in the folders below; do not concurrently edit shared contracts, root configuration, route composition or migrations.

## Workstream A — Repository Intelligence & Detection

Branch: `codex/repository-intelligence`.

Exclusive ownership: `apps/api/src/repositories/` (including registration and future ingestion), `apps/api/src/agents/`, `apps/api/src/scanners/`, new `tests/intelligence/`.

Inputs/outputs: implement `RepositoryIngestionService.ingest(Repository, AbortSignal) → CapabilityResult<WorkspaceHandle>`, `RepositoryIntelligenceAgent.inspect(WorkspaceHandle, AbortSignal) → CapabilityResult<RepositoryMap>`, and `VulnerabilityDetectionAgent.detect({run,workspace,map}, signal) → CapabilityResult<Finding[]>`. Consume the existing shared schemas. Existing `createAnalysisRun(db,user,repositoryId)` is the registration seam; only replace the unavailable behavior when a real worker exists.

First tasks: add safe public-GitHub metadata verification and a bounded clone adapter; map language/framework/test commands without executing repository code; add a static-analysis adapter supporting multiple vulnerability categories. Confirm artifact persistence with Workstream B before emitting findings.

Acceptance: reject unsafe/private/missing URLs during ingestion with real errors; enforce cancellation and clone limits; report exact inspected file/line references and pinned commit; no hardcoded findings; no host test execution; preserve ownership and honest failure states.

## Workstream B — Patching & Verification

Branch: `codex/patching-verification`.

Exclusive ownership: `apps/api/src/patching/`, `apps/api/src/verification/`, `apps/api/src/services/evidence.ts`, new `tests/verification/`.

Inputs/outputs: implement `PatchGenerationAgent.generate({finding,workspace}, signal) → CapabilityResult<Patch>` and `VerificationEngine.verify({patch,workspace}, signal) → CapabilityResult<VerificationRun[]>`. Implement `SandboxExecutionAdapter.execute(ExecutionRequest, signal) → CapabilityResult<ExecutionResult>`. `EvidenceService.recordEvent(input) → RunEvent` records traceable events. `argv` is an array, never a shell command string.

First tasks: build and test Docker execution isolation; capture actual baseline logs/exit codes before any patch; generate an actual unified diff against the inspected commit; reproduce the vulnerability; apply patch and rerun security/regression tests; persist artifacts with limits.

Dependencies: A provides a validated workspace, source map, test argv and Finding. C consumes Patch, VerificationRun and RunEvent. Coordinate how expected vulnerable behavior is recorded in reproduction evidence with the integration lead.

Acceptance: no untrusted code on host; pinned workspace/commit; minimal changes; no successful result without actual execution; fail closed on missing baseline/security/regression evidence; record commands, exits and bounded logs; cleanup on cancellation; supported sandboxes must meet `SECURITY.md` requirements.

## Workstream C — Dashboard & Evidence

Branch: `codex/dashboard-evidence`.

Exclusive ownership: all `apps/web/src/`, `apps/web/public/`, `apps/web/index.html`, new `tests/web/`. Root dependency changes go through integration lead.

Inputs/outputs: use `lib/api.ts` and existing shared envelope/Zod schemas. Reuse `FindingCard({finding})`, `PatchViewer({patch})`, `EvidenceTimeline({events,verification})`. Both roles share components, auth and transport. Keep reviewer queue/decisions integrated with backend role checks.

First tasks: validate new artifact fields from A/B through API contracts; add per-run drill-down links and polling only for actual executing jobs; improve diff presentation and artifact download after real storage exists. Preserve the original black/lime typography and honest empty states.

Acceptance: desktop/mobile navigation; accessible keyboard interactions; loading/error/empty states; strict role routing; actual persisted values only; no fabricated patches, findings or verification; render real file/line references and execution evidence.

## Integration lead — single-writer files

Own `packages/shared/`, `apps/api/src/routes/`, `apps/api/src/controllers/`, `apps/api/src/database/`, `apps/api/src/middleware/`, `apps/api/src/services/auth.ts`, `apps/api/src/utils/`, `apps/api/src/app.ts`, `apps/api/src/server.ts`, root files/configuration, package manifests/lockfile, `docs/`, `tests/api.test.ts` and `tests/contracts.test.ts`.

Owners propose additive contract changes with the exact function signature and compatibility notes. The integration lead merges a small contract/migration PR first; other branches rebase and consume it. New migration versions append to the migration list. Never edit an already-applied migration. API wiring is integrated centrally after adapter acceptance checks. No teammate should need to edit the same shared files simultaneously.

## Safe PR sequence

1. Integration lead makes the foundation commit and pushes `main` to the chosen private remote.
2. Each teammate pulls and creates their branch above; use separate clones/worktrees for separate agents.
3. Keep each PR limited to owned modules; raise contract changes separately before implementation.
4. Before opening a PR run `npm ci`, `npm run typecheck`, `npm test`, `npm run build` and include actual outputs. Review new execution code against `SECURITY.md`.
5. Rebase on current main, resolve owned-module conflicts, rerun affected checks, then request review from the neighboring workstream. The integration lead owns shared-file conflict resolution.
6. Merge contracts → ingestion/detection → patch/verification → UI integrations. Test one actual end-to-end repository only after sandbox isolation is validated. Do not seed demonstrations as real results.
