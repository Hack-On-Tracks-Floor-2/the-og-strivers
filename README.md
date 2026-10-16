# Proof Patch

**Detect. Prove. Patch. Verify.**

**Live demo: https://proofpatch-r2.vercel.app** (use "Fill demo credentials" on the developer or reviewer login)

Given a vulnerable repository, Proof Patch finds the security bug, has an AI write a minimal fix and an attack test, and proves in a locked Docker sandbox that the attack fails before the fix, passes after it, and that every test that passed before still passes. A security reviewer approves, and Proof Patch opens a pull request for the developer.

## Windows quick start

Install Node.js 24 LTS and Git. Open PowerShell in this project folder:

```powershell
npm install
Copy-Item .env.example .env
# Optional: edit .env to set REVIEWER_EMAIL and a unique REVIEWER_PASSWORD (12–128 characters).
npm run dev
```

Open **http://127.0.0.1:5173**. Use the Developers portal to create an account. The reviewer portal accepts only the server-provisioned reviewer account. Leave both reviewer environment values blank to disable reviewer provisioning. Use 127.0.0.1 consistently; localhost is a different Origin and is not accepted by the default configuration. If PowerShell blocks npm.ps1, use `npm.cmd` in place of `npm`.

The web server uses port 5173 and proxies `/api` to the API on port 3001. Both run from `npm run dev`; Ctrl+C stops them. `.env` is read from the project root. The database is created automatically in `.data/proofpatch`; restart the API to verify records persist. Stop the server before copying that directory for backups. Do not run two API processes against the same database directory.

```powershell
npm test
npm run typecheck
npm run build
# Start the compiled API after building (frontend hosting requires a same-origin reverse proxy):
npm start
```

After cloning with the committed lockfile, prefer `npm ci`. Shared contracts compile before the dev processes start; after changing runtime shared schemas, rerun `npm run build -w @proofpatch/shared` or restart `npm run dev`.

## Implemented

- Black/lime role selection, separate developer/reviewer entry pages, login and developer signup.
- Salted scrypt passwords, HTTP-only opaque sessions, expiry/logout, Origin protection, auth rate limits, server-side role and ownership enforcement.
- Responsive developer/reviewer dashboard navigation, overview counts, repository registration/detail and persisted analysis history.
- Versioned PGlite migrations, shared Zod contracts, validated browser responses and modular backend boundaries.
- Analysis request registration with `not_configured` status and real request/capability events. No fake execution.
- Reusable findings, source/diff, evidence timeline, submitted review queue and decision controls. Unpopulated features show empty states. Approval requires actual recorded test evidence.
- API integration tests for auth/roles, URL validation, isolation, jobs, review evidence guards and reopening persisted storage. Synthetic review fixtures exist only in the temporary test database.

## Structure

```text
apps/web/src/       components, features, hooks, layouts, lib, pages, styles
apps/api/src/       routes, controllers, services, repositories, agents,
                    scanners, patching, verification, database, middleware, utils
packages/shared/   v1 Zod schemas and exported TypeScript contracts
tests/             essential shared-contract and real API integration tests
docs/              architecture, API contracts, security boundaries, team ownership
```

## Team handoff

Read [TEAM_TASKS](docs/TEAM_TASKS.md) before parallel changes. A owns `repositories/`, `agents/`, `scanners/`; first implement bounded ingestion and real code mapping. B owns `patching/`, `verification/`, `services/evidence.ts`; first validate Docker isolation and capture baseline execution. C owns `apps/web/src/` and public assets; first integrate actual artifacts from A/B. One integration lead owns shared schemas, API wiring, migrations and root configuration.

Details: [Architecture](docs/ARCHITECTURE.md), [API contracts](docs/API_CONTRACTS.md), [Security](docs/SECURITY.md).

Actual command results and browser checks are recorded in [Foundation validation](docs/VALIDATION.md).

## Git collaboration

The project package is named `proofpatch-ai`; this checkout keeps the provided folder name. Initialize locally if not already initialized:

```powershell
git init -b main
git add .
git commit -m "Build ProofPatch AI foundation"
# Create an empty private GitHub repository first, then substitute its real URL:
git remote add origin https://github.com/YOUR-TEAM/proofpatch-ai.git
git push -u origin main
```

Teammates clone that remote and use `codex/repository-intelligence`, `codex/patching-verification`, and `codex/dashboard-evidence`. Never commit `.env` or `.data`. No remote or hosted deployment is configured by this foundation.

## Deferred and limitations

No LLM reasoning, actual scanning, cloning, automatic patches, GitHub PR submission or repository test execution. Language/framework stay unknown until inspected. No password reset, email delivery, MFA, pagination or production hosting setup. Reviewers are provisioned at API startup; changing their environment password rotates it and invalidates their sessions. PGlite supports this single-process local foundation, not horizontal API scaling. Reference screenshots were not present in the supplied attachment; landing design follows the supplied typography, palette and spacing brief.

Compatibility references: [Vite requirements](https://vite.dev/guide/), [PGlite filesystem persistence](https://pglite.dev/docs/filesystems), [Node releases](https://nodejs.org/en/download/). Dependencies are pinned by package-lock.json after installation.
