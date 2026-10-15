# Security boundaries

## Implemented

- Passwords use Node's salted scrypt KDF (16 random salt bytes, 64 derived bytes), constant-time comparison and no plaintext storage. Login checks an existing dummy hash for unknown emails.
- Sessions are 32 random bytes, stored as SHA-256 digests in PGlite, expire after seven days, rotate on login and are revoked on logout. Cookies are HttpOnly, SameSite=Lax, and Secure in production. Reviewer provisioning invalidates that reviewer's existing sessions at startup and rotates its password to the configured value.
- Developer registration cannot set role. Reviewer credentials are configured only on the server; an existing developer email cannot be promoted during provisioning. There is no built-in/default reviewer password.
- Server authentication, role checks and ownership checks apply regardless of browser routing. Reviewers can inspect only runs with submitted patches.
- Exact Origin validation protects all API mutations, including login, registration and logout. SameSite cookies add another boundary. API JSON bodies are limited to 32 KiB. Login/signup are rate limited together by source IP. Helmet supplies HTTP headers. API responses use no-store.
- GitHub URLs accept only `https://github.com/owner/repository` with optional `.git` and trailing slash. Registration performs no network fetch. Parameterized SQL is used for values; dynamically chosen table names are internal constants.
- A transactional review guard prevents approval without recorded passing evidence. Review approval cannot declare the entire run verified.
- `.env`, database files and dependency/build outputs are ignored in Git. No AI keys are used by or exposed to the browser.

## Hostile repository boundary — required for Phase 2

No repository cloning, source reads, patch application, child processes or untrusted test execution are implemented. The sandbox adapter always returns `not_configured`. Do not add a host-execution fallback.

The future clone adapter must check public visibility with GitHub, pin a commit SHA, disable submodule and LFS fetches, limit clone to 60 seconds / 100 MiB / 20,000 files, and remove partial workspaces on cancellation. Reject symlink escapes, special files, path traversal, absolute file paths and files outside an owned generated workspace. Resolve real paths before any file reads/writes. Git options and args must be separate arguments; never construct interpolated shell strings.

The future Docker adapter must use network=none, a non-root UID, read-only root filesystem, no host sockets, no credentials, restricted mounts, dropped Linux capabilities, no-new-privileges, memory/CPU/PID/time/output/disk limits, seccomp and controlled writable temporary directories. Do not share a writable host checkout between patch/test containers. Enforce limits on the server; do not trust requested limits from a repository. Images and package-install network access need an explicit allowlist and isolated preparation stage. Container escape resistance and clean teardown require validation before enabling execution.

Repository files, READMEs, dependency metadata, issues and source comments are untrusted content. AI adapters must keep them separate from system/tool instructions, apply least-privilege tool allowlists, redact secrets and prevent repository text from authorizing network, filesystem or command access. AI provider keys stay server-side.

## Intentionally deferred

Email verification, password reset/change UI, MFA, CSRF tokens for non-Origin clients, central audit export, tamper-evident artifact storage, background queues, real GitHub visibility checks, vulnerability analysis, patches, container execution and resource enforcement are not implemented. Current evidence is stored as JSONB; an artifact reference is a recorded identifier, not a cryptographic attestation. Before public deployment add HTTPS termination, same-origin SPA hosting, persistent-volume backups, robust rate limiting behind explicitly trusted proxies, monitoring, dependency review, pagination and operational recovery. Production API binds loopback and expects a reverse proxy; do not expose the Vite development server publicly.

## Verification semantics

Never set `verified` from a timeout, generated explanation, reviewer click, empty test suite or capability-unavailable result. Preserve actual argv, commit, workspace identity, command outcome, start/completion times, logs and artifacts. Distinguish “security test unavailable” from “security test passed”; unsupported reproduction must remain visibly incomplete. A reproduction exit code describes the test harness result and must document the vulnerable baseline behavior.
