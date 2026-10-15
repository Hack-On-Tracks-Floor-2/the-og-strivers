# Foundation validation — 15 October 2026

Executed on Windows with Node.js v24.20.0 and npm 11.19.0.

## Actual command results

- Dependency installation: passed; 261 packages installed, npm lockfile generated. The environment's sandbox could not resolve npm initially; installation succeeded with network-enabled execution. npm reported esbuild's postinstall script was not allowlisted; the installed platform binary worked in the completed builds.
- `npm test`: passed, **32 tests / 2 files**. Latest run: 19 API tests and 13 shared-contract tests, 29.63 seconds. Includes authentication, secure cookies, role injection, Origin rejection, malformed JSON, repository URL restrictions, duplicate registration, ownership isolation, real job/events, missing-evidence approval rejection, transactional rejection, session expiry/logout, overview counts and database close/reopen persistence. The persistence test covers missing nested parent directories.
- `npm run build`: passed after final changes. Shared contracts, API TypeScript and Vite production build succeeded. Final client bundle: 361.77 kB JavaScript (109.20 kB gzip), 28.15 kB CSS (6.86 kB gzip).
- `npm run typecheck`: passed in API, web and shared workspaces after final changes.
- `npm run dev`: both Vite and Express started. Frontend HTTP response: 200. First startup exposed a missing data-parent directory; this was fixed in `openDatabase`, tested and rechecked.
- `npm start`: compiled API started on an alternate loopback port with the default `.data/proofpatch` directory. `/api/health` returned HTTP 200, database `ready`, analysis `not_configured`, API version `v1`.
- Git initialized on `main`. Secret, dependency, database and QA paths were checked with `git check-ignore`. No remote, push or initial commit was created.

Vite and Vitest required execution outside the Windows filesystem sandbox because its `realpath` restriction produced EPERM for project files. Those checks passed in the normal host environment. No sandbox restriction was added to the application itself.

## Browser verification

Checked using the in-app browser at 1440 × 1000 desktop and 390 × 844 mobile viewport overrides, then reset the override.

- Role selection, developer landing, reviewer landing and auth screens rendered.
- Registered a QA developer through the browser and entered its protected dashboard.
- Added `https://github.com/expressjs/express` through the UI. Detail view retained unknown language/framework rather than fabricating inspection results.
- Created a persisted analysis request. It displayed `not_configured`, a real request event and an explicit unavailable-capability event. Remaining pipeline stages displayed “not executed”.
- Developer findings, patch studio, evidence rail, settings and overview routes loaded. Empty artifact views stayed empty; the evidence timeline displayed actual recorded request events.
- Mobile drawer opened, navigated and closed. Closed drawer controls are hidden from accessibility/focus. Mobile overview had no horizontal overflow (document width and scroll width both 375 CSS pixels, excluding the scrollbar).
- Reviewer signed in through the server-provisioned QA account. All six reviewer routes loaded, with actual empty states and no invented patches or decisions.
- A signed-in reviewer visiting `/developer/app` was redirected to `/reviewer/app`.
- Logout returned to unauthenticated access. No browser console errors were reported in the completed reviewer navigation check.
- QA screenshots saved locally under `.qa/screenshots/`; QA credentials and records were used only with `.qa/browser-db`, separate from the default database. Neither directory is tracked.

Rebuilding shared contracts while the dev server runs restarts the API and can briefly interrupt requests; the browser now gives a readable backend-unavailable message for non-JSON proxy failures. Retry after startup. Reviewer sessions are deliberately invalidated when server-side reviewer provisioning reruns.

## Remaining scope

No unresolved build/typecheck/test failures. Full AI detection, ingestion/cloning, source patching, real test execution, Docker sandbox enforcement and automatic GitHub PRs are intentionally deferred. Production hosting, account recovery, large-dataset pagination and cryptographic artifact attestation are not implemented. Original screenshot attachments were absent; the interface follows the supplied design brief.

Local QA servers were stopped after verification. Start the application with the README commands.
