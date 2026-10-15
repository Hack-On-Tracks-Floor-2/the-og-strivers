# Regression Verification visibility fix

## Diagnosis before changes

- The active checkout was `codex/mini-ml-classifier` at `ff0672c`, with unrelated
  untracked `ml/mini_classifier/` work. It was left untouched. The fix uses the
  isolated `.data/regression-visibility` worktree on
  `codex/regression-verification-visibility`, based on fetched `origin/main`.
- The real engine is `apps/api/src/verification/regression-demo.ts`; it spawns the
  Node test runner, captures stdout/stderr and exit codes, compares original test
  identities, and saves evidence. The existing full pipeline also has Docker
  verification and patching infrastructure. No execution adapter was replaced.
- The saved demo endpoint is `GET /api/regression-demo/evidence`; analysis records
  use `GET /api/runs/:id/verification`. The existing Evidence Rail and
  `PatchWorkspace` consume analysis records, not the separate demo report.
- Neither role's navigation nor the React router had a Regression Verification
  entry. No frontend code loaded the executed demonstration. This was the
  visibility defect even on current main; pushing backend code alone could not
  add a visible frontend feature.
- Direct HTTP probes of `https://proofpatch-r2.vercel.app` returned 200 HTML;
  `/api/health` returned 200 JSON with analysis available and Docker configured;
  `/api/auth/me` and `/api/regression-demo/evidence` returned 401 JSON. The API is
  reachable, and anonymous evidence access is protected. No authenticated
  production records were accessed. A 401 alone does not prove which protected
  handler is deployed.
- The served asset `/assets/index-ChUZUtvN.js` contained Evidence Rail and Patch
  Studio, but no Regression Verification, Recorded Test Run, or demo-report API
  reference. The existing dashboard deep link returned the SPA shell (200).
- There is no tracked `vercel.json`, local `.vercel` project binding, Vercel CLI,
  or Vercel account connection available. The GitHub deployments API returned
  404 without authentication. Therefore the exact production commit, configured
  branch, and account-side build settings could not be verified. No stale
  deployment claim is inferred from that limitation.
- `apps/web/src/lib/api.ts` uses relative `/api` requests with same-origin
  cookies. There is no `VITE_API_URL` setting in the current implementation.
  Vite's local proxy targets port 3001. Existing production API forwarding works
  and must be preserved.

## Changes

Both authenticated dashboards now expose **Regression Verification** at
`/developer/app/verification` and `/reviewer/app/verification`. Patch Studio links
retain the selected run and patch. The existing Evidence Rail remains available.
Saved analysis mode uses the existing API schemas, hooks, patch source viewer,
verification status logic, and execution timeline. Missing records show
**Not yet executed** / **Verification incomplete**.

The public `/verification` route, also linked from the landing page, gives judges
an evidence viewer independent of login or backend availability. It is explicitly
labeled **Recorded Test Run** and does not execute tests or imply that the
deployed application or an arbitrary repository was tested.

`apps/web/public/evidence/regression-demo.json` packages the authentic retained
run `1f862e38-3746-48ee-98ef-a73b1ff3d217` from commit `676b811`, together with
its original source, patched source, unchanged functional tests, and security
test. Original commands, logs, timestamps, outcomes, diff, and provenance are
preserved. The packaging script does not create or change outcomes. It can be
repeated with:

```powershell
node ../../node_modules/tsx/dist/cli.mjs scripts/package-regression-evidence.mts
```

That relative runtime path applies to the isolated worktree; a normal checkout
can use `npx tsx scripts/package-regression-evidence.mts` with installed dependencies.

The viewer supports loading the bundled record, loading a saved backend demo
report, downloading the authentic packaged record, and importing report JSON.
Imported files are identified as not independently authenticated. Missing code
in a raw report stays unavailable. Verification is assessed from recorded stages,
exit codes, nonempty tests/logs, per-test preservation, integrity flags, and the
saved comparison; the `VERIFIED` label alone is insufficient.

No backend/authentication behavior, environment configuration, dependencies,
existing global styling, or teammate ML files were changed.

## Actual validation

- `npm run build -w @proofpatch/web`: exit 0, including frontend TypeScript.
  Vite emitted the existing large-chunk warning for Monaco; this did not fail
  the build. An initial sandboxed attempt failed on filesystem EPERM; the
  permitted rerun succeeded.
- `node ../../node_modules/vitest/vitest.mjs run tests/ui tests/contracts.test.ts`:
  exit 0, **46 tests passed** (20 existing UI evidence tests, 13 existing shared
  contract tests, 9 recorded-proof checks, 4 navigation/empty-state checks).
- `npm run demo:regression -- .data/verification-smoke`: exit 0. Real fixture
  execution produced baseline 5/5 exit 0; pre-patch security 0/3 exit 1;
  post-patch security 3/3 exit 0; unchanged functional suite 5/5 exit 0. Patch
  provenance was deterministic because this isolated local run had no Groq key.
  This new run did not replace the published historical artifact.
- Browser inspection of the production build at `http://127.0.0.1:4175/verification`
  confirmed the original source, patched source, all four test stages, real
  traversal leak logs, Recorded Test Run label, and final recorded verdict.
  Attempting protected API loading without a session showed the authentication
  error while preserving the already loaded recorded evidence.
- A UI screenshot is saved as `docs/regression-verification-preview.png`.

## Merge and redeploy

The fix branch is separate. It does not automatically merge or publish to
production. From a **clean checkout** after the branch has been pushed:

```powershell
git fetch origin
git switch main
git pull --ff-only origin main
git merge --no-ff origin/codex/regression-verification-visibility
git push origin main
```

If a teammate has changed overlapping code, resolve and verify the merge before
pushing. Never force-push. A GitHub pull request from the fix branch to `main`
can perform the same reviewed merge.

In Vercel, inspect the existing project for `proofpatch-r2.vercel.app`. Confirm
the production Git branch is the branch receiving the merge. For a repository
root build, the expected settings are:

- Root Directory: repository root.
- Install: `npm ci` (or the project's existing equivalent).
- Build: `npm run build -w @proofpatch/web`.
- Output: `apps/web/dist`.

These are recommended settings derived from the repository, **not a claim about
the settings currently stored in Vercel**. If the project is already rooted in
`apps/web`, retain that working monorepo configuration and its appropriate output
directory (`dist`). Keep the existing `/api` forwarding and SPA fallback; do not
replace them with a blanket rewrite that serves HTML for API requests.

Trigger **Redeploy** of the merged production commit if Git auto-deployment does
not start. Do not redeploy the old commit. No new frontend environment variable
is required. After deployment verify:

1. `/verification` loads the Recorded Test Run and all evidence without login.
2. `/evidence/regression-demo.json` returns JSON, not the SPA shell.
3. Both dashboard navigation menus and Patch Studio link to verification.
4. `/api/health` still returns JSON; saved analysis evidence remains authenticated.

Account-side production deployment remains to be performed/confirmed through
the existing Vercel project. No successful production redeployment is claimed.
