# Executed regression demonstration

Implementation lives on `feature/regression-engine` in the separate worktree
`.data/regression-engine`. The original checkout and its UI changes are untouched.

From that worktree, run `npm run demo:regression`. No build, dependency install,
Docker daemon, ML training, downloaded repository, or external service is needed.
Node.js 24.20.0 was used for the recorded demonstration. Existing dependencies are
resolved from the parent checkout; no dependencies were added.

If an existing environment file lives elsewhere, set `REGRESSION_ENV_FILE` to its
path. The existing AI client tries **Groq only**, with a bounded timeout. With no
Groq key, a provider error, or an invalid proposal, the report explicitly labels
the fallback as **deterministic**. The checked-in demonstration used that fallback;
it does not claim an AI-generated patch.

The authored CommonJS fixture reads reports from a directory. Its initial
implementation permits `../private.txt`, sibling-prefix traversal, and nested
traversal. All secrets used in the attack are controlled marker strings created
in temporary folders by the tests, never host credentials or real user data.

Execution order:

1. Copy the trusted fixture and run its five original functional tests.
2. Introduce three security tests and execute them against the vulnerable copy.
   The failure output records the controlled data that escaped the report root.
3. Copy the original fixture into a different directory and apply exact source
   edits there. The patch resolves real paths and enforces directory containment.
4. Run the identical security tests against the patched source.
5. Rerun the unchanged original functional tests; compare outcomes by test identity.

Each stage launches the real Node test runner with a fixed argument array,
`shell: false`, a 30-second timeout, and an output limit. This entry point accepts
no arbitrary repository or command. The existing Docker-only handling for
untrusted repositories remains unchanged. This is a focused demonstration of
the regression proof, not a general host execution adapter.

`evidence/regression-demo/latest.json` contains the verdict, exact executable and
arguments, working directories, exit codes, stdout/stderr, timings, test outcomes,
comparison, hashes of unchanged tests, patch provenance, and unified diff. Each
run directory retains both working copies, individual JSON/text logs, JUnit XML,
`patch.diff`, and the report. A successful verdict requires baseline 5/5,
security-before 3 assertion failures with exit 1, security-after 3/3, regression
5/5, no missing previously passing tests, and unchanged test hashes. Missing
reports, timeouts, subprocess errors, and empty suites cannot produce VERIFIED.

The backend exposes `GET /api/regression-demo/evidence` behind the existing
session authentication. Start the API **from this worktree** using its existing
development command to load the route. `REGRESSION_EVIDENCE_DIR` can override the
evidence location. Anonymous requests return 401; missing evidence returns 404.
The route reads evidence only and cannot start code execution. The integration
test exercises these responses through the real Express application.

The controlled fixture proof and authenticated API are implemented. Arbitrary
Node.js repository support in the existing Python/Docker/AI pipeline is outside
this demonstration. Groq generation remains unverified because no key was
configured. Nothing is merged or pushed automatically.
