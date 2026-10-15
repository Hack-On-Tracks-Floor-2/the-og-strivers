# AI usage rules

These rules are enforced in code (`apps/api/src/ai/`, `scanners/funnel.ts`, `patching/`), not just documented.

## Providers and keys
- Providers are tried in `AI_PROVIDER_ORDER` (default `groq,gemini`): Groq first, Gemini as fallback. A provider without a key is skipped.
- Keys (`GROQ_API_KEY`, `GEMINI_API_KEY`) live only in the server `.env`. They are never sent to the browser, logged, or stored in run evidence.
- Each provider call has a timeout (`AI_TIMEOUT_MS`, default 90 s). Groq requests size `max_completion_tokens` to fit its per-minute limit (`GROQ_TOKEN_BUDGET`, default 8,000), counting the prompt.
- Free tiers may use submitted content to improve their services. Demo with public open-source repositories only.

## What the AI sees (token-efficient search funnel)
1. **No AI:** source files are listed, skipping tests, vendored, generated and >200 KB files.
2. **No AI:** dangerous "sinks" are matched per vulnerability class. Bandit runs in the sandbox. Candidates are scored (sink weight + user input in the same function + scanner agreement). Only the top 6 are kept.
3. **No AI:** each candidate is cut to its enclosing function with Python's `ast` module (parse only, never executed), up to 45 lines.
4. **One AI call** confirms which snippets are real vulnerabilities.
5. **One AI call per attempt** writes the patch. It sees only the confirmed function, the file's imports, the names of existing test files, and on retry the last ~1,500 characters of the failure.

The AI never receives whole files, the whole repository, logs beyond that tail, or any key.

## Untrusted content
- Repository text is wrapped in a `<<<DATA … DATA>>>` block. The system prompt says it is untrusted and must never be followed as instructions.
- The AI has no tools: it cannot run code, browse, read files or call the network. Its output is JSON validated against a schema, and anything else is rejected.
- Secret-looking values (private keys, cloud/GitHub/Slack/Google/Groq/OpenAI tokens, JWTs, connection-string passwords, `password/secret/token/api_key = "…"`) are replaced with `«SECRET_n»` placeholders before sending. They are restored only in the returned edits, so patches still apply to the real file. The count is recorded in the run's evidence.

## Budget and evidence
- Every run has a hard token cap (`RUN_TOKEN_BUDGET`, default 30,000). A step that would exceed it is refused with a clear error.
- Identical prompts are served from an in-memory cache and not charged again.
- Each AI call is recorded as an `ai_usage` event: the provider, model, input/output tokens, the cache hit, the redaction count and the running total.

## What the AI is not trusted with
- **Edits:** AI edits are exact search/replace blocks. Each must match the file exactly once, stay inside the workspace, touch ≤ 2 files and ≤ 40 changed lines, and never modify existing tests.
- **Patch acceptance:** a patch counts only after real execution in the sandbox. The AI-written exploit test must fail on the original code (reproduction), pass on the patched code (security retest), and every previously passing test must still pass (regression).
- **Approval:** the AI never approves anything. A human reviewer makes the decision, and approval requires all recorded evidence.
