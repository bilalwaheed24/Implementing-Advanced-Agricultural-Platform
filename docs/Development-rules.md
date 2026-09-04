# Development-rules.md — Engineering Rules

Binding rules for anyone working in this repository. "MUST" is enforced in review or CI.

---

## 1. Coding standards

* Python 3.12, 4-space indent, max line length 100, UTF-8, LF endings.
* Type hints on every public function signature. Pydantic models at every I/O boundary.
* Docstrings on modules and on any function whose behaviour is not obvious from its name.
* No wildcard imports. Standard library → third party → local import order.
* Functions do one thing; a function longer than ~60 lines needs a reason.
* No bare `except:`; catch the narrowest exception and either handle or re-raise as a domain error.
* No mutable default arguments; no global mutable state except explicit caches.
* All datetimes are timezone-aware UTC (`datetime.now(timezone.utc)`), never naive.
* Comparisons of secrets or MACs use `hmac.compare_digest`.
* Randomness for anything security-relevant uses `secrets`, never `random`.

## 2. Naming conventions

| Thing | Convention | Example |
|---|---|---|
| Module / package | `snake_case` | `supply_chain.py` |
| Class | `PascalCase` | `SupplyChainEvent` |
| Function / variable | `snake_case` | `verify_device_signature` |
| Constant | `UPPER_SNAKE` | `MAX_SEQUENCE_LENGTH` |
| Permission constant | `domain:action` | `certification:issue` |
| Database table | plural `snake_case` | `supply_chain_events` |
| API path | plural kebab/lower | `/api/v1/supply-chain/events` |
| Test | `test_<unit>_<condition>_<expected>` | `test_ingest_replayed_nonce_rejected` |
| Frontend module | one view per file | `views/devices.js` |

## 3. Folder structure

Fixed at the repository root: `backend/`, `frontend/`, `ai/`, `ledger/`, `iot/`,
`infrastructure/`, `scripts/`, `security/`, `docs/`, `.github/`. New top-level directories require
an ADR. Inside `backend/app/`: `core/`, `routers/`, `services/`, `models.py`, `schemas.py`,
`repositories.py`.

## 4. Git workflow and branching

`main` is always releasable and protected. Work happens on `feat/<slug>`, `fix/<slug>`,
`sec/<slug>`, `docs/<slug>`, `chore/<slug>`. No direct pushes to `main`. Rebase before merge;
squash-merge with a Conventional Commit title.

## 5. Commit conventions

Conventional Commits: `type(scope): summary` where type ∈ `feat, fix, sec, docs, test, refactor,
chore, ci, perf`. Summary in the imperative, ≤ 72 characters. A security fix uses `sec:` and must
reference the threat id from `Security.md` where one applies.

## 6. Pull-request requirements

A pull request MUST: describe what and why; list the requirement IDs it satisfies; include tests
for new behaviour; pass every CI gate; update the affected documents (including
`REQUIREMENTS-TRACEABILITY.md` status); contain no secrets; and note any new `ponytail:`-style deliberate
simplification with its ceiling.

## 7. Code-review requirements

At least one reviewer. A reviewer MUST check: authorisation declared on every new route; tenancy
scoping used for every data read; input validated at the boundary; no string-built SQL; no secret
or PII in logs; errors do not leak internals; new dependencies (there must be none) justified;
tests actually assert behaviour rather than that code ran.

## 8. Testing requirements

Every new route gets at least: a success test, an unauthenticated test, and a wrong-role test.
Every new business rule gets a unit test including its failure branch. Security-relevant behaviour
(replay, tenancy, lockout, chain verification) gets an explicit test. No pull request may reduce
the number of passing tests. Tests must not depend on network access.

## 9. Security requirements for contributors

Deny by default. Never widen a permission set to make a test pass. Never disable a security header,
a validator or a rate limit for convenience. Never log a token, password, device secret, private
key or full sequence payload. Never introduce `eval`, `exec`, `pickle.loads`, `yaml.load` on
untrusted input, or shell interpolation of user data.

## 10. Dependency rules

**No new runtime dependency may be added** (constraint C-3 and control §17 of `Security.md`). If
one is unavoidable, it requires an ADR stating the alternative implementations rejected, a licence
check, a maintenance check, and a scan result. Versions are pinned exactly. Base images are pinned
by digest.

## 11. Environment-variable rules

All configuration comes from the environment and is validated at start-up by a typed settings
object. Every variable is documented in `.env.example` with a safe placeholder. No variable may
have a production-usable default. Code never reads `os.environ` directly outside the settings
module.

## 12. Secrets rules

NEVER commit: passwords, API keys, private keys, blockchain private keys, cloud credentials,
database credentials, JWT secrets, device secrets, or any real `.env`. `.gitignore` excludes
`.env*` (except `.env.example`), `*.pem`, `*.key`, `ledger_data/`, `*.db`. Rotate immediately if a
secret is exposed, and record it as an incident.

## 13. API conventions

Versioned under `/api/v1`. Plural resource nouns. Standard verbs. Pagination via `page` and
`page_size` (cap 200) returning `{items, total, page, page_size}`. Errors are RFC-7807-shaped:
`{type, title, status, detail, correlation_id}`. Status codes: 200/201/204, 400 validation,
401 unauthenticated, 403 unauthorised, 404 not found or not visible to this tenant, 409 conflict,
422 semantic validation, 429 rate limited, 500 unexpected. `404` is preferred over `403` where
revealing existence would itself leak tenancy information.

## 14. Database migration rules

Forward-only, numbered, reviewed SQL in `backend/migrations/`. Never edit an applied migration.
Every migration is idempotent where possible and is tested by running it against a fresh database
in CI. Destructive changes require an explicit backup step and a rollback note. Traceability and
audit tables never receive `UPDATE` or `DELETE` migrations.

## 14a. Security state on error paths (MUST)

A route handler commits only on its success path. Any security-relevant state change made
immediately before raising — a failed-login counter, an account lockout, a revoked token family, a
device authentication-failure counter — MUST therefore be committed by the service that makes it.
Three separate controls in this codebase were silently inert for exactly this reason: the change
was flushed, the exception unwound, and the session rolled back. If a control only matters when
the request fails, its persistence cannot depend on the request succeeding.

## 15. Error handling

One exception hierarchy (`AppError` → `ValidationError`, `AuthError`, `PermissionError`,
`NotFoundError`, `ConflictError`, `IntegrationError`). Services raise domain errors; a single
handler maps them to HTTP. Stack traces go to logs, never to clients. External integrations
(ledger, AI) are wrapped so their failure degrades the response rather than failing the request.

## 16. Logging

Structured JSON. Every line carries `timestamp`, `level`, `logger`, `correlation_id`, and where
known `actor_id`/`org_id`. Security events go to the security logger; business-significant actions
go through the audit service, not the logger. A redaction filter strips values whose key matches
`password|secret|token|key|authorization|hmac|private`.

## 17. Documentation rules

Documents in `docs/` are normative. Changing behaviour without updating the affected document is an
incomplete change. Each document has one purpose; content is cross-referenced, not duplicated.
Every simulated or mocked capability must be labelled `REAL IMPLEMENTATION`, `DEMO/SIMULATION`, or
`MOCK` wherever it is described.

## 18. Docker rules

Multi-stage builds; non-root user; pinned base digest; no secrets in build args or layers;
`.dockerignore` excludes `.git`, `.env`, tests and data; `HEALTHCHECK` present; images scanned by
Trivy in CI; runtime filesystem read-only except declared volumes.

## 19. CI/CD rules

Every push and pull request runs the full gate set. A HIGH or CRITICAL finding in SAST, SCA, secret
scanning or container scanning fails the build. Workflows pin actions by commit SHA and declare
least-privilege `permissions`. Deployment happens only from `main` after all gates pass, and is
followed by smoke tests.

## 20. Definition of done

Code + tests + documentation updated + requirement traceability status updated + all CI gates green
+ no new secrets + the feature demonstrable from the UI or a script.
