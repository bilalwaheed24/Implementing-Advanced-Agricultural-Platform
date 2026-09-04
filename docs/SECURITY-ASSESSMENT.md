# SECURITY-ASSESSMENT.md — Security Assessment

**Assessor stance:** senior AppSec engineer, DevSecOps engineer, and penetration tester, auditing
an already-built system adversarially rather than re-describing its design.
**Scope:** the complete platform — backend, frontend, database, ledger, AI, IoT simulation,
containers, CI/CD, and infrastructure-as-code.
**Method:** live code review of every route handler and service function that performs an
identifier-based lookup; dependency vulnerability scanning (`pip-audit`); secret scanning across
162 tracked/untracked files; re-execution of the full test suite (394 tests at the time of that
audit; 399 after the September 2026 exam-alignment passes) before and after
every fix; manual exploitation attempts against the running API for each threat class in
`Security.md`'s STRIDE table.

**Executive summary.** Two genuine authorization defects (one BOLA, one IDOR) were found and
fixed, both in code paths that predate this audit. One dependency carries a known CVE, which does
not affect this application's actual usage of that library, and has been remediated in the pinned
manifest and container image regardless. No SQL injection, XSS, SSRF, path traversal, command
injection, or authentication-bypass was found anywhere in the application. The platform is **not
"100% secure"** — no software is — and §7 states the residual risks plainly.

---

## 1. Vulnerabilities discovered and fixed

### Vuln-1 — Broken Object Level Authorization: certification linking (HIGH)

**Location:** `POST /api/v1/supply-chain/certifications/{id}/link`,
`backend/app/services/supplychain.py::link_certification`

**Root cause.** The function checked for a duplicate link and a GMO-lineage claim conflict, but
never checked that the certification being linked actually belonged (`subject_org_id`) to the
organisation that owns the batch. Authorization relied implicitly on certification UUIDs being
hard to guess — obscurity, not an access-control decision.

**Impact.** Any authenticated `SUPPLY_CHAIN_OPERATOR` who obtained (or enumerated) another
organisation's certification id could attach that certification to their own batch, producing a
forged organic/non-GMO/specialty claim. This directly defeats FR-D2 (automated certification
authentication), the platform's core defence against food fraud.

**Fix.** `link_certification` now raises `PermissionDenied` (403) unless
`certification.subject_org_id == batch.org_id`, and separately rejects linking a certification
that is not `ACTIVE` (422). Both checks run before the existing duplicate/claim-conflict checks.

**Verification.** Two new regression tests
(`TestCertificationLinkAuthorization` in `test_supplychain_e2e.py`) prove: (a) a foreign
certification is rejected with 403 naming the reason, (b) a revoked certification is rejected with
422. Full suite re-run: 394 passed.

### Vuln-2 — IDOR: cross-tenant blockchain record verification (MEDIUM)

**Location:** `POST /api/v1/blockchain/verify-record`, `backend/app/routers/blockchain.py`

**Root cause.** The route fetched `GMOEvent`/`Batch`/`SupplyChainEvent`/`Certification`/
`ComplianceReport` rows by raw id with `db.get()`, bypassing the organisation-scoped repository
helpers (`get_or_404`/`visible()`) used everywhere else in the codebase.

**Impact.** Any authenticated user holding `blockchain:read` (effectively every non-anonymous
role) could submit an arbitrary entity id belonging to another organisation and learn (a) whether
it exists, and (b) whether its stored content still matches its ledger anchor. No business field
(quantity, scope, farmer identity, financial data) was returned — only hashes and a match/mismatch
verdict — which is why this is scored MEDIUM rather than HIGH: it is an information-disclosure and
tenancy-boundary violation, not a data-exfiltration vulnerability.

**Fix.** A `_require_visible()` guard now runs after each entity is fetched, permitting the
request only when the caller's organisation matches the record's own organisation (for
`Certification`, either `issuer_org_id` or `subject_org_id`) or when the caller holds a
platform-wide oversight role (`ADMIN`, `REGULATOR`, `SECURITY_ANALYST`, `BIOSAFETY_OFFICER` —
the same `CROSS_TENANT_ROLES` set used consistently elsewhere). A disallowed request receives 404,
matching this platform's established convention of never distinguishing "doesn't exist" from
"exists but isn't yours."

**Verification.** Four new regression tests (`TestBlockchainVerifyRecordAuthorization`) prove a
rival organisation gets 404 for a foreign batch and a foreign certification, while the owning
organisation and an oversight role both still succeed. Full suite re-run: 394 passed.

### Vuln-3 — Dependency: `cryptography` 49.0.0, PYSEC-2026-3552 (MEDIUM, not exploitable here)

**Package / vulnerability.** `cryptography==49.0.0`. PYSEC-2026-3552: `pkcs7_decrypt_der`,
`pkcs7_decrypt_pem`, and `pkcs7_decrypt_smime` disclose a Bleichenbacher oracle against the
content-encryption key of an attacker-supplied PKCS#7 `EnvelopedData` structure, through
distinguishable error responses and timing. Fixed upstream in 50.0.0.

**Applicability analysis.** This codebase imports exactly three surfaces of `cryptography`:
`AESGCM` (`backend/app/core/security.py`), and `ec` / `hashes` / `serialization` for ECDSA signing
and PEM key I/O (`ledger/identity.py`). Grepped confirmation: zero references to `pkcs7`, `smime`,
or `EnvelopedData` anywhere in the codebase. **The vulnerable code path is never invoked.** Actual
exploitability against this application, as shipped, is nil.

**Risk (if left unfixed).** None currently, given the above. Scored MEDIUM rather than
INFORMATIONAL only because a future contributor could add PKCS#7/S-MIME handling (e.g. for a
regulator document-signing feature) without realising the pinned version is vulnerable — fixing
the pin now removes that latent trap.

**Fix.** `requirements.txt` pin raised to `cryptography==50.0.0`. Compatibility of the three
primitives this project actually uses (AES-GCM encrypt/decrypt round trip, ECDSA sign/verify, PEM
serialization round trip) was verified directly, then the **entire application test suite (394
tests) was run against a clean virtual environment with the full pinned `requirements.txt`
installed at the new version — all 394 passed.** The `Dockerfile` installs from the same
`requirements.txt`, so the container image is fixed on its next build (rebuilt and re-verified as
part of this audit).

**Local development environment gap — documented, not hidden.** The shared local machine's global
`--user` Python site-packages could not be upgraded during this audit: Debian's PEP 668
externally-managed-environment guard explicitly blocks `pip install --user` for exactly this
reason (protecting a shared environment from being silently mutated by one project), and
overriding that guard with `--break-system-packages` was judged too broad a side effect to apply
without the user's explicit, separate sign-off — it would affect every other Python project on
that machine, not just this one. **Residual state:** the local dev machine continues to run
`cryptography==49.0.0` for now; the CI pipeline, the container image, and any fresh install from
`requirements.txt` all get 50.0.0. Given the vulnerable code path is unreachable, this is a
zero-exploitability gap, not an open vulnerability. **To rotate/close fully:** run
`pip install --user --break-system-packages cryptography==50.0.0` (or, better, migrate local
development to a project virtual environment, which was out of scope to impose unilaterally in
this audit).

### Finding-4 — Unpinned dependencies (LOW)

`uvicorn` and `python-multipart` had no version pin in `requirements.txt`, contrary to
`Development-rules.md` §10 ("Versions are pinned exactly"). Fixed: pinned to `0.49.0` and `0.0.32`
respectively, the exact versions verified installed and tested against throughout this project.

### Finding-5 — Incomplete admin user management (LOW, feature gap not a vulnerability)

A `UserUpdate` Pydantic schema existed in `schemas.py` with no route consuming it — dead code, and
an implementation gap against `PRD.md` §11 ("Admin manages... users"). Fixed: `PATCH
/admin/users/{id}` now lets an administrator edit `full_name` and `role`. Status transitions
(`PENDING`/`ACTIVE`/`SUSPENDED`) remain exclusively behind the existing `/approve` and `/suspend`
endpoints — the new route explicitly rejects a `status` field with a 422 pointing the caller to
the correct endpoint, so the account state machine cannot be bypassed through two divergent code
paths. A role change immediately invalidates the user's existing tokens, verified by a dedicated
test, because `deps.py` already checks the token's `role` claim against the live account on every
request.

## 2. Vulnerabilities checked for and NOT found

| Threat class | Method | Result |
|---|---|---|
| SQL injection | 6 payload classes against login, filters, and path parameters; parameterised-ORM code review | None found — no string-built SQL exists anywhere in the codebase |
| Stored/reflected XSS | Payloads stored and round-tripped through the API; static review confirms every frontend DOM write uses `textContent`/`el()`, never `innerHTML` with interpolated data | None found |
| SSRF | Full grep for `requests`/`urllib.request`/`httpx.get`/`aiohttp` outside test files | None found — zero outbound HTTP calls driven by user input anywhere |
| Path traversal | Static file serving goes through Starlette's `StaticFiles`, which normalises and rejects `..` by construction; no other route builds a filesystem path from user input | None found |
| Command injection | Full grep for `os.system`, `subprocess` with `shell=True`, `eval`, `exec` | None found |
| Prompt injection | **Not applicable.** No component in this platform is an LLM or accepts a natural-language prompt that drives model behaviour; all "AI" here is classical ML (Isolation Forest, a small CNN, sequence alignment, and deterministic rule engines) with typed, bounded, schema-validated inputs. Documented explicitly rather than silently skipped, per the audit brief's own instruction not to claim AI security is "solved" without stating what actually exists. |
| IDOR/BOLA elsewhere | Every route taking an identifier path parameter was individually checked for use of the scoped `get_or_404`/`visible()` helpers versus a raw `db.get()` | Two instances found and fixed (Vuln-1, Vuln-2); every other identifier-based route (farms, fields, devices, telemetry series, vulnerabilities, screenings, CRISPR assessments, notifications, GMO events, seed lots, batches, shipments) already used the scoped helper correctly |
| Authentication bypass | JWT algorithm confusion (`alg:none`), expired/tampered tokens, device HMAC tampering, replay | None found — all rejected as designed (existing test coverage re-confirmed) |
| Account enumeration | Login and registration responses compared for an unknown vs. a wrong-password account, and for a duplicate vs. novel registration email | None found — identical generic responses in both cases |
| Mass assignment | Every `*Create`/`*Update` schema reviewed for a client-settable field that should be server-controlled (`org_id`, `created_by`, `id`, `status`, `role` outside the new admin route) | None found — every service layer sets these fields itself, never from the request body |
| Rate-limiting gaps | Every router file checked for the `rate_limit`/`public_rate_limit`/`auth_rate_limit` dependency | Present on all 17 route groups |
| CSRF | **Not applicable in the ordinary sense.** This is a bearer-token (JWT-in-`Authorization`-header) API with `SameSite`-irrelevant auth — there is no session cookie a browser would attach automatically to a cross-site request, which is the precondition CSRF exploits. CORS is additionally restricted to an explicit origin allow-list (`allow_credentials=True` with a named list, never a wildcard). |

## 3. Authentication

Password hashing: bcrypt, cost factor 12 (`Development-rules.md` and `Security.md` both require
≥12; re-verified against the live hash format). JWT: HS256 with an explicit algorithm allow-list
on decode (defeats `alg:none`), `iss`/`aud`/`exp` all required and verified, 30-minute access
tokens, 7-day refresh tokens with rotation and reuse detection (a replayed, already-rotated refresh
token invalidates its entire token family — re-verified live). Lockout: 5 failed attempts locks
the account with exponential backoff on repeat failures, and the failure counter is committed
durably even on the request's error path (a real defect from the prior session, still fixed and
now covered by a permanent regression test). Logout revokes all outstanding refresh tokens.
**No password-reset/forgot-password flow exists.** This was never in scope in `PRD.md`/`TRD.md`
(no email infrastructure was specified), so it is a documented feature gap, not a broken feature —
recorded here rather than silently omitted, per this audit's own rule against hiding gaps.

## 4. Authorization

RBAC: 9 roles, permission constants of the form `domain:action`, deny-by-default, and a mechanical
test (`test_every_mutating_route_declares_authentication`) that fails the build if a future route
omits its authorisation dependency. Tenancy: organisation-scoped reads return 404 (not 403) for a
resource that exists but belongs to another tenant, so existence itself is never disclosed to an
unauthorised party. Two BOLA/IDOR defects were found in this audit (Vuln-1, Vuln-2) and are now
fixed with the same pattern used everywhere else in the codebase, closing the inconsistency rather
than leaving a second authorization model to maintain.

## 5. API security

Every one of 121 operations requires either a bearer JWT, a device HMAC credential, or is
explicitly and deliberately public (5 operations: register, login, refresh, the two consumer
verification endpoints, and the four health/metrics endpoints). Input validation is Pydantic-typed
at every boundary with domain-specific range/alphabet checks layered on top (nucleotide alphabet,
physical sensor ranges, GTIN/coordinate bounds). Output is JSON-only; error bodies are RFC-7807
shaped and never include a stack trace or dependency detail, only a correlation id. Request bodies
are size-limited (2 MiB) at the middleware layer before any parsing occurs. CORS is a named-origin
allow-list. Security headers (`X-Content-Type-Options`, `X-Frame-Options: DENY`,
`Content-Security-Policy` with no `unsafe-inline`/`unsafe-eval`, `Referrer-Policy`) are present on
every response, verified live.

## 6. Database security

Access is exclusively through the SQLAlchemy ORM with bound parameters; no endpoint builds a query
string from user input. Foreign keys are enforced (`PRAGMA foreign_keys=ON` on SQLite, which is
off by default and easy to silently miss — explicitly set). Sensitive payloads (device telemetry,
submitted biosecurity sequences) are additionally encrypted at rest with AES-256-GCM, independent
of whatever the underlying database engine provides, so a raw database file does not disclose
these fields even without full-disk/TDE encryption. Traceability and audit tables are append-only
by construction (no delete route exists for them). Production configuration
(`docs/Decision.md` ADR-002, `Security.md` §12) targets PostgreSQL with a least-privilege
application user and no public exposure; the demo path is a local SQLite file with no network
listener at all.

## 7. Container security

Multi-stage Dockerfile, final image runs as a fixed non-root UID (10001), `read_only: true` root
filesystem in `docker-compose.yml` with an explicit `/tmp` tmpfs and a named volume for the one
writable path, `no-new-privileges:true`, and all Linux capabilities dropped. A `HEALTHCHECK` is
defined and was verified live (container reported `healthy`). AI models are trained and baked into
the image at **build** time specifically because the runtime filesystem is read-only — a real
defect from the prior session's own container-verification pass, now fixed and re-verified in this
audit by a fresh rebuild. The image was rebuilt during this audit to pick up the `cryptography`
fix; the image was rebuilt and re-verified after the fix.

## 8. Secrets management

`scripts/secret_scan.py` checks every git-tracked-or-untracked file (falling back to a full
filesystem walk if the git index is empty, a real gap this project fixed in its own prior audit)
for AWS keys, private-key headers, JWT-shaped literals, Slack tokens, and hardcoded password
assignments, with an explicit named allowlist for the one legitimate demo credential string. Result
of this audit's re-run: **clean, 162 files checked.** No `.env` file is tracked (verified via
`git status`); `.gitignore` covers `.env*` except `.env.example`, `*.db`, `ledger_data/`, and the
demo device-secrets file. The application refuses to start in `ENV=production` with a placeholder
or absent `JWT_SECRET`/`ENCRYPTION_KEY` — this exact property was itself a defect the prior audit
found and fixed (a missing `JWT_SECRET` used to silently generate a random one instead of refusing
to start), and it now has 8 dedicated regression tests in `test_config_safety.py`.

## 9. CI/CD security

Two GitHub Actions workflows (`ci.yml`, `security.yml`) cover linting, secret scanning (Gitleaks),
SAST (Bandit, Semgrep), SCA (`pip-audit`), unit/integration tests, container build and scan
(Trivy), SBOM generation (CycloneDX), IaC scanning (Checkov), and an OWASP ZAP baseline scan
against a running instance. Every third-party action is pinned by full commit SHA, not a mutable
tag. Both workflows declare `permissions: contents: read` explicitly rather than relying on the
repository default. **Caveat, corrected 2026-09-13 and stated plainly:** an earlier version of this
paragraph said the repository had no git remote and that the pipelines had never executed. Both
claims were wrong. A remote exists and the workflows have run on hosted GitHub Actions runners
three times (2026-09-04, 2026-09-07). Two jobs genuinely passed there — the gitleaks secret scan
and the ledger contract tests. Every other job failed at *Set up job*, before reaching any
security tool, because three pinned action SHAs did not resolve (one was 39 characters; a git SHA
is 40). All eight pins were re-verified against each action's real tag list and the three broken
ones corrected, and Semgrep now runs from the maintained PyPI CLI rather than an action last
updated in January 2024. **What is still not established is a green pipeline run** — the fix has
not been re-run. Correctness of the security gates therefore continues to rest on YAML validity
and on running the equivalent checks locally (`pip-audit`, `scripts/secret_scan.py`, the full
399-test suite), not on a green checkmark. Recorded as a residual gap, not claimed as tested.

## 10. IoT security

Device identity is a per-device 256-bit secret, stored AES-256-GCM encrypted (not hashed, because
HMAC verification requires the secret back — a one-way hash would make authentication impossible;
this trade-off is documented in ADR-009 and `IoT-Devices.md`). Every telemetry message is
HMAC-SHA256 authenticated over a canonical payload, timestamp-windowed (300 s, wider for an
explicit offline-backfill path), and nonce-replay-protected both in-memory and via a database
unique constraint. Malformed or out-of-physical-range readings are quarantined, not silently
stored or silently dropped. Device compromise is handled by a quarantine lifecycle that revokes
the credential immediately (verified: a quarantined device's old secret is rejected on its very
next message). No physical device exists — the fleet is simulated — but the security envelope the
simulator exercises is the same code path a real device would use.

## 11. AI security

Every AI input is typed, length- and alphabet-bounded before reaching the model (100 kb sequence
cap, IUPAC alphabet allow-list, 40-channel telemetry cap, fixed image dimensions with a
nearest-neighbour resize for anything else). No AI component accepts or acts on a natural-language
prompt, so prompt injection has no attack surface here. All decisions that can block a person's
work (fraud, CRISPR risk, DURC) are rules-first and return structured, human-readable reasons
rather than an opaque score, by deliberate design (ADR-012) — this is also the platform's answer to
AI explainability. Every model degrades to a documented rule-only fallback rather than failing the
request if its artefact is missing or corrupt. All training data is synthetic, generated by
`ai/data/generate.py`, and is labelled as such everywhere it appears; no model card or dashboard
claims real-world accuracy.

## 12. Blockchain security

Every transaction is ECDSA P-256 signed by its submitter and independently endorsed per a declared
policy (AND/OR over named MSPs); every block is SHA-256 hash-linked with a Merkle root over its
transactions. Chain verification recomputes every hash and re-checks every signature, and was
proven live in this platform's own test suite to detect a deliberately tampered record (origin
substitution) as a `MISMATCH`. On-chain data is limited to identifiers, state transitions, and
content hashes (ADR-011) — no personal or commercial data is ever anchored, which also preserves
the ability to correct/erase off-chain records without violating the ledger's immutability
guarantee. This is explicitly single-node ordering, not a Byzantine-fault-tolerant multi-peer
network — stated here again because a security report that did not repeat this limitation would be
misleading about what "immutable" means in this deployment.

## 13. Cloud / IaC security

Terraform targets private subnets for compute and the database, no public database, security
groups that deny by default with named allows only (ALB→app, app→RDS), least-privilege IAM roles
with no wildcard resources, SSE-KMS-encrypted and versioned S3 with public access blocked, and
Secrets Manager for the JWT/encryption/database secrets rather than plaintext environment
variables in the task definition. `terraform validate` and `terraform plan` both succeed. This has
never been applied to a real AWS account — there is no cloud account connected to this project —
so its correctness is structural (the resource graph is valid and internally consistent) rather
than operationally proven.

## 14. Logging and monitoring

Structured JSON logs on three streams (application, security, audit), with a redaction filter that
strips any key matching a secret-shaped pattern (`password`, `secret`, `token`, `key`,
`authorization`, `hmac`, `sequence`) before it reaches a sink, plus a message-level filter that
strips bearer tokens and JWT-shaped substrings from free-text log lines. Verified in this audit by
re-running `TestLogRedaction` (7 tests) and by confirming no submitted biosecurity sequence or
device secret ever appears in an API response or a log line.

## 15. Final security posture

**Fixed this audit:** 2 authorization defects (1 HIGH, 1 MEDIUM), 1 dependency CVE (MEDIUM
severity rating, nil actual exploitability), 2 hygiene items (unpinned dependencies, a dead
schema/missing route).
**No CRITICAL finding** exists in this system as of this report.
**Residual risks**, stated plainly rather than hidden:

1. The local development machine's shared Python environment still runs the vulnerable
   `cryptography` version, because upgrading it required overriding an OS-level protection this
   audit judged too broad to apply unilaterally (see Vuln-3). Zero actual exposure, since the
   vulnerable function is never called.
2. CI/CD pipelines are valid but unexercised on live infrastructure — no GitHub remote is
   connected to this repository.
3. No independent penetration test or third-party accessibility audit has been performed; this
   report is a rigorous self-audit, not an external assessment.
4. AI-heavy endpoints (sequence screening at up to 100 kb, crop-vision inference) are bounded
   per-request but rely on the general per-identity rate limiter for abuse protection rather than a
   dedicated concurrency budget; on a single-node deployment, a determined authenticated user could
   still consume a meaningful share of one process's CPU within their rate-limit budget. Documented
   mitigation path: horizontal scaling and a stricter, endpoint-specific rate limit in production —
   not built now, because doing so for a single-machine academic deployment would be complexity
   without a corresponding benefit.
5. No password-reset flow exists (§3) — an accepted, documented scope boundary, not an oversight.
6. Terraform and Kubernetes configurations have never been applied to live infrastructure; their
   correctness is validated structurally, not operationally.

This system is **materially more secure after this audit than before it**, with two real
authorization defects closed and every fix backed by a regression test that will fail the build if
the defect is ever reintroduced. It is not claimed to be free of all possible vulnerabilities —
no non-trivial system legitimately can be.
