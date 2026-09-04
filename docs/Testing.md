# Testing.md — Testing Strategy and Results

Every category below is implemented and passing, not merely planned. Full run:
`python3 -m pytest backend/tests/ -q` → **382 passed**. Frontend: a full headless-Chrome
smoke test walks all 23 authenticated views plus the public page (see §7).

---

## 1. Test inventory

| Suite | File | Count | Covers |
|---|---|---|---|
| Security primitives | `test_security_primitives.py` | 30 | bcrypt, JWT (incl. `alg:none`), HMAC, AES-GCM, hashing, verification codes |
| Ledger | `test_ledger.py` | 43 | Identity, Merkle proofs, genesis, endorsement, contract rules, tamper detection |
| AI | `test_ai.py` | 55 | Sequence screening, CRISPR risk, anomaly detection, fraud rules, crop vision, data provenance |
| Authentication | `test_auth.py` | 27 | Registration, login, lockout, refresh rotation + reuse detection, suspension |
| Authorization (security) | `security/test_authorization.py` | 35 | RBAC matrix, route-coverage (mechanical), HTTP-level denial, tenancy isolation |
| Hardening (security) | `security/test_hardening.py` | 99 | SQL injection, XSS storage, headers, error hygiene, input limits, rate limiting, log redaction, public endpoint exposure |
| Devices & telemetry | `test_devices_telemetry.py` | 29 | Provisioning, HMAC auth, replay, validation/quarantine, lifecycle, vulnerability management |
| Biosecurity API | `test_biosecurity_api.py` | 26 | Screening workflow, CRISPR workflow, hazard database |
| Supply chain E2E | `test_supplychain_e2e.py` | 51 | GMO registration, traceability, certification authentication, fraud/integrity, compliance, public verification, blockchain/audit, dashboards |
| Config safety | `test_config_safety.py` | 8 | Production refuses missing/placeholder secrets; development still works with none set |
| Performance | `performance/test_performance.py` | 15 | API latency, telemetry throughput (inline vs deferred), screening scaling, ledger append/verify, concurrency |
| **Total** | | **382 (backend)** | |

## 2. Unit testing

**Backend:** security primitives, permission matrix, repository scoping helpers.
**AI:** every algorithm tested in isolation — sequence alignment on exact/diverged/benign/
reverse-complement inputs, CRISPR scoring components, off-target scanning against a planted
site, anomaly rule fallback, fraud rule triggers one at a time, crop-vision class separability.
**Blockchain:** every contract function tested for its success path and every rejection path
(duplicate id, unauthorised submitter, illegal transition, quantity violation).
**Utility functions:** canonical hashing, timestamp windowing, Merkle proof construction.

## 3. Integration testing

**Database:** every service test runs against a real (SQLite) database with foreign keys
enforced; fixtures build real organisations, users, farms and devices through the ORM.
**APIs:** every router is exercised through `TestClient` end to end (auth → permission →
schema → service → repository → database).
**IoT:** device provisioning through activation through authenticated ingestion through
anomaly scoring — one continuous path, not mocked at any layer.
**AI:** invoked through the real HTTP endpoints (`/biosecurity/screenings`, `/biosecurity/crispr`,
`/ai/crop-vision`), not called directly, so serialization and permission checks are covered too.
**Authentication:** the full token lifecycle including rotation and reuse detection.

## 4. End-to-end testing

`test_supplychain_e2e.py` and `scripts/demo_flow.py` both drive the complete business
workflow: screen a sequence → register a GMO event → record jurisdictional approvals →
produce a seed lot → create a batch → record five chain-of-custody events → attach a
shipment with cold-chain telemetry → issue and link a certification → run integrity
verification → evaluate compliance → generate an environmental impact assessment →
verify publicly by QR code → **tamper with a stored record and prove the platform detects
it** → verify the audit hash chain. `demo_flow.py` runs this against a live HTTP server
(not `TestClient`) so it is a genuine black-box rehearsal of the presentation.

## 5. Security testing

| Category | Where | Result |
|---|---|---|
| Authentication | `test_auth.py` | Lockout after 5 failures verified durable across the failing request; refresh reuse kills the whole token family |
| Authorization / RBAC | `security/test_authorization.py` | Every one of 9 roles' permission set asserted; mechanical check that every mutating route declares an authorisation dependency |
| Tenancy isolation | `security/test_authorization.py::TestTenancyIsolation` | A rival organisation gets 404 (not 403) for a foreign farm/device/field |
| Injection | `security/test_hardening.py::TestSqlInjection` | 6 SQL payloads tried against login, query filters and path parameters; data survives |
| Stored-content safety | `TestStoredContentIsNotExecutable` | XSS payloads stored as inert data; static assertion that no frontend file uses `innerHTML` or `eval` |
| Dependency vulnerabilities | CI (`pip-audit`) | Runs on every push; see `.github/workflows/ci.yml` |
| Secrets detection | `scripts/secret_scan.py` + CI Gitleaks | 141 files scanned locally, clean; CI adds Gitleaks history scanning |
| Container vulnerabilities | CI (Trivy) | Scans the built image for CRITICAL/HIGH CVEs; fails the build |
| IaC vulnerabilities | CI (Checkov) | Scans Terraform, Kubernetes manifests and the Dockerfile |
| Smart-contract vulnerabilities | `test_ledger.py::TestContractRules` | Unauthorised submitter, duplicate identifier, illegal transition, quantity violation, custody-transfer authority — all rejected |
| IoT security | `test_devices_telemetry.py::TestDeviceAuthentication`, `TestReplayProtection` | Wrong secret, tampered payload, stale/future timestamp, non-monotonic sequence, identical replay — all rejected with the correct status |
| AI security | `security/test_hardening.py::TestInputLimits` | Oversized/invalid-alphabet sequences rejected before reaching the alignment engine |

## 6. Performance testing

Measured, not assumed (`performance/test_performance.py`, run with `-s` to print figures):

| Metric | Result |
|---|---|
| API read p95 (farms, devices, dashboard, alerts, screenings) | 8–16 ms |
| Telemetry ingestion, inline AI scoring | 25 messages/s |
| Telemetry ingestion, scoring deferred to a background task | 155 messages/s |
| Sequence screening, 5 kb query against 10 hazards | 0.14–0.58 s |
| Ledger block append | p95 < 1 ms |
| Full-chain verification, 121 blocks / 82+ signatures | 24 ms |
| 40 concurrent API reads across 8 threads | completes without error |
| 30 concurrent ledger submissions | all commit exactly once; chain remains valid |

The ingestion-cost breakdown (`test_ingestion_cost_breakdown`) attributes the per-message cost:
security controls (HMAC + validation + AES-GCM) together cost under 0.03 ms; scikit-learn's
per-call anomaly-scoring overhead is 6.5–10 ms and dominates the budget. This finding is the
basis for the revised NFR-2 in `PRD.md`.

## 7. Frontend testing

No unit-test framework was added for 23 dependency-free view modules (YAGNI — each is a thin
declarative composition of the shared `core.js` primitives, which are tested through use).
Instead, correctness is verified where it actually matters: does the page render, and does a
write round-trip through the real API. Verified with a headless Chrome (Playwright) session:

* All 23 authenticated views render without a console error, under the platform's own strict
  CSP (`script-src 'self'; style-src 'self'`), for both a broad-permission role (Administrator)
  and a narrow one (Farm Operator, confirming role-filtered navigation).
* The public `/verify.html` page renders with no session at all.
* A farm is created through the UI form and appears in the list without a page reload.
* A CRISPR risk assessment and a sequence screening are each submitted through their forms and
  produce a verdict, navigating to the correct detail view.
* Device-detail navigation resolves correctly from a table link.

This exercise caught two real regressions during development (recorded in
the project's defect log): a broken form-toggle after a CSS refactor, and two
CSP violations from styles/scripts that had not yet been externalised — neither of which any
API-level test could have found, because the API side of both bugs was correct.

## 8. Test data and environment

Tests run against an isolated SQLite database in a temporary directory
(`backend/tests/conftest.py`), never the developer's own `absp.db`. No test requires network
access. Rate limiters are reset between tests so they cannot starve each other, and the
authentication rate limiter is exercised deliberately in its own test rather than being
disabled globally.

## 9. Known gaps

* No automated accessibility audit tool (e.g. axe-core) was run; the frontend follows WCAG 2.1 AA
  principles by construction (semantic landmarks, labelled controls, focus rings, `aria-live`)
  but this has not been independently verified — see `PRD.md` NFR-14.
* Load testing beyond 40 concurrent requests was not performed; the measured figures establish an
  order of magnitude on a single developer machine, not a capacity model for production traffic.
