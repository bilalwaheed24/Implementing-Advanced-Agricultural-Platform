# Security.md — Security Architecture, Threat Model and Controls

Security is treated as a design input, not a release gate. This document is written against
`Architecture.md` (trust boundaries) and is the source for the security tests in
`backend/tests/security/`.

---

## 1. Security objectives

| ID | Objective | Requirement |
|---|---|---|
| SO-1 | Only authenticated, authorised principals reach data, and only their own organisation's data | FR-X1, FR-X2, FR-X3 |
| SO-2 | Device data is authentic, integral and non-replayable | FR-A1 |
| SO-3 | Provenance records are tamper-evident and independently verifiable | FR-B4, FR-F3 |
| SO-4 | Agronomic and commercial data cannot be bulk-exfiltrated unnoticed | FR-A3 |
| SO-5 | Hazardous biological designs are screened before approval | FR-C1 |
| SO-6 | The build pipeline cannot ship known-vulnerable or secret-bearing artefacts | FR-E1…E3 |

## 2. Threat model (STRIDE, per trust boundary)

| ID | Boundary | Threat | STRIDE | Control |
|---|---|---|---|---|
| T-01 | TB-1 public | Consumer endpoint enumerated to harvest the batch graph | I, D | Opaque 128-bit verification codes, rate limiting, non-sensitive projection only |
| T-02 | TB-2 user | Credential stuffing / brute force | S | bcrypt cost 12, lockout after 5 failures, timing-neutral failure path |
| T-03 | TB-2 user | JWT forgery or `alg:none` downgrade | S, E | Explicit algorithm allow-list on decode, signature+exp+iss+aud verified, no default secret in production (an *absent* `JWT_SECRET` is preserved as empty through settings construction so the production startup check catches it, rather than being silently backfilled with a random value — see `SECURITY-ASSESSMENT.md`) |
| T-04 | TB-2 user | Stolen refresh token reuse | S | Rotation with reuse detection; denylist by `jti`; family invalidation |
| T-05 | TB-2 user | Horizontal privilege escalation across organisations | E, I | Org scoping in the repository layer (ADR-015), automated cross-tenant tests |
| T-06 | TB-2 user | Vertical escalation (operator performing certifier actions) | E | Deny-by-default RBAC; permission constant required on every route; coverage test |
| T-07 | TB-3 device | Spoofed device identity | S | HMAC-SHA256 over canonical payload with per-device secret |
| T-08 | TB-3 device | Replay of captured telemetry | T | Nonce cache + 300 s timestamp window + monotonic sequence check |
| T-09 | TB-3 device | Compromised device injecting false readings | T | Physical-range validation, AI anomaly scoring, quarantine lifecycle |
| T-10 | TB-3 device | Device secret theft from the database | I | Secrets stored AES-256-GCM encrypted with the device id as associated data; the key lives in the environment/KMS, not in the database, so a database dump alone does not yield usable secrets. Plaintext is returned once at provisioning |
| T-11 | TB-4 ledger | Retroactive alteration of provenance | T, R | SHA-256 hash-linked blocks, Merkle roots, signature verification on replay |
| T-12 | TB-4 ledger | Forged endorsement | S | Per-organisation ECDSA P-256 verification against registered MSP public keys |
| T-13 | TB-5 AI | Adversarial or oversized input to screening/vision | D, T | Length caps, alphabet allow-list, content-type checks, timeouts |
| T-14 | TB-6 DB | SQL injection | T, I | ORM-only parameterised access; no string-built SQL anywhere |
| T-15 | TB-6 DB | Data exfiltration via bulk export | I | Export rate limits, page-size caps, anomaly detection on access patterns, audit |
| T-16 | TB-7 CI | Malicious dependency or leaked secret in the repository | T, I | Gitleaks, pip-audit, Trivy, pinned digests, SBOM, no-new-dependency policy |
| T-17 | All | Repudiation of an action | R | Hash-chained audit log with actor, IP, correlation ID, ledger anchoring |
| T-18 | All | Sensitive data disclosure through errors or logs | I | Central error handler, no stack traces to clients, log redaction filter |
| T-19 | TB-1/2 | Denial of service through expensive endpoints | D | Rate limiting per identity and per IP, pagination caps, screening length caps |
| T-20 | TB-2 | XSS / clickjacking / MIME sniffing in the UI | T, E | CSP, `X-Frame-Options: DENY`, `nosniff`, `textContent`-only DOM writes |

## 3. Attack surface

Public: `/`, `/verify`, `GET /api/v1/verify/{code}`, `/health`, `/docs` (disabled in production).
Authenticated: ~90 REST routes. Device: `POST /api/v1/telemetry/ingest`, `POST /api/v1/telemetry/batch`.
Non-HTTP: SQLite/PostgreSQL socket, ledger state files, environment variables, container image,
CI workflow definitions.

## 4. Security architecture (layers)

```
L1 Ingress    security headers, CSP, CORS allow-list, rate limiting, body size cap
L2 Identity   bcrypt(12), JWT HS256 + kid, refresh rotation, lockout, device HMAC
L3 Authz      deny-by-default RBAC, permission per route, org scoping in data layer
L4 Input      Pydantic types, domain range checks, alphabet allow-lists, size caps
L5 Data       AES-GCM at rest for sensitive payloads, TLS in transit, redacted logs
L6 Integrity  audit hash chain, ledger anchoring, Merkle inclusion proofs
L7 Supply     SAST/SCA/secrets/container/IaC scanning, SBOM, pinned digests, no new deps
```

## 5. Authentication

Registration requires an organisation and is admin-approved for privileged roles. Passwords: ≥ 12
characters, checked against a common-password list, hashed with bcrypt cost 12. Login failures are
constant-response and increment a per-account counter; five failures lock the account for an
increasing interval. Access tokens live 30 minutes and carry `sub`, `org`, `role`, `jti`, `iat`,
`exp`, `iss`, `aud`. Refresh tokens live 7 days, rotate on use, and are denylisted on rotation;
reuse of a rotated token invalidates the whole token family and raises a `CRITICAL` alert.

## 6. Key management

| Key | Storage | Rotation |
|---|---|---|
| JWT signing secret | Environment / Secrets Manager | `kid` header supports overlapping rotation |
| Data encryption key (AES-GCM) | Environment / KMS in production | Versioned key ids on each ciphertext |
| Device secrets | AES-256-GCM encrypted at rest (key from environment/KMS), plaintext returned once | Rotation issues a new secret and invalidates the old immediately |
| Ledger organisation keys | `ledger_data/msp/` in the demo, HSM/KMS in production | Documented in `Blockchain-integration.md` §14 |

Migration trigger to RS256/JWKS is recorded in ADR-007: the first additional token verifier.

## 7. Authorisation and least privilege

Nine roles (`PRD.md` §11) map to explicit permission constants such as `device:write`,
`biosecurity:review`, `certification:issue`, `compliance:read`, `audit:read`. Every route declares
one. `REGULATOR` cannot mutate any other party's operational data. Its set contains every read
permission plus exactly two non-read permissions: `compliance:run`, which computes and stores a
compliance report, and `gmo:approve`, which records the regulator's own jurisdictional decision
(and is the only ledger transaction a regulator submits). It holds no permission over farms,
devices, batches, certifications, users, or biosecurity review. A test asserts both halves of
this: the exact set of non-read permissions, and the absence of each operational write. Cross-organisation reads require the explicit `unscoped()` accessor, which is permitted only for
the four platform-wide oversight roles — `ADMIN`, `REGULATOR`, `SECURITY_ANALYST` and
`BIOSAFETY_OFFICER` — and is always audit-logged. Security and biosafety oversight are
platform-wide by definition: an analyst who could not see another tenant's device alerts could not
do the job the platform exists to support. The set is defined once, in `core/permissions.py`, and
imported by the repository layer, the request dependencies and the notification fan-out.

## 8. Input validation and output encoding

All request bodies are Pydantic models with types, bounds and patterns. Domain validators enforce
physical plausibility (soil moisture 0–100 %, pH 0–14, temperature −60…80 °C), nucleotide alphabet
`[ACGTUNRYKMSWBDHVacgtu]`, sequence length ≤ 100 kb, page size ≤ 200. Responses are JSON only; the
frontend writes to the DOM with `textContent` and builds elements programmatically — no
`innerHTML` interpolation, no `eval`, no inline event handlers (enforced by CSP).

## 9. Encryption

*In transit:* TLS terminated at the ALB/ingress in production; HSTS set; local demo is HTTP on
loopback only, documented as such.
*At rest:* sensitive telemetry payloads and biosecurity sequences are encrypted with AES-256-GCM
using a key from the environment, with a per-record nonce and the record id as associated data;
database-level encryption (RDS KMS) in production; ledger blocks are hashed and signed, not
encrypted (integrity, not confidentiality, is their purpose).

## 10. Secrets management

No secret is committed. `.env.example` documents every variable with a placeholder. The application
refuses to start in `ENV=production` if `JWT_SECRET`, `ENCRYPTION_KEY` or `DB` credentials are
absent or equal to a development default. Gitleaks runs in CI and `scripts/secret_scan.py` runs
pre-commit and can be run locally offline.

## 11. Blockchain and smart-contract security

Transactions are signed with ECDSA P-256 and verified against the registered MSP public key before
endorsement. Contracts validate: caller organisation is permitted for the operation, referenced
state exists, state transitions follow the allowed lifecycle, quantities are conserved, and no
duplicate transformation-event identifiers are created. Replay is prevented by content-hash
transaction ids. Blocks verify parent hash, Merkle root and every signature on replay; the chain
verification endpoint reports the first divergent block. Known limitation: single-node ordering
(ADR-003).

## 12. Database security

ORM-parameterised access only; least-privilege database user in production (no DDL at runtime);
foreign keys enforced (including `PRAGMA foreign_keys=ON` for SQLite); append-only traceability and
audit tables; backups encrypted; connection strings from environment.

## 13. IoT device security

Provisioning issues a device id and a 256-bit secret shown once. HMAC verification requires the
secret to be recoverable, so it is stored encrypted rather than hashed: AES-256-GCM with the device
id as associated data, under a key held outside the database. A stolen database is therefore not
sufficient to forge telemetry. Every message is authenticated,
timestamped, nonced and range-validated. Device state machine: `PROVISIONED → ACTIVE → SUSPENDED →
QUARANTINED → RETIRED`; quarantine and retirement immediately reject telemetry. Firmware version
and known vulnerabilities are tracked per device with severity and remediation status (FR-E3).
Offline devices buffer and replay with per-message nonces, so a replayed batch is rejected.

## 14. AI security

Inputs are size- and alphabet-constrained; inference runs with a wall-clock budget; model files are
loaded from a fixed path and their SHA-256 is recorded in the model card (integrity of the artefact
supply chain); no model input is echoed back unescaped; screening results that would block are
never silently downgraded by the model — only a human biosafety officer can release a `BLOCKED`
record, and that action is audited.

## 15. Container and Kubernetes security

Multi-stage build, non-root `UID 10001`, no shell in the runtime layer where avoidable, dropped
capabilities, read-only root filesystem with explicit writable volumes, `HEALTHCHECK`, pinned base
image digest, `.dockerignore` excluding `.env`, `.git`, tests and data. Kubernetes: `runAsNonRoot`,
`allowPrivilegeEscalation: false`, `seccompProfile: RuntimeDefault`, resource limits,
`NetworkPolicy` default-deny with explicit egress, secrets mounted from a `Secret`, not baked in.

## 16. Cloud and network security

Private subnets for compute and database; no public database; security groups deny by default and
allow only ALB→app and app→RDS; IAM roles scoped per task with no wildcard resources; S3 buckets
private, versioned, SSE-KMS; CloudTrail/CloudWatch enabled; secrets in Secrets Manager with
rotation documented.

## 17. Software supply-chain security

Zero new Python dependencies (constraint turned into a control); pinned versions recorded in
`requirements.txt` with the exact versions verified in the environment; SBOM generated in CI;
container base images pinned by digest; GitHub Actions pinned by commit SHA; dependency and
container scanning gate the build.

## 18. Detection: agricultural data theft (FR-A3)

Signals: request volume per principal above a rolling baseline; page-size maximisation across
sequential requests; access outside the principal's historical hours; access to farms the principal
has never touched; export endpoints hit repeatedly; failed cross-tenant attempts. Each signal
contributes to a weighted score; crossing the threshold raises a `HIGH` security alert, records an
incident, and can trigger automatic rate reduction for that principal.

## 19. Security logging and audit

Three streams: application, security (authn/authz outcomes, rate-limit hits, device auth failures),
and audit (business-significant actions). Audit records are hash-chained (ADR-010) and carry actor,
role, org, action, entity, before/after summary, IP, user agent and correlation id. Sensitive
fields are redacted by a logging filter that matches secret-shaped keys.

## 20. Incident response

Detect (alert) → triage (analyst acknowledges, severity set) → contain (quarantine device, revoke
token family, suspend user) → eradicate → recover → review. Incidents are first-class records with
a timeline of linked alerts and actions. Containment actions are available as API operations so the
response is auditable rather than manual.

## 21. Backup, recovery and disaster recovery

Database: nightly full plus point-in-time recovery in production (RDS); demo: file copy script.
Ledger: block files are append-only and replicated with the database backup; chain integrity is
verified after any restore. Documented RPO 15 minutes, RTO 1 hour for the production path.
Restoration is validated by running the chain verification and audit verification endpoints.

## 22. Data privacy

Personal data is limited to user account fields. Farm and agronomic data is commercially sensitive
and is org-scoped. No personal data is written to the ledger (ADR-011), preserving the ability to
erase. Public verification exposes only batch, product, certification status and coarse origin —
never farmer identity, exact coordinates, or contract data.

## 23. Secure coding practices

Deny by default; validate at the boundary; parameterise all queries; no secrets in code; no
`eval`/`exec`/`pickle` on untrusted input; explicit algorithm allow-lists for JWT; constant-time
comparison for secrets and HMACs (`hmac.compare_digest`); `secrets` module for all token
generation; UTC-aware datetimes; exceptions never carry secrets; every new route must declare a
permission and gain a test.

## 24. Standards alignment

OWASP ASVS L2 as the control baseline; OWASP Top 10 (2021) and API Security Top 10 mapped in the
threat table; NIST SP 800-53 families AC, AU, IA, SC, SI as the audit vocabulary; NIST SSDF for the
pipeline; ISO 27001 Annex A for governance framing; USDA/FDA/Codex/GS1 for domain compliance rules
(see `docs/flow.md` and the compliance engine).
