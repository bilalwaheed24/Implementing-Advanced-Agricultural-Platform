# Decision.md — Architecture Decision Records

Format per record: **Decision · Context · Options · Chosen approach · Reason · Trade-offs · Consequences**.
No major architectural choice in this project was made silently; every ADR below is referenced from
`TRD.md` or `Architecture.md`.

---

## ADR-001 — Modular monolith rather than microservices

**Decision.** Build one deployable backend composed of clearly bounded modules (identity, farm,
device, telemetry, ai, biosecurity, gmo, supplychain, compliance, ledger, audit) rather than
separate services.

**Context.** The specification spans six capability areas that look, on an architecture diagram,
like six services. The deployment target is a single machine for an offline examination demo (C-5,
C-6), and there is one engineer.

**Options.** (a) Microservices per capability. (b) Modular monolith. (c) Monolith with no internal
boundaries.

**Chosen.** (b).

**Reason.** The module boundaries that matter for maintainability are enforced by package
structure and typed interfaces, not by HTTP hops. Microservices would add service discovery,
inter-service auth, distributed tracing and 11 containers — cost with no benefit at this scale, and
a larger attack surface to secure. (c) is rejected because the boundaries genuinely differ in trust
level (biosecurity data ≠ telemetry).

**Trade-offs.** Independent scaling and independent deploys are lost. A fault in one module can
affect the process.

**Consequences.** Each module owns its routers, services and models, and communicates through
function calls with typed schemas. The seam is drawn so that `biosecurity`, `ai` and `ledger` can
be extracted into services later without changing their callers' contracts.

---

## ADR-002 — Relational database (SQLite dev / PostgreSQL prod) over document store

**Decision.** SQLAlchemy 2.0 against SQLite for the demo and PostgreSQL for production.

**Context.** Traceability is a graph of strongly related entities and must be provably complete;
compliance queries join across seven or more entities.

**Options.** (a) PostgreSQL only. (b) MongoDB. (c) SQLite dev + PostgreSQL prod on one ORM.

**Chosen.** (c).

**Reason.** Referential integrity is a *compliance control*, not a convenience: a supply-chain
event that references a non-existent batch is a data-integrity failure. SQLite removes all setup
from the offline demo; the same ORM models run on PostgreSQL unchanged.

**Trade-offs.** SQLite lacks concurrent write scalability and some PostgreSQL types; behavioural
differences (e.g. `JSONB` operators) must be avoided in queries.

**Consequences.** No PostgreSQL-only SQL is used. `DATABASE_URL` selects the engine. Foreign keys
are explicitly enabled on SQLite (`PRAGMA foreign_keys=ON`), which is off by default — a real
correctness trap.

---

## ADR-003 — Fabric-shaped permissioned ledger implemented in-process, not a production Fabric network

**Decision.** Implement the Hyperledger Fabric *model* — MSP identities, ECDSA endorsement,
ordering, hash-linked blocks with Merkle roots, world state, chaincode-style contracts — as an
in-process Python package (`ledger/`), and document the migration path to a real Fabric network.

**Context.** The specification names Hyperledger Fabric for supply-chain traceability. Constraints
C-2 and C-4 mean a real Fabric network (multiple peer/orderer/CA containers, ~2 GB of images,
minutes of start-up, network access for image pulls) cannot be depended upon for an offline
demonstration or for CI.

**Options.** (a) Real Fabric test network. (b) Ethereum/Ganache + Solidity. (c) Fabric-shaped
in-process ledger with real cryptography. (d) A fake "blockchain" that is only a database table.

**Chosen.** (c).

**Reason.** What the specification actually requires is the *security property* — tamper-evident,
multi-party, verifiable provenance under a permissioned identity model. (c) delivers exactly that
with real ECDSA P-256 signatures, real SHA-256 hash chaining and real Merkle inclusion proofs,
while starting instantly and being fully testable. (b) has the wrong trust model for a four-party
consortium of known organisations. (d) would be dishonest.

**Trade-offs.** No real distributed consensus, no multi-node Byzantine fault tolerance, no
independent physical custody of the ledger by each organisation. These are precisely the properties
a single-machine demo cannot honestly provide.

**Consequences.** Every artefact and screen that shows blockchain data carries the marking
**DEMO/SIMULATION — single-node ordering**. Cryptographic components are marked **REAL**.
`Blockchain-integration.md` §17 gives the function-by-function mapping from our contracts to Fabric
chaincode and the deployment steps to migrate.

---

## ADR-004 — Dependency-free frontend

**Decision.** Vanilla ES modules, semantic HTML, CSS custom properties, hand-rendered inline SVG
charts. No framework, no bundler, no `node_modules`.

**Context.** The demo must run offline on an unknown machine (C-4). The platform's own subject
matter is software supply-chain security; shipping ~1,100 transitive npm packages to render 20
internal screens would contradict the thesis of the project.

**Options.** (a) React + Vite + a chart library. (b) Server-rendered Jinja templates. (c) Vanilla
ES modules.

**Chosen.** (c).

**Reason.** Zero build step means the UI cannot fail on a toolchain error during a 20-minute
examination; zero third-party JavaScript means zero JS supply-chain risk and a trivially auditable
frontend; ES2022 modules, `fetch`, and CSS Grid cover every requirement natively (ladder rung 4:
the platform already does this).

**Trade-offs.** More hand-written DOM code; no component ecosystem; charts are bespoke.

**Consequences.** Strict discipline is required in `frontend/`: one module per view, a single API
client with automatic token refresh, a small render helper, and manual XSS-safe DOM construction
(`textContent`, never `innerHTML` with interpolated data).

---

## ADR-005 — AWS as the Infrastructure-as-Code target

**Decision.** Terraform targeting AWS; provider-isolated module layout.

**Context.** Cloud deployment is required by the brief (§26) but not by the demo. The IaC must be
credible and scannable by Checkov/tfsec.

**Options.** AWS, Azure, GCP, or cloud-agnostic Kubernetes-only manifests.

**Chosen.** AWS, with Kubernetes manifests also provided.

**Reason.** Every component we need has a first-class managed equivalent (RDS, ECR, Secrets
Manager, CloudWatch, ALB, VPC, IAM), which makes least-privilege IAM and encryption-at-rest
concrete rather than hypothetical.

**Trade-offs.** Provider lock-in in the IaC layer.

**Consequences.** Application code contains no AWS SDK calls; the cloud coupling stays inside
`infrastructure/terraform/`. No credentials are committed; `terraform.tfvars.example` is provided.

---

## ADR-006 — REST/JSON API with OpenAPI, not GraphQL or gRPC

**Decision.** Versioned REST at `/api/v1`, OpenAPI 3.1 generated from Pydantic models.

**Context.** Consumers are a browser UI, a device simulator, a public verification endpoint, and
regulators' tooling.

**Options.** REST, GraphQL, gRPC.

**Chosen.** REST.

**Reason.** Per-endpoint authorisation and rate limiting are the security model; GraphQL's single
endpoint makes field-level authorisation and query-cost control materially harder, which is the
wrong direction for a security platform. gRPC is a poor fit for browsers and public consumer QR
verification.

**Trade-offs.** Some over-fetching; more endpoints to document.

**Consequences.** Every route declares its required permission explicitly; the OpenAPI document is
generated and validated in CI.

---

## ADR-007 — HS256 JWT for the demo, RS256 documented for production

**Decision.** Symmetric HS256 access/refresh tokens, secret supplied by environment; refresh
rotation with a denylist.

**Context.** Single backend issuer and verifier (ADR-001). No key-distribution problem exists yet.

**Options.** HS256, RS256/EdDSA with JWKS, opaque server-side sessions.

**Chosen.** HS256 now; RS256 + JWKS documented as the production path once a second verifier exists.

**Reason.** With one issuer and one verifier, asymmetric signing adds key-management complexity
without adding a security property. The moment a second service verifies tokens, HS256 requires
sharing a signing secret — that is the trigger to migrate, and it is recorded in `Security.md` §6.

**Trade-offs.** Secret compromise means token forgery; all verifiers must hold the secret.

**Consequences.** The secret is environment-supplied, never defaulted in production (the app
refuses to start with a default secret when `ENV=production`), and rotation is supported by a key
identifier (`kid`) in the token header.

---

## ADR-008 — Custom seed-and-extend aligner instead of the BLAST binary

**Decision.** Implement k-mer seeding plus Smith–Waterman local alignment in `ai/sequence_screening.py`.

**Context.** The specification names "BLAST, custom sequence screening tools". NCBI BLAST+ binaries
are not installable offline (C-3/C-4), and biopython is unavailable.

**Options.** (a) Require BLAST+ at runtime. (b) Naive substring matching. (c) k-mer index +
Smith–Waterman with an affine-free scoring matrix and score-based ranking.

**Chosen.** (c).

**Reason.** BLAST's core method *is* seed-and-extend with local alignment; implementing it directly
preserves the biological meaning (detects diverged homology, not just exact substrings) with no
external binary. (b) would miss any mutated variant — a real biosecurity failure, not a
simplification.

**Trade-offs.** Slower and less statistically calibrated than BLAST; no true E-values against a
large reference corpus; suitable for a curated hazard database, not for screening against GenBank.

**Consequences.** Scores are reported as normalised identity plus alignment length and coverage,
with the hazard database's own severity class driving the verdict. Limits are stated in `GMO.md`
and in the model card. A production deployment should call a real BLAST/DIAMOND service; the
interface is isolated behind `screen_sequence()` so the backend is unaffected by that swap.

---

## ADR-009 — HMAC device authentication over mutual-TLS PKI

**Decision.** Per-device secret issued once at provisioning; every telemetry message carries
`device_id`, `timestamp`, `nonce`, and an HMAC-SHA256 over the canonical payload.

**Context.** FR-A1 requires real device identity and authenticated telemetry. Operating a device CA
offline, with revocation, is disproportionate for a simulator.

**Options.** (a) API key in a header. (b) HMAC with nonce + timestamp window. (c) X.509 client
certificates with mTLS.

**Chosen.** (b).

**Reason.** (a) provides identity but neither integrity nor replay protection — a captured request
can be replayed forever. (b) gives identity, payload integrity and replay resistance with stdlib
`hmac`, and the server-side model (registry, revocation, quarantine) is identical to what mTLS
would need. (c) is the production answer and is documented as such.

**Trade-offs.** A shared-secret scheme is symmetric, so the server must hold the secret to verify a
message. Secrets are therefore stored AES-256-GCM encrypted (key outside the database) rather than
hashed, and the plaintext is shown exactly once at provisioning. This concentrates risk in the
application encryption key; asymmetric device identity (option (c)) is the design that removes the
trade-off and is the documented production path.

**Consequences.** Nonce cache with a 300-second window; clock-skew handling; per-device replay
counters; revocation invalidates the secret immediately.

---

## ADR-010 — Hash-chained audit log in the primary database, anchored to the ledger

**Decision.** Append-only `audit_log` table where each row stores `prev_hash` and `entry_hash`,
with periodic anchoring of the chain head to the ledger.

**Context.** FR-F3 requires a tamper-evident audit trail. Writing every audit record to the ledger
would bloat it and leak sensitive detail into a shared structure.

**Options.** (a) Plain DB table. (b) Every audit record as a ledger transaction. (c) Hash-chained DB
table with periodic ledger anchoring.

**Chosen.** (c).

**Reason.** Detects any retroactive edit or deletion (the chain breaks), keeps sensitive detail
off-chain (privacy), and still gives an externally verifiable anchor. This is the standard
on-chain/off-chain split.

**Trade-offs.** Tampering is detectable but not preventable at the DB layer; detection granularity
is bounded by anchoring frequency.

**Consequences.** `GET /api/v1/audit/verify` recomputes the whole chain and reports the first
divergence. Audit writes are non-blocking and failures are themselves alarmed.

---

## ADR-011 — On-chain hashes and identifiers only; payloads off-chain

**Decision.** The ledger stores identifiers, state transitions, participant identities, timestamps
and SHA-256 content hashes. Full records, imagery, telemetry and personal data stay in the database.

**Context.** FR-B4 requires verifiable anchoring; privacy and data-protection requirements forbid
publishing farm-level commercial data to a shared ledger.

**Options.** (a) Full records on-chain. (b) Hash-only anchoring. (c) Encrypted payloads on-chain.

**Chosen.** (b).

**Reason.** A hash proves integrity and existence-at-a-time without disclosing content; ledgers are
immutable, so any personal data written to them can never be erased (a direct conflict with data
subject erasure rights). (c) merely defers the problem to key compromise.

**Trade-offs.** Verification requires possession of the off-chain record; losing the record loses
the ability to prove what was anchored.

**Consequences.** Every anchored entity stores `content_hash`, `tx_id` and `block_number`.
Verification recomputes the hash and compares it to the chain. A content hash must cover only
**immutable** facts: hashing a batch's current quantity or state made every legitimate processing
event register as tampering, so the anchor covers `initial_quantity` and identity fields, while
each state change is anchored by its own event transaction.

---

## ADR-012 — Explainable rules first, machine learning second

**Decision.** Fraud detection, CRISPR risk and DURC monitoring lead with deterministic rules;
unsupervised ML supplements them. Only anomaly detection and crop vision are ML-primary.

**Context.** Outputs may block a commercial release or a research proposal and must withstand
challenge by a regulator or a researcher.

**Options.** ML-first, rules-first, hybrid.

**Chosen.** Hybrid, rules-first for decisions that block.

**Reason.** "The model said so" is not an acceptable justification for blocking a gene-edit
proposal or a shipment. Rules produce a citable reason; the model contributes a score and catches
novel patterns.

**Trade-offs.** Rules require maintenance and can be gamed by an insider who knows them.

**Consequences.** Every AI verdict returns structured `reasons[]` evidence. Thresholds are
configuration, not constants buried in code.

---

## ADR-013 — Synthetic data, explicitly labelled

**Decision.** All datasets are generated by scripts in this repository and carry a provenance
header; every model card states that metrics are on synthetic data.

**Context.** Real agricultural telemetry, real hazard sequences and real fraud labels are not
available (and a real hazard sequence database would itself be an information-security concern).

**Options.** Use unlabelled public data, fabricate "real-looking" data silently, or generate and
label synthetic data openly.

**Chosen.** Generate and label openly.

**Reason.** Brief §23 forbids presenting synthetic data as real-world data; scientific honesty
requires the same.

**Trade-offs.** Reported model metrics do not predict real-world performance.

**Consequences.** Generators live in `ai/data/`; the UI displays a "demo data" badge; the final
report lists this as a known limitation.

---

## ADR-014 — Plain SQL migrations instead of Alembic

**Decision.** Versioned, numbered SQL migration files applied by a small runner in
`backend/migrations/`.

**Context.** Alembic is not installed and cannot be installed (C-3).

**Options.** (a) `create_all()` only. (b) Hand-written versioned SQL with a runner. (c) Vendor
Alembic.

**Chosen.** (b), with `create_all()` used for the fast test path.

**Reason.** (a) has no upgrade story and would fail requirement "database migration rules"; (c)
vendoring a dependency tree to avoid writing 40 lines is the wrong trade.

**Trade-offs.** No autogeneration; migrations must be written by hand and reviewed.

**Consequences.** `schema_version` table; forward-only migrations; migration review is a
pull-request requirement in `Development-rules.md`.

---

## ADR-015 — Security control placement: the data-access layer, not the handler

**Decision.** Tenancy scoping and permission checks are enforced by shared dependencies and
repository helpers, not re-implemented per route handler.

**Context.** Cross-tenant leakage (FR-X3, NFR-13) is the most likely serious defect in a
multi-organisation platform, and it arises from one forgotten `WHERE org_id = ?`.

**Options.** Per-handler checks; middleware-only checks; layered dependency + scoped repository.

**Chosen.** Layered.

**Reason.** A control that must be remembered on every one of ~90 routes will eventually be
forgotten. Making the scoped accessor the *only* convenient way to fetch data makes the secure path
the default path.

**Trade-offs.** Slightly more indirection; a deliberate cross-tenant read (regulator, admin)
requires an explicit, auditable escape hatch.

**Consequences.** `deps.py` provides `require_permission()`; the escape hatch `unscoped()` is
available only to the four platform-wide oversight roles (`ADMIN`, `REGULATOR`,
`SECURITY_ANALYST`, `BIOSAFETY_OFFICER`) and every use is audit-logged. That set is defined exactly
once, in `core/permissions.py`: it was originally restated in three modules, and the copies drifted
so that a security analyst could not see other tenants' device alerts at all. A test asserts that
every mutating route has an authorisation dependency.
