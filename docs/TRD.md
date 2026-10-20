# TRD.md — Technical Requirements Document

**Product:** Agricultural Biotechnology Security Platform (ABSP)
**Companion documents:** `PRD.md` (what), `Decision.md` (why, ADR form), `Architecture.md` (how it fits together)

---

## 1. Technology selection method

Every technology below is justified in the fixed format required by the project brief:

```
Technology · Why required · Why it fits · Alternative considered · Why alternative rejected
```

Two hard filters were applied before any choice:

* **Specification priority.** The exam brief explicitly names TensorFlow, Hyperledger Fabric, BLAST,
  QGIS/OpenDroneMap, CI/CD security scanning, and USDA/Codex/GS1 standards. Named technologies win
  unless a documented constraint blocks them (see ADR-003 for Fabric).
* **Environment constraint C-3.** PyPI is unreachable in the build environment. The Python runtime
  set is therefore fixed to what is pre-installed. This *removes* choices; it does not lower the
  security bar, because every security control below is implementable with the standard library
  plus `cryptography`.

## 2. Frontend

| Field | Value |
|---|---|
| **Technology** | Dependency-free ES2022 modules + semantic HTML + CSS custom properties; charts as hand-rendered inline SVG |
| **Why required** | FR-X5 dashboards, FR-D4 consumer verification, UI for every persona |
| **Why it fits** | Constraint C-4 (offline, no CDN) and C-3; zero build step means the demo cannot fail on a toolchain error; no `node_modules` means no JS supply-chain attack surface — directly aligned with the platform's own software-supply-chain security theme |
| **Alternative considered** | React + Vite + Recharts |
| **Rejected because** | Adds a build step and ~1,100 transitive packages for a 20-screen internal tool; npm reachable but the artefact must run offline on an unknown examination machine; the risk/benefit is negative here |

Structure: `frontend/index.html` (app shell), `frontend/app.js` (router, API client, state),
`frontend/views/*.js` (one module per screen), `frontend/assets/styles.css`, `frontend/verify.html`
(public, unauthenticated). Served as static files by the backend.

## 3. Backend

| Field | Value |
|---|---|
| **Technology** | Python 3.12 + FastAPI 0.138 + Uvicorn, modular monolith |
| **Why required** | All API requirements (FR-A*, FR-B*, FR-C*, FR-D*, FR-F*) |
| **Why it fits** | The AI and bioinformatics workload (TensorFlow, scikit-learn, sequence alignment) is Python-native, so a Python API removes a whole cross-service boundary; FastAPI gives Pydantic validation at every trust boundary (NFR-11), dependency-injected authorisation, and OpenAPI generation for free (FR-E1) |
| **Alternative considered** | Node.js/NestJS API + separate Python AI service |
| **Rejected because** | Two runtimes, two dependency trees, two container images and an extra network hop for zero functional gain on a single-machine deployment (C-5) |

API style: REST/JSON over HTTP, versioned at `/api/v1`, OpenAPI 3.1 auto-generated.
See ADR-006 for REST vs GraphQL vs gRPC.

## 4. Database

| Field | Value |
|---|---|
| **Technology** | SQLAlchemy 2.0 ORM over SQLite (dev/demo) and PostgreSQL 16 (production path) |
| **Why required** | Relational, highly-joined domain: org → farm → field → device → telemetry; batch → events → certifications |
| **Why it fits** | One ORM layer, one set of models, two engines; SQLite makes the offline demo a single file with zero setup (C-4, C-6), PostgreSQL is the documented production target in `docker-compose.yml` and Terraform |
| **Alternative considered** | MongoDB |
| **Rejected because** | Referential integrity and multi-entity joins are the core of traceability; losing foreign keys to gain schema flexibility is the wrong trade for a compliance system |

Parameterised queries only (ORM), no string-built SQL — see `Security.md` §12.
Migrations: versioned SQL scripts under `backend/migrations/` (ADR-014 explains why not Alembic).

## 5. Cache and message broker

| Field | Value |
|---|---|
| **Decision** | **Not used.** In-process TTL cache for AI model handles and rule sets; background work via FastAPI `BackgroundTasks` |
| **Why** | Single-node demo (C-5); Redis/Kafka would add two containers and two failure modes with no measurable benefit at demo scale. YAGNI. |
| **Production path** | Redis for the rate-limit bucket store and session denylist; Kafka/MQTT bridge for telemetry at fleet scale — documented in `IoT-Devices.md` §14 and `Architecture.md` §9 |

## 6. AI / ML

| Component | Technology | Why this technique |
|---|---|---|
| Telemetry anomaly detection (FR-A5) | scikit-learn `IsolationForest`, one model per device class | Unsupervised: no labelled attack data exists for farm telemetry; robust to multivariate drift; fast enough to score inline |
| Crop disease vision (precision-ag imagery) | TensorFlow/Keras CNN (small, CPU) | Specification names TensorFlow and computer vision for crop monitoring |
| Sequence screening (FR-C1) | Custom k-mer index + Smith–Waterman local alignment | Specification names BLAST and "custom sequence screening tools"; BLAST binaries are unavailable offline, so the same algorithmic principle (seed-and-extend, local alignment, bit-score/E-value style ranking) is implemented directly — see ADR-008 |
| CRISPR risk assessment (FR-C2) | Weighted rule model + PAM-aware off-target scan | Risk must be explainable to a biosafety officer; a black-box classifier would be unauditable |
| Food fraud detection (FR-D3) | Deterministic integrity rules + `IsolationForest` on event features | Rules give explainability and legal defensibility; the model catches novel patterns |
| DURC monitoring (FR-C3) | Rule correlation over hazard class × intent × technique | Policy, not statistics — must be reviewable |

Model artefacts are versioned in `ai/models/` with a `model_card.json` recording training data
provenance, metrics and limitations. All training data is synthetic and labelled as such.

## 7. Blockchain and smart contracts

| Field | Value |
|---|---|
| **Technology** | Permissioned, in-process ledger implementing the Hyperledger Fabric transaction model: MSP identities, ECDSA P-256 signing, endorsement policies, ordering, SHA-256 hash-linked blocks with Merkle roots, key/value world state, chaincode-style contracts in Python |
| **Why required** | FR-B1, FR-B2, FR-B4, FR-D1, FR-F3 |
| **Why it fits** | Preserves the Fabric *semantics* the specification asks for (permissioned membership, endorsement, immutability, world state, chaincode) while satisfying C-2 and C-4: no 2 GB image pull, no external network, starts in milliseconds, fully testable in CI |
| **Alternative considered** | (a) Real Hyperledger Fabric test network, (b) Ethereum/Ganache + Solidity |
| **Rejected because** | (a) Requires Docker Hub pulls, a 6-container topology and ~10 minutes of start-up — cannot be relied on for an offline examination demo, and CI cannot run it cheaply; (b) a public/permissionless chain with gas economics is the wrong trust model for a consortium of four known, KYC'd organisations |
| **Honesty marking** | **DEMO/SIMULATION** where consensus and multi-node ordering are concerned; **REAL** cryptography (ECDSA P-256, SHA-256, Merkle trees). Migration path to production Fabric with a chaincode function mapping table is in `Blockchain-integration.md` §17 |

Smart contracts implemented as chaincode-shaped modules: `gmo_registry`, `provenance`,
`certification`, `compliance_anchor`.

## 8. IoT

| Field | Value |
|---|---|
| **Technology** | HTTP/JSON telemetry ingestion with HMAC-SHA256 device authentication, monotonic nonce and timestamp replay window; Python device simulator |
| **Why required** | FR-A1, FR-A2, FR-A4 |
| **Why it fits** | HMAC over a shared secret issued at provisioning gives per-device identity, integrity and replay protection with no PKI to operate offline; the security envelope is identical whether the transport is HTTP or MQTT |
| **Alternative considered** | MQTT + Mosquitto broker with mutual TLS |
| **Rejected because** | Requires a broker container and a client library that is not installed (C-3); the security properties demonstrated would be the same. MQTT/mTLS is the documented production path (`IoT-Devices.md` §14) |

Device classes: drone, soil sensor, weather station, yield monitor, irrigation controller,
cold-chain sensor.

## 9. Authentication and authorisation

| Concern | Technology | Notes |
|---|---|---|
| Password storage | `bcrypt` (cost 12) | Used directly, not via passlib — passlib 1.7.4 is incompatible with bcrypt 5.x |
| Session tokens | PyJWT, HS256, short-lived access (30 min) + refresh (7 d) with rotation and denylist | ADR-007 covers HS256 vs RS256 |
| Authorisation | RBAC with explicit permission constants, enforced by a FastAPI dependency on every route | Deny by default |
| Tenancy | Organisation scoping enforced in the data-access layer, not in handlers | Prevents cross-tenant leakage (FR-X3) |
| Device auth | HMAC-SHA256 + nonce + 300 s window | Separate credential type; devices cannot obtain user tokens |
| Brute force | Per-account lockout after 5 failures, exponential backoff | FR-X1 |

## 10. Cloud, containers, orchestration, IaC

| Field | Value |
|---|---|
| **Containers** | Docker, multi-stage builds, non-root user, pinned base digests, `HEALTHCHECK`, read-only root filesystem where possible |
| **Local orchestration** | Docker Compose: `api`, `postgres`, `ledger-explorer` (static), `iot-simulator` |
| **Kubernetes** | Manifests provided (`infrastructure/k8s/`): Deployment, Service, Ingress, HPA, NetworkPolicy, PodSecurityContext, Secret/ConfigMap templates. Not required for the demo (C-5) |
| **Cloud / IaC** | Terraform for AWS (VPC, private subnets, ECS/EKS, RDS PostgreSQL, S3, IAM least-privilege, Secrets Manager, CloudWatch, ECR, ALB, security groups) |
| **Why AWS** | ADR-005: broadest managed coverage of every component the specification implies; RDS + Secrets Manager + ECR map 1:1 to our database, secrets and registry needs |
| **Alternative** | Azure / GCP — rejected on parity grounds; the Terraform layout is deliberately provider-isolated so a port is a module swap |

## 11. CI/CD and security tooling

| Stage | Tool | Requirement |
|---|---|---|
| Pre-commit | `scripts/pre-commit.sh` — format, lint, secret scan, fast tests | FR-E1 |
| Lint / format | `ruff`-compatible style rules, enforced in CI | FR-E1 |
| Unit + integration tests | `pytest` | FR-E2, NFR-12 |
| SAST | Bandit + Semgrep | FR-E2 |
| SCA / dependency | `pip-audit` + `safety`-style advisory check | FR-E3 |
| Secret scanning | Gitleaks + local `scripts/secret_scan.py` | NFR-6 |
| Container scanning | Trivy | FR-E3 |
| IaC scanning | Checkov + `tfsec` | FR-E3 |
| DAST | OWASP ZAP baseline against the running container | FR-E2 |
| SBOM | CycloneDX generation and artefact upload | FR-E3 |
| Smoke tests | `scripts/smoke_test.py` post-deploy | §37 of brief |

## 12. Pinned runtime set (environment constraint C-3)

| Library | Version present | Used for |
|---|---|---|
| fastapi | 0.138.0 | API |
| uvicorn | installed | ASGI server |
| pydantic | 2.12.5 | Validation at trust boundaries |
| sqlalchemy | 2.0.51 | ORM |
| pyjwt | 2.13.0 | JWT |
| bcrypt | 5.0.0 | Password hashing |
| cryptography | 49.0.0 | ECDSA P-256, AES-GCM, X.509 primitives |
| numpy | 2.4.4 | Numeric |
| scikit-learn | 1.9.0 | Isolation Forest |
| tensorflow | 2.21.0 | CNN crop vision |
| pytest / httpx | 9.1.1 / 0.28.1 | Testing |

**No new Python dependency is introduced anywhere in this repository.** Anything else needed
(rate limiting, k-mer indexing, alignment, QR encoding, Merkle trees, HMAC) is implemented on the
standard library.

## 13. Observability

Structured JSON logging with correlation IDs and automatic redaction of secret-shaped fields;
separate application / security / audit log streams; `/health`, `/health/ready`, `/health/live`;
Prometheus-format `/metrics` (request count, latency histogram, ingestion rate, ledger height,
AI inference count, auth failures).

## 14. Testing frameworks

`pytest` with `httpx`/FastAPI `TestClient` for unit, integration, E2E, RBAC and security suites;
a custom load harness (`tests/performance/`) using the standard library for NFR-1…NFR-4.

## 15. Development tooling

`scripts/run_local.sh` (one-command start), `scripts/seed_demo.py`, `scripts/demo_flow.py`
(scripted end-to-end demonstration), `scripts/security_scan.sh`, `Makefile`-equivalent shell
entrypoints, `.env.example`, `.editorconfig`.
