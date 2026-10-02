# Agricultural Biotechnology Security Platform (ABSP)

**Precision farming protection, GMO traceability, and food supply chain security for global
food systems.** Built for EduQual Level 6 Topic 135 (ANPP-OP).

> **Markings used throughout this repository:** `REAL IMPLEMENTATION` — a genuine, working
> control. `DEMO/SIMULATION` — a faithful stand-in for hardware or infrastructure this
> deployment cannot depend on (physical IoT devices, a production Hyperledger Fabric network).
> `MOCK` — not used; nothing in this repository fakes a result. Every simulated element is
> named as such at the point it appears. See `docs/EXAM-LIMITATIONS.md` for the full
> real-vs-simulated breakdown, and `docs/Decision.md` ADR-003.

---

## 1. What this is

A single platform combining three capabilities normally bought as three separate products:

| Capability | What it does |
|---|---|
| **Precision agriculture IoT security** | Cryptographic device identity, HMAC-authenticated and replay-protected telemetry, anomaly detection, vulnerability management |
| **GMO / biotechnology traceability** | Sequence biosecurity screening, CRISPR risk assessment, dual-use research monitoring, and blockchain-anchored GMO registration |
| **Food supply chain security** | EPCIS-shaped chain-of-custody, certification authentication, automated fraud detection, and consumer-facing QR verification |

Everything is tied together by a permissioned ledger and an automated regulatory compliance
engine (USDA, FDA, EU, Codex Alimentarius, GS1).

## 2. Architecture at a glance

```
Browser (23 top-level views, framework-free) ──┐
Public /verify.html (no login)      ──┤
IoT device simulator                ──┼──►  FastAPI backend (11 services, 16 routers, 121 API operations)
                                        │        │
                                        │        ├─► SQLite / PostgreSQL (34 tables)
                                        │        ├─► Permissioned ledger (ECDSA P-256, Merkle proofs)
                                        │        └─► AI services (screening, anomaly, fraud, CRISPR, vision)
```

Full detail: `docs/Architecture.md`. Every architectural choice is recorded as an ADR in
`docs/Decision.md`. The complete requirement-to-implementation trace is in
`docs/REQUIREMENTS-TRACEABILITY.md`.

## 3. Technology stack

Python 3.12 · FastAPI · SQLAlchemy 2 · Pydantic 2 · PyJWT · bcrypt · `cryptography` ·
scikit-learn · TensorFlow/Keras · dependency-free ES2022 frontend · Docker · Terraform (AWS) ·
Kubernetes manifests · GitHub Actions.

**No new Python dependency was added anywhere in this project** (Development-rules.md §10) —
the build environment has no PyPI access, so the stack is exactly what `requirements.txt` pins,
and everything else (rate limiting, QR codes, Merkle trees, sequence alignment) is implemented
on the standard library. See `docs/TRD.md` for the full technology-decision rationale.

## 4. Repository structure

```
agri-biotech-security-platform/
├── backend/            FastAPI app: core, models, schemas, services, routers, tests
├── ai/                 Screening, CRISPR risk, anomaly detection, fraud, crop vision, models
├── ledger/             Permissioned ledger: identities, blocks, contracts, chain
├── iot/                Device simulator (DEMO/SIMULATION fleet, real security envelope)
├── frontend/           28 view modules, framework-free ES modules, public verify.html
├── infrastructure/     Terraform (AWS) and Kubernetes manifests
├── scripts/            run_local.sh, seed_demo.py, demo_flow.py, train_models.py, smoke_test.py
├── security/           Disclosure policy and OWASP ZAP rules
├── docs/               Engineering documentation and 13 Mermaid diagrams (see §22)
├── .github/workflows/  CI and security pipelines
├── docker/             One Dockerfile per service (api, ai, ledger, frontend) + nginx config
├── requirements/       Per-image dependency subsets (requirements.txt is the full set)
├── docker-compose.yml  Five-service stack: frontend, api, ai, ledger, db (ADR-016)
└── .env.example
```

`backend/` contains `app/` (16 routers, 11 service modules, 34-table model layer),
`migrations/` (forward-only SQL runner, ADR-014) and `tests/` (413 tests, 99 of them security).

## 5. Prerequisites

- Python 3.12 with the packages in `requirements.txt` installed (`pip install -r requirements.txt`)
- Node.js is **not** required — the frontend has no build step
- Docker (optional, for the containerised path)
- No internet access is required to run the platform

## 6. Quick start (single command)

```bash
./scripts/run_local.sh
```

This generates a `.env` with fresh secrets on first run, trains the AI models on synthetic
data (`--fast`, a few seconds), seeds a complete demonstration dataset, and starts the API at
`http://127.0.0.1:8000`.

To start clean:

```bash
./scripts/run_local.sh --reset
```

Sign in at `http://127.0.0.1:8000/` with any seeded account (password `DemoPassw0rd!2026`):

| Email | Role |
|---|---|
| `admin@absp.demo` | Administrator |
| `farmer@absp.demo` | Farm operator |
| `agronomist@absp.demo` | Agronomist |
| `analyst@absp.demo` | Security analyst |
| `researcher@absp.demo` | Biotech researcher |
| `biosafety@absp.demo` | Biosafety officer |
| `supply@absp.demo` | Supply chain operator |
| `certifier@absp.demo` | Certifier |
| `regulator@absp.demo` | Regulator |

Consumer verification needs no login: `http://127.0.0.1:8000/verify.html`.

## 7. Manual setup

```bash
pip install -r requirements.txt
cp .env.example .env
python3 -c "import secrets; print(secrets.token_urlsafe(48))"   # → JWT_SECRET
python3 -c "import base64,os; print(base64.b64encode(os.urandom(32)).decode())"  # → ENCRYPTION_KEY
# paste both into .env

python3 scripts/train_models.py --fast     # trains on synthetic data — see ai/data/generate.py
python3 scripts/seed_demo.py --reset
python3 -m uvicorn app.main:app --app-dir backend --reload
```

## 8. Environment variables

Every variable is documented with a safe placeholder in `.env.example`. Notable ones:

| Variable | Purpose |
|---|---|
| `JWT_SECRET`, `ENCRYPTION_KEY` | Required in production; the app refuses to start with a default in `ENV=production` |
| `DATABASE_URL` | `sqlite:///./absp.db` for `run_local.sh`, `postgresql+psycopg://...` in the compose stack and production |
| `AI_SERVICE_URL`, `LEDGER_SERVICE_URL`, `SERVICE_TOKEN` | Empty = ai and ledger run in-process. Set (compose does) = call the `ai` / `ledger` containers with the shared token (ADR-016) |
| `TELEMETRY_INLINE_SCORING` | `true` gives an immediate anomaly verdict per message; `false` defers scoring to a background task for ~6x throughput — see PRD.md NFR-2 |
| `DEMO_MODE` | Labels the deployment as a demonstration in API responses |

## 9. Database

`run_local.sh` uses SQLite (zero setup). The Docker stack uses PostgreSQL in its own `db`
container: the api creates the schema, applies migrations and seeds on first start (§16). The
driver is `psycopg` 3, the one dependency added under Development-rules §10 (ADR-017).

The same ORM models and migrations run against either engine (ADR-002).

## 10. Blockchain

In the Docker stack the ledger runs as its own `ledger` container and is the only writer of the
chain; under `run_local.sh` and the tests it runs in-process with the API (ADR-016). It implements the Hyperledger Fabric transaction model (MSP identities, ECDSA P-256 endorsement,
hash-linked blocks, Merkle proofs, chaincode-style contracts) as an in-process package. This is
explicitly a **single-node ordering** demonstration; the migration path to a production Fabric
network is documented function-by-function in `docs/Blockchain-integration.md` §17.

```bash
python3 -m pytest backend/tests/test_ledger.py -q     # 42 tests incl. tamper detection
```

## 11. AI models

All models train on synthetic data generated by `ai/data/generate.py`, with a provenance
header naming the generator (ADR-013). Training:

```bash
python3 scripts/train_models.py            # full training run
python3 scripts/train_models.py --fast     # smaller run, a few seconds
python3 scripts/calibrate_anomaly.py       # re-measure the anomaly score scale after retraining
```

Model cards (architecture, inputs/outputs, limitations, training metrics) are written to
`ai/models/*_model_card.json` and are served at `GET /api/v1/ai/model-cards`.

## 12. IoT simulation

No physical hardware is available or required. The simulator drives real devices through the
real HMAC authentication path:

```bash
python3 iot/simulator.py --list-devices
python3 iot/simulator.py --mode normal --count 20
python3 iot/simulator.py --mode spoof --count 6           # raises an anomaly alert
python3 iot/simulator.py --mode replay                    # demonstrates replay rejection (409)
python3 iot/simulator.py --mode bad-signature              # demonstrates auth failure (401/404)
python3 iot/simulator.py --mode malformed                  # demonstrates quarantine on bad data
python3 iot/simulator.py --mode cold-chain-break --count 10 # temperature excursion
```

## 13. Running the full demonstration

```bash
python3 scripts/demo_flow.py --api-url http://127.0.0.1:8000
```

Scripts the complete journey end to end against the live API: biosecurity screening → GMO
registration → jurisdictional approval → seed lot → harvest → processing → shipment
(cold chain) → certification → integrity verification → compliance evaluation →
environmental impact assessment → consumer QR verification → **a live tamper-detection
demonstration** → audit-chain verification. 25 steps, every check asserted.

## 14. Tests

```bash
python3 -m pytest backend/tests/ -q                       # 382 tests
python3 -m pytest backend/tests/security/ -q               # RBAC, tenancy, injection, headers
python3 -m pytest backend/tests/performance/ -q -s         # NFR measurements, printed
```

Categories: unit (security primitives, AI algorithms, ledger contracts), integration (auth,
devices, biosecurity, supply chain), end-to-end (the full traceability journey), security
(authorization coverage, tenancy isolation, injection, headers, rate limiting, log redaction),
and performance (latency, throughput, ledger append/verify cost). See `docs/Testing.md`.

## 15. Security scans (offline-capable)

```bash
python3 scripts/secret_scan.py         # no network required
bash scripts/pre-commit.sh             # secret scan + fast tests + syntax checks
```

CI additionally runs Bandit, Semgrep, pip-audit, Gitleaks, Trivy, Checkov and an OWASP ZAP
baseline scan — see `.github/workflows/ci.yml` and `security.yml`.

## 16. Docker

Five containers, one per component (ADR-016):

| Service | Image | Role | Reachable from |
|---|---|---|---|
| `frontend` | `absp-frontend` (nginx) | Serves the UI, proxies everything else to the api | host, `127.0.0.1:8080` |
| `api` | `absp-api` | FastAPI backend: auth, business logic, persistence | frontend only |
| `ai` | `absp-ai` | Model inference (screening, CRISPR, anomaly, fraud, crop vision) | api only, service token |
| `ledger` | `absp-ledger` | Permissioned ledger node, sole writer of the chain | api only, service token |
| `db` | `postgres:16-alpine` | PostgreSQL | api only |

```bash
docker compose up -d --build                 # whole stack; open http://127.0.0.1:8080
docker compose --profile simulator up        # also run the IoT simulator against the api
docker compose logs -f api                   # follow one service
```

`.env` must define `JWT_SECRET`, `ENCRYPTION_KEY`, `POSTGRES_PASSWORD` and `SERVICE_TOKEN`
(see `.env.example`). The first start seeds the same demonstration dataset as `run_local.sh`.
Every image is non-root with a read-only root filesystem, no capabilities and a health check
(`docs/Security.md` §15); `ai`, `ledger` and `db` sit on an internal-only network.

### Kubernetes

The same five services run on Kubernetes from `infrastructure/k8s/`: `base/` is the
production-shaped set (default-deny NetworkPolicies, non-root read-only pods, HPA, Ingress) and
`local/` adapts it for a local k3d cluster.

```bash
./scripts/k8s_up.sh      # creates a k3d cluster, loads the images, deploys; http://127.0.0.1:8080
./scripts/k8s_down.sh    # deletes the cluster
kubectl --context k3d-absp -n absp get pods
```

The scripts never change your current kubectl context. Secrets are created from `.env` and
never written to disk.

### Terraform (local)

`infrastructure/terraform-local/` deploys the same five containers, two networks and three
volumes to this machine's Docker with the `kreuzwerker/docker` provider. The AWS configuration in
`infrastructure/terraform/` is separate and untouched.

```bash
./scripts/tf_local_up.sh      # terraform init + apply; http://127.0.0.1:8080
./scripts/tf_local_down.sh    # terraform destroy (containers, networks and data volumes)
```

Secrets are passed from `.env` as `TF_VAR_*` and never written to a tfvars file; the local
state file holds them and is gitignored.

## 17. CI/CD

`.github/workflows/ci.yml`: lint → secret scan → SAST (Bandit, Semgrep) → SCA (pip-audit) →
unit/integration tests → container build → SBOM → container scan (Trivy) → IaC scan (Checkov).
`.github/workflows/security.yml`: Gitleaks, a scheduled weekly image rescan, and an OWASP ZAP
baseline scan against a running instance.

**Verified green on GitHub-hosted runners** (commit `d3c1c60`):

| Workflow | Jobs | Status |
|---|---|---|
| CI | `iac-scan`, `lint-and-test`, `build-and-scan-image` | ✅ all pass |
| Security | `secret-scan`, `smart-contract-tests`, `dast` | ✅ all pass |

DAST (OWASP ZAP) against a live instance: **FAIL-NEW 0, PASS 65, WARN-NEW 5** — one warning was a
real missing security header and was fixed in code; the other four are triaged with a written
reason each in `security/zap-rules.tsv`.

Container scan: all HIGH/CRITICAL findings with an available vendor fix were remediated. Remaining
findings are upstream OS-package vulnerabilities with no published fix at the time of testing and
are documented as residual risk in `docs/EXAM-LIMITATIONS.md` §2.1.

## 18. Deployment

Local: `docker-compose.yml`. Production: `infrastructure/terraform/` (AWS — VPC, private
subnets, RDS PostgreSQL, ECR, Secrets Manager, S3, least-privilege IAM) and
`infrastructure/k8s/` (Deployment, HPA, NetworkPolicy default-deny, non-root pod security
context). Copy `infrastructure/terraform/terraform.tfvars.example` to `terraform.tfvars` and
never commit the real file. Verified: `terraform validate` and `terraform plan` both succeed
against this configuration.

Post-deploy: `python3 scripts/smoke_test.py --api-url https://your-deployment`.

## 19. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `ConfigurationError` on startup | Running with `ENV=production` and a placeholder secret | Set real `JWT_SECRET`/`ENCRYPTION_KEY`, or use `ENV=development` locally |
| `sqlite3.OperationalError: disk I/O error` | Another process (often a previous server) holds the database file | Stop the other process before deleting/reseeding the database |
| Telemetry returns 404 "Device authentication failed" | Wrong or stale device secret, or the device is not `ACTIVE` | Re-provision the device or check `demo_device_secrets.json` |
| Login returns 429 | The authentication rate limiter (10/minute/IP) — a real security control | Wait for `Retry-After`, do not disable the limiter |
| A view shows "Not available to your role" | The signed-in role lacks the required permission | Sign in as a role with that permission — see `docs/PRD.md` §11 |

## 20. Demo workflow for the oral presentation

1. `./scripts/run_local.sh --reset`
2. `python3 scripts/demo_flow.py` — the full 25-step journey with a live tamper-detection proof
3. `python3 iot/simulator.py --mode spoof --count 6` then show the resulting alert in the UI
4. Open `http://127.0.0.1:8000/` and walk the dashboard, biosecurity review queue, blockchain
   explorer and compliance report from the previous steps
5. Open `http://127.0.0.1:8000/verify.html?code=<code from step 2>` on a phone or a second window

## 21. Requirements coverage

Traced requirement by requirement in `docs/REQUIREMENTS-TRACEABILITY.md`, against the exam brief,
the documentation and the running code:

| Status | Count |
|---|---|
| **COMPLETE** | 37 |
| **PARTIAL** | 3 |
| **MISSING** | 0 |

The three PARTIAL items are: no independent accessibility audit or assistive-technology user
testing; Hyperledger Fabric and BLAST implemented as model and algorithm rather than the named
products running; and OpenDroneMap/QGIS not integrated. Each is explained in full — what exists,
what is missing, and why it is acceptable for an academic demonstration.

## 22. Known limitations

`docs/EXAM-LIMITATIONS.md` is the complete, honest accounting of what is real, what is
simulated, and what remains outstanding. In short:

* IoT devices, telemetry values, satellite scene data and hazard sequences are **simulated** —
  the fleet is simulated, the security envelope around it is not.
* AI models use **synthetic labelled demonstration datasets**; reported metrics describe the
  synthetic task only.
* The ledger is a **local single-node permissioned cryptographic ledger**, not a deployed
  Hyperledger Fabric consortium.
* Terraform and Kubernetes manifests are implemented and validate, but have **never been applied**
  to live cloud infrastructure.
* CI and Security workflows run **green on GitHub-hosted runners** (commit `d3c1c60`): `iac-scan`,
  `lint-and-test`, `build-and-scan-image`, `secret-scan`, `smart-contract-tests`, `dast`.
* Container scanning: all HIGH/CRITICAL findings with an available vendor fix were remediated.
  60 HIGH/CRITICAL findings remain in Debian base-image OS packages with no published fix at the
  time of testing, and are documented as residual risk — see `docs/EXAM-LIMITATIONS.md` §2.1.
* No independent penetration test and no independent accessibility audit have been performed.

## 23. Documentation map

| Document | What it answers |
|---|---|
| `docs/PRD.md`, `docs/TRD.md` | What is being built and to what requirements |
| `docs/Architecture.md`, `docs/Backend.md` | How the system is structured |
| `docs/Decision.md` | 15 ADRs — why each significant choice was made |
| `docs/API-spec.md`, `docs/openapi.json` | The full API surface (121 operations, 101 paths) |
| `docs/Security.md`, `docs/SECURITY-ASSESSMENT.md` | Threat model, controls, and the adversarial assessment |
| `docs/Testing.md` | Test strategy and coverage |
| `docs/IoT-Devices.md`, `docs/GMO.md`, `docs/Blockchain-integration.md` | Domain subsystems |
| `docs/flow.md`, `docs/UIUX.md` | End-to-end flows and interface design |
| `docs/REQUIREMENTS-TRACEABILITY.md` | Requirement → implementation → test → status |
| `docs/DEMO-RUNBOOK.md` | How to run and demonstrate the platform |
| `docs/EXAM-LIMITATIONS.md` | Real vs simulated, and what production would change |
| `docs/diagrams/` | 13 Mermaid diagrams, labelled IMPLEMENTED / SIMULATED / NOT APPLIED |
| `docs/Development-rules.md` | Engineering rules enforced in review and CI |
