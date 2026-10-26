# Agricultural Biotechnology Security Platform (ABSP)

**Precision farming protection, GMO traceability, and food supply chain security for global
food systems.** Built for EduQual Level 6 Topic 135 (ANPP-OP).

> **Markings used throughout this repository:** `REAL IMPLEMENTATION` — a genuine, working
> control. `DEMO/SIMULATION` — a faithful stand-in for hardware or infrastructure this
> deployment cannot depend on (physical IoT devices, a production Hyperledger Fabric network).
> `MOCK` — not used; nothing in this repository fakes a result. Every simulated element is
> named as such at the point it appears. See §22 for the full real-vs-simulated breakdown.

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

## 3. Technology stack

Python 3.12 · FastAPI · SQLAlchemy 2 · Pydantic 2 · PyJWT · bcrypt · `cryptography` ·
scikit-learn · TensorFlow/Keras · dependency-free ES2022 frontend · Docker · Terraform (AWS) ·
Kubernetes manifests · GitHub Actions.

**The only Python dependency added beyond the original pinned set is the PostgreSQL driver
`psycopg`.** The stack is exactly what `requirements.txt` pins, and everything else (rate
limiting, QR codes, Merkle trees, sequence alignment) is implemented on the standard library.

## 4. Repository structure

```
agri-biotech-security-platform/
├── backend/            FastAPI app: core, models, schemas, services, routers, tests
├── ai/                 Screening, CRISPR risk, anomaly detection, fraud, crop vision, models
├── ledger/             Permissioned ledger: identities, blocks, contracts, chain
├── iot/                Device simulator (DEMO/SIMULATION fleet, real security envelope)
├── frontend/           28 view modules, framework-free ES modules, public verify.html
├── infrastructure/     Terraform (AWS) and Kubernetes manifests
├── scripts/            start.sh, stop.sh, run_local.sh, seed_demo.py, demo_flow.py, train_models.py
├── security/           Disclosure policy and OWASP ZAP rules
├── fabric/             Hyperledger Fabric chaincode (absp-anchor) and the gateway bridge
├── .github/workflows/  CI and security pipelines
├── docker/             One Dockerfile per service (api, ai, ledger, frontend) + nginx config
├── requirements/       Per-image dependency subsets (requirements.txt is the full set)
├── docker-compose.yml  Five-service stack: frontend, api, ai, ledger, db
└── .env.example
```

`backend/` contains `app/` (16 routers, 11 service modules, 34-table model layer),
`migrations/` (forward-only SQL runner) and `tests/` (791 tests).

## 5. Prerequisites

- Python 3.12 with the packages in `requirements.txt` installed (`pip install -r requirements.txt`)
- Node.js is **not** required for the platform itself — the frontend has no build step. The
  optional Hyperledger Fabric mirror (§12) does need Node.js 22.12 or newer for its bridge
  (`@hyperledger/fabric-gateway` requires it); the version is pinned in `.nvmrc` and in
  `engines` in `fabric/gateway/package.json`. With nvm: `nvm install 22 && nvm alias default 22`
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

That is the no-Docker path, and it runs the ledger in-process. For the full containerised
demonstration — all six services plus the Hyperledger Fabric mirror behind them, on
`http://127.0.0.1:8080` — one command covers both halves (§16):

```bash
./scripts/start.sh
```

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
| `AI_SERVICE_URL`, `LEDGER_SERVICE_URL`, `SERVICE_TOKEN` | Empty = ai and ledger run in-process. Set (compose does) = call the `ai` / `ledger` containers with the shared token |
| `TELEMETRY_INLINE_SCORING` | `true` gives an immediate anomaly verdict per message; `false` defers scoring to a background task for ~6x throughput |
| `DEMO_MODE` | Labels the deployment as a demonstration in API responses |

## 9. Database

`run_local.sh` uses SQLite (zero setup). The Docker stack uses PostgreSQL in its own `db`
container: the api creates the schema, applies migrations and seeds on first start (§16). The
driver is `psycopg` 3, the one dependency added for the PostgreSQL stack.

The same ORM models and migrations run against either engine.

## 10. Blockchain

In the Docker stack the ledger runs as its own `ledger` container and is the only writer of the
chain; under `run_local.sh` and the tests it runs in-process with the API. It implements the Hyperledger Fabric transaction model (MSP identities, ECDSA P-256 endorsement,
hash-linked blocks, Merkle proofs, chaincode-style contracts) as an in-process package. This is
explicitly a **single-node ordering** demonstration, not a production Fabric network.

```bash
python3 -m pytest backend/tests/test_ledger.py -q     # 42 tests incl. tamper detection
```

## 11. AI models

All models train on synthetic data generated by `ai/data/generate.py`, with a provenance
header naming the generator. Training:

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

### IoT attack tests

```bash
python3 scripts/iot_attack_tests.py --api-url http://127.0.0.1:8000
```

Plays nine attackers against the live, seeded API: replay, forged signature, unregistered
device, stale timestamp, impossible values, spoofed but validly signed data, and a tenant
probing another organisation's shipments (which must stay a plain 404 *and* be counted by the
data-theft detector). Runs in CI as the `iot-attack-tests` job of the Security workflow.

### Drone imagery (OpenDroneMap) and QGIS

OpenDroneMap turns drone photos into one georeferenced map (`odm_orthophoto.tif`).
`scripts/odm_ingest.py` hashes that file, computes a vegetation index from the pixels (NDVI
with a near-infrared band, VARI for an ordinary RGB camera), converts the footprint to WGS84
and ingests it as a DRONE scene; the API anchors the file's SHA-256 on the ledger.

```bash
pip install -r requirements/geo.txt                       # rasterio, for these scripts only
docker run --rm -v "$PWD/odm:/datasets" opendronemap/odm --project-path /datasets project --fast-orthophoto
python3 scripts/odm_ingest.py --project odm/project --field-id <field id> --captured-at <flight time, ISO 8601>
python3 scripts/make_sample_orthophoto.py --lat 42.03 --lon -93.63 --out sample.tif   # synthetic test image
```

The **Satellite & Drone** page has *Download fields for QGIS (GeoJSON)*: every field polygon
with its latest index and stress level, plus each drone footprint. In QGIS: Layer > Add Layer >
Add Vector Layer, then style by `index_mean`.

Run once against real imagery: ODM's public Caliterra sample (77 photographs from a drone over
Texas) was processed with `opendronemap/odm --fast-orthophoto` into a 1789 x 1937 px,
10 cm RGB orthophoto, ingested as a DRONE scene by a farm operator (an agronomist cannot: it
lacks `telemetry:write`), and the file's SHA-256 was found on both the local ledger and
Fabric. It has no near-infrared band, so it took the VARI path and stayed out of the NDVI
stress ranking. The exported GeoJSON was opened with GDAL (`ogrinfo`, `ogr2ogr`), the library
QGIS reads files with: EPSG:4326, a footprint at lon -98.0911..-98.0892, lat 30.1704..30.1722,
which matches the photographs' EXIF GPS. That is GDAL validation, not a QGIS desktop session.
The ingest script needs only `requirements/geo.txt`; the first real run showed it had been
importing the backend's own packages, which is fixed. The export mixes polygons and points
in one layer (a field with no boundary is exported as a point), so QGIS offers it as sublayers.

### Hyperledger Fabric mirror

`./scripts/fabric_up.sh` starts a Fabric 2.5 test network (two organisations, Raft orderer),
deploys the `absp-anchor` chaincode with `AND('Org1MSP.peer','Org2MSP.peer')` endorsement and
starts the bridge. With `FABRIC_BRIDGE_URL` set, every ledger anchor is also written to Fabric,
and record and batch verification return a second verdict read from Fabric. See
`fabric/README.md`; `./scripts/fabric_down.sh` removes it. The bridge needs Node.js 22.12 or
newer (§5); `fabric_up.sh` checks that before it downloads anything. `./scripts/start.sh`
starts this and the compose stack together (§16).

### Scheduled security sweeps

`scripts/scheduled_tasks.py` (ledger anchor retry and Fabric re-mirror, silent devices,
data-theft scoring, certification expiry) runs every 15 minutes as the Kubernetes CronJob
`security-sweeps`, and every 5 minutes in the compose `scheduler` service, which starts with
the stack. Repeated runs do not duplicate open alerts. Every ledger write is journalled in
`ledger_writes` (migration 0004); one left PENDING/FAILED by a ledger outage is replayed in
order (a batch before its events and custody transfers), and writes that arrive behind it
are queued rather than rejected. An administrator or security analyst can run the same
sweep with `POST /api/v1/blockchain/anchors/retry`.

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
python3 -m pytest backend/tests/ -q                       # 791 tests
python3 -m pytest backend/tests/security/ -q               # RBAC, tenancy, injection, headers
python3 -m pytest backend/tests/performance/ -q -s         # NFR measurements, printed
```

Categories: unit (security primitives, AI algorithms, ledger contracts), integration (auth,
devices, biosecurity, supply chain), end-to-end (the full traceability journey), security
(authorization coverage, tenancy isolation, injection, headers, rate limiting, log redaction),
and performance (latency, throughput, ledger append/verify cost).

`tests-e2e/` holds a separate **live re-audit suite of 44 tests** (21 Playwright browser tests,
23 API security tests). It drives a running stack through the real login form and is not part
of CI. Playwright is installed separately and is not in `requirements.txt`:

```bash
pip install playwright pytest && playwright install chromium
ABSP_BASE_URL=http://127.0.0.1:8000 ABSP_HEADLESS=1 python3 -m pytest tests-e2e -q
```

Run it against a disposable stack: the tests create records. Leave `ABSP_SLOWMO` at its default
(220 ms); the authentication rate limiter (10 logins/minute/IP) rejects faster runs with 429.

## 15. Security scans (offline-capable)

```bash
python3 scripts/secret_scan.py         # no network required
bash scripts/pre-commit.sh             # secret scan + fast tests + syntax checks
```

CI additionally runs Bandit, Semgrep, pip-audit, Gitleaks, Trivy, Checkov and an OWASP ZAP
baseline scan — see `.github/workflows/ci.yml` and `security.yml`.

## 16. Docker

Five containers, one per component:

| Service | Image | Role | Reachable from |
|---|---|---|---|
| `frontend` | `absp-frontend` (nginx) | Serves the UI, proxies everything else to the api | host, `127.0.0.1:8080` |
| `api` | `absp-api` | FastAPI backend: auth, business logic, persistence | frontend only |
| `ai` | `absp-ai` | Model inference (screening, CRISPR, anomaly, fraud, crop vision) | api only, service token |
| `ledger` | `absp-ledger` | Permissioned ledger node, sole writer of the chain | api only, service token |
| `db` | `postgres:16-alpine` | PostgreSQL | api only |

```bash
./scripts/start.sh                           # Fabric + the whole stack; open http://127.0.0.1:8080
./scripts/start.sh --rebuild                 # the same, rebuilding the images first
./scripts/stop.sh                            # stop both halves again (data survives)
docker compose --profile simulator up        # also run the IoT simulator against the api
docker compose logs -f api                   # follow one service
```

`start.sh` checks the prerequisites first (Docker running, `.env`, `$FABRIC_DIR`, Node 22 for
the bridge), starts Fabric unless it is already running, waits for the bridge to answer, brings
the stack up, waits for the platform and prints the demo accounts. Re-running it is harmless:
a Fabric network that is already up is reused rather than torn down and rebuilt, so a seeded
demonstration survives a second start. Only `./scripts/start.sh --fresh` destroys data — it
runs `docker compose down -v` and `fabric_down.sh`, then starts clean and re-seeds — and it
asks for confirmation unless `--yes` is passed.

Underneath it is the two manual steps, which still work on their own:

```bash
export FABRIC_DIR=$HOME/absp-fabric
BRIDGE_HOST=0.0.0.0 ./scripts/fabric_up.sh                 # Fabric network + bridge on :8300
COMPOSE_FABRIC_BRIDGE_URL=http://host.docker.internal:8300 docker compose up -d
```

Without the Fabric half, `docker compose up -d --build` on its own is enough; the mirror is
optional (§12).

`.env` must define `JWT_SECRET`, `ENCRYPTION_KEY`, `POSTGRES_PASSWORD` and `SERVICE_TOKEN`
(see `.env.example`). The first start seeds the same demonstration dataset as `run_local.sh`.
Every image is non-root with a read-only root filesystem, no capabilities and a health check;
`ai`, `ledger` and `db` sit on an internal-only network.

### Kubernetes

The same five application services run on Kubernetes from `infrastructure/k8s/`, with the
scheduler's sweeps as a CronJob rather than a sixth Deployment: `base/` is the
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

`infrastructure/terraform-local/` deploys the same five application containers (no scheduler;
run the sweeps by hand), two networks and three
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
are listed as residual risk in §22.

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
| A view shows "Not available to your role" | The signed-in role lacks the required permission | Sign in as a role with that permission |
| `fabric_up.sh` stops with "needs Node.js 22 or newer" | The Fabric gateway library requires Node 22.12+ (`.nvmrc`) | `nvm install 22 && nvm alias default 22`, then run `./scripts/start.sh` again |
| `start.sh` reports "The bridge did not answer" | The gateway failed to start | Read `$FABRIC_DIR/bridge.log`; `./scripts/start.sh --fresh` rebuilds the network (and wipes the demo data) |

## 20. Demo workflow for the oral presentation

1. `./scripts/run_local.sh --reset`
2. `python3 scripts/demo_flow.py` — the full 25-step journey with a live tamper-detection proof
3. `python3 iot/simulator.py --mode spoof --count 6` then show the resulting alert in the UI
4. Open `http://127.0.0.1:8000/` and walk the dashboard, biosecurity review queue, blockchain
   explorer and compliance report from the previous steps
5. Open `http://127.0.0.1:8000/verify.html?code=<code from step 2>` on a phone or a second window

## 21. Requirements coverage

Three requirements from the exam brief are only partly met: no independent accessibility
audit or assistive-technology user testing; BLAST implemented as an algorithm (k-mer seeding
with Smith-Waterman) rather than the named product running; and the QGIS GeoJSON export, which
has been validated with GDAL against a real OpenDroneMap run (§13) but never opened in QGIS
desktop. Hyperledger Fabric is no longer on this list: §12 runs the named
product.

## 22. Known limitations

What is real, what is simulated, and what remains outstanding:

* IoT devices, telemetry values, satellite scene data and hazard sequences are **simulated** —
  the fleet is simulated, the security envelope around it is not.
* Drone imagery has been run **once** against real photographs (ODM's Caliterra sample, RGB only)
  and the export validated with GDAL, not QGIS desktop. Not yet run: a multispectral flight with a
  near-infrared band (the NDVI path from real pixels), a large orthophoto at full resolution, or
  imagery of one of this platform's own fields. The API does not check that a footprint lies on
  the field it is filed against, and `captured_at` defaults to the file's modified time (when ODM
  finished) unless `--captured-at` is given.
* AI models use **synthetic labelled demonstration datasets**; reported metrics describe the
  synthetic task only.
* The local ledger is a **single-node permissioned cryptographic ledger** and remains the
  system of record. Every anchor is mirrored to a **real Hyperledger Fabric 2.5 network**
  (§12) — two organisations, a Raft orderer, `AND(Org1MSP.peer, Org2MSP.peer)` endorsement —
  but that is Fabric's own test network with both organisations on this machine, not a
  production consortium across separate companies.
* Terraform and Kubernetes manifests are implemented and validate, but have **never been applied**
  to live cloud infrastructure.
* CI and Security workflows run on GitHub-hosted runners over every pull request — `lint-and-test`,
  `build-and-scan-image` (one image per service), `iac-scan`, `secret-scan`, `smart-contract-tests`,
  `dast` and `iot-attack-tests`. The container gate earns its place: it failed the branch on three
  fixable nginx CVEs, which were fixed by re-pinning the base image rather than by relaxing the gate.
* Container scanning: all HIGH/CRITICAL findings with an available vendor fix were remediated.
  60 HIGH/CRITICAL findings remain in Debian base-image OS packages with no published fix at the
  time of testing, and are documented as residual risk.
* No independent penetration test and no independent accessibility audit have been performed.
