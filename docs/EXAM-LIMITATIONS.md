# EXAM-LIMITATIONS.md — what is not real, and what production would change

Every limitation here is stated deliberately. Naming them first is the difference between a
candidate who knows their system and one who gets caught by a question.

Two sections, because they are different kinds of thing:

- **Demo limitations** — things deliberately simulated or scoped down so the project could be
  built and shown in an academic setting. These are acceptable *as they are*.
- **Production improvements** — real engineering work that would be required before anyone ran
  this for actual food safety. These are not acceptable in production; they are simply out of
  scope here.

---

## Part 1 — Demo limitations

### 1.1 Physical IoT devices are simulated

**What exists now.** `iot/simulator.py` drives a 13-device fleet across all six device classes.
There is no hardware.

**Why this is acceptable for an academic demo.** The fleet is simulated; the security envelope is
not. The simulator holds each device's real 256-bit secret, signs every message with the same
HMAC-SHA256 scheme physical hardware would use, and gets no privileged path into the API. It has
seven fault-injection modes — replay, spoofed signature, malformed readings, drift, cold-chain
break — specifically so the demonstration proves the platform *rejects* bad input rather than only
accepting good input. The code path a simulated reading takes is byte-for-byte the path a real
sensor's reading would take.

**What production would change.** Real hardware, and a move from shared-secret HMAC to X.509
client certificates with per-device key attestation, so a compromised device cannot be cloned from
a leaked secret. Secrets would live in a hardware security module or a device secure element
rather than in an encrypted database column.

### 1.2 Agricultural telemetry values are generated

**What exists now.** `ai/data/generate.py` produces physically plausible readings per device class
with diurnal and seasonal variation.

**Why acceptable.** No real farm was available. The values are plausible enough to exercise range
validation, anomaly scoring and cold-chain logic meaningfully.

**What production would change.** Real sensor feeds, and anomaly models retrained on real
per-site baselines rather than one synthetic distribution per device class.

### 1.3 Satellite data is metadata only

**What exists now.** `telemetry.ingest_scene()` accepts scene **metadata** — NDVI statistics,
cloud cover, capture time — with a checksum over the declared fields, verified on ingestion. Six
scenes are seeded. There is no raster imagery.

**Why acceptable.** The topic names satellite imagery pipelines; what this demonstrates is the
*secure ingestion and integrity* half of that pipeline, which is the part that belongs to a
security platform. A tampered checksum is rejected with a 422, and that is demonstrable live.

**What production would change.** Real Sentinel-2 or commercial imagery, actual raster processing,
and per-pixel NDVI computation rather than accepting declared statistics. OpenDroneMap and QGIS,
which the topic names, were **not** used — do not claim otherwise.

### 1.4 AI models use synthetic labelled demonstration datasets

**What exists now.** Five AI modules; eight trained artefacts (six per-device-class Isolation
Forests, one fraud Isolation Forest, one crop-vision CNN). All training data comes from
`ai/data/generate.py`. Every model card records this.

**Why acceptable.** The requirement is to demonstrate a complete, working AI workflow — data
generation, training, versioned artefacts, model cards, inference, and graceful degradation when a
model is unavailable. That workflow is real and complete.

**The specific trap.** The crop-vision model reports **validation accuracy 1.000**. That number
means far less than it appears to: training and validation images come from the same procedural
generator, so it measures whether the synthetic classes are separable, not whether the model
generalises to a photograph of a real leaf. The model card says exactly this. Say it before you
are asked.

**What production would change.** Real labelled agronomic imagery and real fraud labels; a held-out
test set from a genuinely different distribution; per-site model monitoring and drift detection.
Accuracy figures would then mean something.

### 1.5 The ledger is single-node

**What exists now.** A local permissioned cryptographic ledger in `ledger/`, implementing the
Hyperledger Fabric *model* in-process: MSP identities, ECDSA P-256 endorsement by named
organisations, chaincode-style contracts, an orderer, hash-linked blocks with Merkle roots, and a
world state. Verification genuinely detects an altered record.

**Why acceptable.** The cryptography is real, not mocked — real ECDSA signatures, real SHA-256
chaining, real Merkle proofs. What is missing is *distribution*: one ordering node instead of a
multi-organisation consortium. A real Fabric network needs several containers, a channel
configuration and a certificate authority per organisation, which is infrastructure work rather
than a demonstration of understanding. ADR-003 records the decision and maps each contract
function to its Fabric chaincode equivalent.

**Do not say "production blockchain".** Say: *a local single-node permissioned cryptographic
ledger used for demonstration, with signed records and tamper verification.*

**What production would change.** An actual Fabric network: multiple peers, Raft ordering, a CA
per organisation, channel-level access control, and real endorsement policies enforced across
organisational boundaries rather than in one process.

### 1.6 Hazard sequences are synthetic motifs

**What exists now.** Ten synthetic hazard records across five classes, marked `is_synthetic` in
the database and displayed as such.

**Why acceptable.** Distributing real pathogen sequences in a student repository would be
irresponsible. The screening algorithm — k-mer seeding with Smith–Waterman local alignment — is
real and is the same seed-and-extend approach BLAST uses. BLAST itself could not be installed
(ADR-008); the algorithm was implemented directly rather than claimed.

**What production would change.** A curated, access-controlled hazard database sourced from a
recognised biosecurity authority, with a vetting process for who may query it.

### 1.7 Demonstration credentials are published

**What exists now.** Nine seeded accounts sharing one documented password, shown on the login page.

**Why acceptable.** They exist only in the seeded demo database, which is rebuilt from scratch by
`--reset`. `DEMO_MODE` is explicit, and configuration-safety tests assert that production settings
reject demo defaults.

**What production would change.** No seeded accounts at all; SSO or an invite flow; MFA on
privileged roles.

---

## Part 2 — Production improvements (genuinely outstanding work)

### 2.1 CI/CD has run, and is currently failing

**What exists now — corrected 2026-09-13.** Earlier versions of this project's own documentation
claimed the workflows had "never run on a hosted runner (no remote configured)". **That was
wrong.** A remote exists and the workflows *have* executed on hosted GitHub Actions runners —
three runs, on 2026-09-04 and 2026-09-07. All three are marked failed.

Two jobs genuinely passed on the hosted runner: **secret-scan (gitleaks)** and
**smart-contract-tests**. The rest failed at *"Set up job"*, before running any security tool,
because three pinned action SHAs did not resolve:

| Action | Problem |
|---|---|
| `returntocorp/semgrep-action` | Pinned to a **39-character** SHA — a git SHA is 40, so it could never resolve. The action has also not been updated since January 2024, and its successor is archived. |
| `bridgecrewio/checkov-action` | Pinned SHA did not exist for the claimed tag |
| `zaproxy/action-baseline` | Pinned SHA did not exist for the claimed tag |

**Fixed in this pass.** All eight pinned actions were verified against each action's real tag list
via the GitHub API; the three broken pins were corrected, and Semgrep now runs from the maintained
PyPI CLI instead of the abandoned action. The workflow YAML parses cleanly.

**What is still not proven.** The fix has **not been re-run** on a hosted runner, so a green
pipeline remains unverified. Do not claim "CI/CD fully proven". Say: *the workflows are
implemented and the action pins are now verified to resolve; hosted-runner execution of the
corrected pipeline is not yet demonstrated.*

**What production would change.** A required green pipeline as a merge gate, with failures
blocking rather than `soft_fail`/`continue-on-error`.

### 2.2 Terraform has never been applied

**What exists now.** `infrastructure/terraform/` describes an AWS target — VPC, ALB, ECS/EKS, RDS
PostgreSQL in a private subnet, CloudWatch. It validates and plans. There is **no `terraform.tfstate`
anywhere in this repository**, which is the direct evidence that it was never applied.

**Why acceptable here.** No AWS account was in scope, and applying it would incur real cost.

**What production would change.** An actual apply against a real account, with remote state, state
locking, drift detection, and a separate environment per stage. Until then the correct wording is:
*Infrastructure-as-Code is implemented and validated, but has not yet been applied to live cloud
infrastructure.*

### 2.3 Kubernetes manifests have never been applied

**What exists now.** `infrastructure/k8s/` — namespace, deployment, network policy, secret example.
Valid YAML, never applied to a cluster.

**What production would change.** A real cluster, with pod security admission, resource limits
enforced, and the network policy actually tested against a hostile pod.

### 2.4 No independent penetration test

**What exists now.** An adversarial self-audit that found and fixed two real authorisation defects
— a **BOLA** (any organisation could attach another organisation's certification to its own batch)
and an **IDOR** (cross-organisation record verification) — plus a vulnerable `cryptography`
version. Both defects have regression tests. A 99-test security suite covers RBAC, tenancy
isolation, injection, replay, hardening and log redaction.

**The honest claim.** *No known critical findings remain from the testing performed; residual risks
are documented.* Not "100% secure", and not "no vulnerabilities" — a self-audit by the author is
structurally weaker than an independent one.

**What production would change.** A third-party penetration test and a threat-modelling review by
someone who did not write the code.

### 2.5 Accessibility is not independently audited

**What exists now.** Automated inspection confirms: every form input across twelve views is
programmatically labelled, no duplicate element ids, no table without a header cell, a skip link
that is first in tab order and moves focus to `<main>`, a visible 3px focus indicator, logical tab
order, and no horizontal overflow at 390 / 768 / 1440 px.

**What is NOT verified.** Colour contrast ratios were not measured. Screen-reader announcement
quality was not assessed. Reduced-motion preferences were not handled. **No assistive-technology
user has tested this interface**, and no formal WCAG 2.1 AA conformance audit has been performed.

**What production would change.** A formal audit against WCAG 2.1 AA and testing with real users
of screen readers.

### 2.6 Chart SVGs have no tabular alternative

**What exists now.** Each chart SVG carries an `aria-label` summarising its series and range, so a
screen reader announces one descriptive sentence.

**Why this is a limitation.** A sentence is not navigable. A screen-reader user cannot move through
individual data points as they could through a table.

**What production would change.** A visually-hidden `<table>` alongside each chart carrying the same
values, or a toggle between chart and table views.

### 2.7 Observability is basic

**What exists now.** Structured JSON logging with correlation ids, a `/health` endpoint, a
readiness check and a metrics endpoint.

**What production would change.** Distributed tracing, real metric aggregation and alerting
thresholds, log shipping with retention policy, and an on-call runbook per alert.

### 2.8 Single-process deployment

**What exists now.** A modular monolith — one FastAPI process with eleven service modules
(ADR-001). SQLite in development; the same models run against PostgreSQL unchanged.

**Why acceptable.** A deliberate decision, not a shortcut. Microservices pay off when independent
scaling or independent deploys are actually needed, and neither was a requirement here.

**What production would change.** PostgreSQL as the default, multiple replicas behind a load
balancer, and extraction of the ledger and AI inference into separate services only if a measured
scaling need appeared.

---

## Summary table

| # | Limitation | Kind | Acceptable for the exam? |
|---|---|---|---|
| 1.1 | IoT devices simulated | Demo | Yes — security envelope is real |
| 1.2 | Telemetry values generated | Demo | Yes |
| 1.3 | Satellite = metadata only | Demo | Yes — integrity path is real |
| 1.4 | Synthetic AI training data | Demo | Yes — stated on every model card |
| 1.5 | Single-node ledger | Demo | Yes — cryptography is real |
| 1.6 | Synthetic hazard sequences | Demo | Yes — responsible choice |
| 1.7 | Published demo credentials | Demo | Yes — demo database only |
| 2.1 | CI runs failing, fix unverified | Production | Disclose it |
| 2.2 | Terraform never applied | Production | Disclose it |
| 2.3 | Kubernetes never applied | Production | Disclose it |
| 2.4 | No independent pen test | Production | Disclose it |
| 2.5 | Accessibility not independently audited | Production | Disclose it |
| 2.6 | Charts lack a tabular alternative | Production | Disclose it |
| 2.7 | Basic observability | Production | Disclose it |
| 2.8 | Single-process deployment | Production | Deliberate (ADR-001) |
