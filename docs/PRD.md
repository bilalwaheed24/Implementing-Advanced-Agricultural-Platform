# PRD.md — Product Requirements Document

**Product:** Agricultural Biotechnology Security Platform (ABSP)
**Source of truth:** the exam brief — Topic 135, ANPP-OP v0.1 (not redistributed in this repository)
**Document owner:** Technical Project Manager / Lead Architect
**Version:** 1.0

---

## 1. Product vision

> A single, verifiable control plane for the security of the food system — from the sensor in the
> soil, through the gene in the seed, to the code on the package a consumer scans in a shop.

ABSP unifies three capabilities that are normally bought as three unrelated products: agricultural
IoT security, biotechnology governance with blockchain traceability, and food supply-chain
authentication. The unifying idea is that **every claim about food should be independently
verifiable by the party that bears the risk of it being false** — regulator, buyer, or consumer.

## 2. Problem statement

| # | Problem | Evidence from specification |
|---|---|---|
| P-1 | Farm equipment (drones, sensors, autonomous machinery) is connected but unsecured. | "Deploy comprehensive security for agricultural drones, sensors, and autonomous farming equipment" |
| P-2 | Agronomic data is commercially valuable and is exfiltrated by competitors. | "protection against agricultural data theft and competitive intelligence attacks" |
| P-3 | GMO provenance is recorded in siloed, mutable, mutually distrusted databases. | "Deploy blockchain-based tracking for genetically modified organisms and biotech crops" |
| P-4 | GMO labelling compliance is manual, slow, and inconsistent across jurisdictions. | "automated compliance validation for GMO labeling and regulatory requirements" |
| P-5 | Engineered agricultural pathogens and risky gene edits are not screened before use. | "AI-powered screening for engineered agricultural pathogens and biosecurity threats" |
| P-6 | Dual-use agricultural biotechnology research is unmonitored. | "dual-use research monitoring for agricultural biotechnology" |
| P-7 | Food fraud: organic / non-GMO / specialty claims cannot be verified downstream. | "automated authentication for organic, non-GMO, and specialty food certifications" |
| P-8 | Agtech software and connected equipment ship without security testing. | "secure development practices…automated security testing for agricultural IoT and control systems" |
| P-9 | Food-safety regulatory reporting and audit trails are assembled by hand. | "automated compliance monitoring for USDA, FDA, and international food safety regulations" |

## 3. Objectives

| ID | Objective | Measured by |
|---|---|---|
| O-1 | Secure every agricultural device identity and data path end to end | 100% of telemetry authenticated + replay-protected |
| O-2 | Make GMO and food provenance tamper-evident and independently verifiable | Every batch verifiable from a public QR endpoint |
| O-3 | Detect biosecurity threats before deployment, not after | Screening runs on 100% of submitted sequences |
| O-4 | Automate certification authentication and fraud detection | Fraud score computed on every supply-chain event |
| O-5 | Make security a build-time property, not a release-time audit | Security gates in CI on every commit |
| O-6 | Produce regulator-ready compliance evidence automatically | Compliance report generated on demand per batch |

## 4. Target users and personas

**Persona 1 — Dana, Farm Operations Manager (co-operative, 4 farms, 18 fields).**
Goals: keep irrigation and yield monitoring running, know immediately when a device misbehaves.
Frustrations: vendor dashboards that show data but never say *what changed and whether it is
trustworthy*. Needs: one device inventory, health at a glance, plain-language alerts.

**Persona 2 — Dr. Rao, Biotech Researcher.**
Goals: register a new transformation event, get a gene-edit proposal screened and approved fast.
Frustrations: biosafety review is an email thread. Needs: submit a sequence, get a screening
verdict with evidence, and an auditable approval record.

**Persona 3 — Marta, Biosafety Officer.**
Goals: no hazardous or dual-use construct proceeds without review. Needs: a queue of flagged
screenings with alignment evidence, and the authority to block.

**Persona 4 — Tom, Supply Chain Operator (processor).**
Goals: record processing and shipment events quickly; never break the chain of custody.
Needs: scan a batch, record an event, get an immediate integrity verdict.

**Persona 5 — Aisha, Regulator/Auditor (USDA/FDA).**
Goals: verify a company's claims without trusting the company's database. Needs: read-only access,
compliance status per batch, immutable audit trail, exportable evidence.

**Persona 6 — Consumer.**
Goals: scan the pack, see where the food came from and whether the organic claim is real.
Needs: no login, instant answer, honest "unverified" when the chain is incomplete.

## 5. Stakeholders

Agricultural biotechnology companies, precision farming operators, food supply chain
organisations, regulatory agencies (per the specification's "Industry Application"), plus internal
platform security and engineering teams.

## 6. User journeys

**J-1 Device onboarding.** Dana registers a device → platform issues a device identity and secret
once → device signs telemetry with HMAC → first authenticated reading appears on the dashboard.

**J-2 Compromise detection.** A device begins emitting readings outside its learned envelope → AI
anomaly detector scores it → a security alert is raised → Dana quarantines the device → the device
key is revoked and further telemetry is rejected → the action is written to the audit log.

**J-3 GMO registration to consumer.** Dr. Rao registers a transformation event → submits the
insert sequence for screening → screening passes → biosafety approves → a seed lot is created and
anchored on the ledger → the farm plants it → harvest, processing, packaging, shipment events are
recorded and anchored → a consumer scans the QR code and sees the full verified chain.

**J-4 Biosecurity block.** A researcher submits a sequence with homology to a hazard motif →
screening flags it HIGH → the record is created in `BLOCKED` state → Marta reviews the alignment
evidence → the request is denied and logged as a DURC event.

**J-5 Fraud detection.** A shipment claims organic status but its certification is expired and its
cold chain shows a gap → fraud detector raises the score above threshold → integrity verification
fails → an alert is routed to the certifier and the regulator.

**J-6 Compliance report.** Aisha opens a batch, requests a compliance evaluation → the engine
evaluates USDA/FDA/EU/Codex/GS1 rules → a report with per-rule pass/fail and evidence is produced
and anchored to the ledger.

## 7. Business requirements

| ID | Requirement |
|---|---|
| BR-1 | The platform must serve four distinct organisation types with segregated data and shared trust. |
| BR-2 | Provenance claims must be verifiable by a party that does not trust the platform operator. |
| BR-3 | Compliance evidence must be producible without manual data assembly. |
| BR-4 | The platform must be demonstrable offline on a single machine. |
| BR-5 | No agricultural or personal data may be exposed to unauthorised tenants or the public endpoint. |

## 8. Functional requirements

Requirement IDs are derived directly from the six learning-objective groups in the exam brief (Topic 135, ANPP-OP v0.1).
Group letters: **A** Precision Ag IoT Security, **B** GMO/Blockchain Traceability,
**C** Biosecurity & Sequence Screening, **D** Food Supply Chain Security,
**E** DevSecOps, **F** Regulatory Compliance.

### A — Precision Agriculture IoT Security and Data Protection

| ID | Requirement | Priority |
|---|---|---|
| FR-A1 | Provide comprehensive security for agricultural drones, sensors and autonomous farming equipment: unique device identity, provisioning, per-device secrets, authenticated telemetry, replay protection, device authorisation scoped to its own farm, lifecycle and revocation. | MUST |
| FR-A2 | Provide secure data pipelines for satellite imagery, soil sensors and yield monitoring: schema-validated typed ingestion, integrity hashing, range validation, quarantine of malformed data, and encrypted-at-rest storage of payloads. | MUST |
| FR-A3 | Protect against agricultural data theft and competitive intelligence attacks: detect bulk export, off-hours access, cross-tenant access attempts and abnormal query volume; rate-limit; alert; log. | MUST |
| FR-A4 | Monitor device health (battery, signal, firmware, last-seen) and raise alerts on degradation or silence. | SHOULD |
| FR-A5 | Detect anomalous telemetry indicating device compromise, spoofing or sensor failure using AI. | MUST |

### B — GMO and Biotechnology Traceability with Blockchain

| ID | Requirement | Priority |
|---|---|---|
| FR-B1 | Register genetically modified organisms and biotech crops (transformation event, trait, donor organism, developer, approval jurisdictions) and track them on a blockchain. | MUST |
| FR-B2 | Record supply-chain provenance from seed development through distribution as an ordered, signed chain of custody. | MUST |
| FR-B3 | Automatically validate GMO labelling and regulatory requirements (threshold rules, jurisdiction approval, label text correctness) and block non-compliant releases. | MUST |
| FR-B4 | Anchor every provenance-critical record to the ledger with a content hash and expose verification of any record against the chain. | MUST |
| FR-B5 | Represent the complete GMO lifecycle: origin → registration → certification → cultivation → harvest → processing → packaging → transport → distribution → retail → consumer. | MUST |

### C — Agricultural Biosecurity and Sequence Screening

| ID | Requirement | Priority |
|---|---|---|
| FR-C1 | AI-powered screening of nucleotide sequences for engineered agricultural pathogens and biosecurity threats, producing a risk verdict with alignment evidence. | MUST |
| FR-C2 | Automated risk assessment for agricultural gene editing and CRISPR crop modifications, including off-target scanning and a documented risk score. | MUST |
| FR-C3 | Dual-use research (DURC) monitoring: flag combinations of hazard class, intent and technique that constitute research of concern, and route them to a biosafety officer. | MUST |
| FR-C4 | Maintain a hazard/agent database with severity classes and a review workflow (`PENDING → APPROVED / BLOCKED`). | MUST |

### D — Food Supply Chain Security and Authentication

| ID | Requirement | Priority |
|---|---|---|
| FR-D1 | End-to-end food traceability combining blockchain records with IoT sensor evidence (e.g. cold-chain telemetry bound to a shipment). | MUST |
| FR-D2 | Automated authentication of organic, non-GMO and specialty food certifications, including validity window, issuer trust and scope matching. | MUST |
| FR-D3 | Food fraud detection and supply-chain integrity verification: quantity conservation, timeline consistency, geographic plausibility, certification conflicts, custody gaps. | MUST |
| FR-D4 | Consumer-facing verification by QR/reference code, unauthenticated, exposing only non-sensitive provenance. | MUST |

### E — DevSecOps for Agricultural Technology Platforms

| ID | Requirement | Priority |
|---|---|---|
| FR-E1 | Secure development practices for the farm-management and biotech application: coding standards, secret hygiene, pre-commit checks, review rules. | MUST |
| FR-E2 | Automated security testing for agricultural IoT and control systems: authn/authz tests, replay tests, injection tests, device-security test suite in CI. | MUST |
| FR-E3 | Vulnerability management for connected farming equipment and biotech labs: firmware/vulnerability inventory per device, severity, remediation status, and dependency/container/IaC scanning in CI. | MUST |

### F — Regulatory Compliance and Food Safety Automation

| ID | Requirement | Priority |
|---|---|---|
| FR-F1 | Automated compliance monitoring against USDA, FDA and international food-safety regulations (incl. Codex Alimentarius, EU 1829/2003, GS1). | MUST |
| FR-F2 | Automated reporting for biotech crop approvals and environmental impact assessments. | MUST |
| FR-F3 | Audit-trail management for food-safety certifications and traceability requirements — append-only, tamper-evident, exportable. | MUST |

### Cross-cutting platform requirements (derived, needed to satisfy the above)

| ID | Requirement | Priority |
|---|---|---|
| FR-X1 | Authentication with password hashing, JWT access/refresh, lockout on brute force. | MUST |
| FR-X2 | Role-based access control with least privilege across 9 roles and per-route permissions. | MUST |
| FR-X3 | Multi-organisation tenancy with data segregation. | MUST |
| FR-X4 | Notifications and alerting with severity and acknowledgement workflow. | MUST |
| FR-X5 | Dashboards and reporting for each persona. | MUST |
| FR-X6 | Immutable audit logging of every security-relevant action. | MUST |
| FR-X7 | Health/readiness/liveness endpoints and metrics. | SHOULD |

## 9. Non-functional requirements

| ID | Category | Requirement | Target |
|---|---|---|---|
| NFR-1 | Performance | Read API p95 latency (local, seeded DB) | < 200 ms |
| NFR-2 | Performance | Telemetry ingestion throughput, single node, inline AI scoring | ≥ 20 readings/s (measured 25) |
| NFR-2b | Performance | Telemetry ingestion throughput, single node, AI scoring deferred | ≥ 100 readings/s (measured 155) |
| NFR-3 | Performance | Sequence screening of a 5 kb query | < 2 s |
| NFR-4 | Performance | Ledger block append | < 50 ms |
| NFR-5 | Availability | Graceful degradation: AI or ledger outage must not break core CRUD | No 5xx cascade |
| NFR-6 | Security | All secrets from environment; none in source | 0 findings in secret scan |
| NFR-7 | Security | Every mutating route authenticated and authorised | 100% coverage, test-enforced |
| NFR-8 | Security | Passwords bcrypt (cost ≥ 12); tokens signed; sensitive payloads encrypted at rest | Verified by test |
| NFR-9 | Auditability | Every security-relevant action produces a hash-chained audit record | 100% |
| NFR-10 | Portability | Full stack runs offline via `docker compose up` or one script | Verified |
| NFR-11 | Maintainability | Typed schemas at every boundary; layered modules | Enforced in review |
| NFR-12 | Testability | Unit, integration, E2E, security and performance suites | All green |
| NFR-13 | Privacy | No PII or secret material in logs; farm data scoped to its organisation | Verified by test |
| NFR-14 | Accessibility | Keyboard navigable, semantic HTML, WCAG 2.1 AA contrast | Reviewed |
| NFR-15 | Interoperability | GS1-style identifiers and EPCIS-shaped events | Implemented |

### Note on NFR-2 (revised after measurement)

The original target was 200 readings/s. Profiling the ingestion path
(`backend/tests/performance/test_performance.py::test_ingestion_cost_breakdown`) showed where the
time actually goes per message:

| Stage | Cost |
|---|---|
| HMAC verification | 0.010 ms |
| Physical-range validation | 0.005 ms |
| AES-GCM payload encryption | 0.012 ms |
| Anomaly scoring (scikit-learn, single row) | 6.5–10 ms |

The security controls together account for under 0.03 ms — under 0.5% of the cost. Effectively all
of it is scikit-learn's per-call overhead on a single-row prediction. Two consequences:

1. The requirement was rewritten to match measured behaviour rather than left as an unmet claim.
   `TELEMETRY_INLINE_SCORING` selects the mode: inline gives the caller an immediate anomaly
   verdict (what the demonstration wants), deferred moves scoring to a background task and raises
   throughput about sixfold.
2. Reaching 200+ readings/s is a deployment change, not an application change: PostgreSQL instead
   of SQLite, several Uvicorn workers, and batched scoring across messages. Nothing in the
   security envelope needs to be relaxed to get there, which was the point worth proving.

## 10. Core features (product view)

1. **Device Trust Centre** — inventory, provisioning, health, firmware/vulnerability posture, quarantine.
2. **Field Intelligence** — telemetry, satellite scenes, NDVI, yield, crop-disease vision.
3. **Threat & Anomaly Detection** — AI anomaly scoring, data-theft detection, security alerts.
4. **Biosecurity Desk** — sequence screening, CRISPR risk assessment, DURC monitoring, review queue.
5. **GMO Registry** — transformation events, approvals, seed lots, labelling validation.
6. **Traceability Ledger** — chain of custody, EPCIS-style events, blockchain anchoring and verification.
7. **Certification & Fraud** — certification issuance/validation, fraud scoring, integrity verification.
8. **Consumer Verification** — public QR lookup.
9. **Compliance Automation** — rule engine, per-batch reports, environmental impact assessment.
10. **Audit & Governance** — hash-chained audit log, exports, incident records.
11. **DevSecOps** — CI security gates, scanning, vulnerability management.

## 11. User roles and permissions

| Role | Key permissions |
|---|---|
| `ADMIN` | All. User/org management, platform config. |
| `SECURITY_ANALYST` | Read all security data, manage alerts/incidents, quarantine devices, read audit. |
| `FARM_OPERATOR` | CRUD own farms/fields/crops/devices, read own telemetry and AI insight. |
| `AGRONOMIST` | Read farm data and AI insight for assigned org; no device mutation. |
| `BIOTECH_RESEARCHER` | Create GMO events, seed lots, submit screenings and CRISPR assessments. |
| `BIOSAFETY_OFFICER` | Review/approve/block screenings and gene edits; read all biosecurity data. Does **not** grant market access in a jurisdiction. |
| `SUPPLY_CHAIN_OPERATOR` | Create products, batches, supply-chain events, shipments. |
| `CERTIFIER` | Issue, suspend, revoke certifications; read supply chain. |
| `REGULATOR` | Read-only across compliance, traceability and audit; run compliance reports; record jurisdictional GMO approvals (the only ledger write a regulator makes). |
| *(public)* | Verification endpoint only, non-sensitive fields. |

## 12. Notifications

Severity `INFO / WARNING / HIGH / CRITICAL`. Channels: in-app notification centre (implemented),
webhook/email (documented production path). Triggers: device anomaly, device offline, screening
HIGH/BLOCKED, certification expiring or expired, fraud score above threshold, compliance failure,
custody gap, incident opened.

## 13. Reporting and dashboards

Per persona: Operations dashboard (devices, telemetry, alerts), Biosecurity dashboard (screening
queue, risk distribution), Supply-chain dashboard (batches in transit, integrity status),
Compliance dashboard (rule pass rate, expiring certificates), Security dashboard (alerts,
incidents, audit volume). Exports: compliance report, EIA report, audit export, traceability
dossier.

## 14. Success criteria

| ID | Criterion |
|---|---|
| SC-1 | All 20 functional requirements implemented, tested, and traceable in `REQUIREMENTS-TRACEABILITY.md`. |
| SC-2 | `docker compose up` (or `scripts/run_local.sh`) yields a working system with seeded demo data. |
| SC-3 | The full demo journey (seed → farm → harvest → processing → shipment → consumer QR) succeeds. |
| SC-4 | A tampered record is detected by ledger verification. |
| SC-5 | An unauthenticated or wrongly-authorised request to any mutating route is rejected — test-enforced. |
| SC-6 | Secret scan, dependency scan and test suite pass. |

## 15. KPIs

Device authentication success rate; mean time to detect an anomalous device; % batches with
complete chain of custody; % sequences screened before approval; fraud detection precision on the
labelled demo set; % compliance rules automatically evaluated; CI security-gate pass rate.

## 16. Constraints

See `EXAM-LIMITATIONS.md`. Summary: no hardware, no production Fabric, no new Python
dependencies, offline, single machine, demonstrable in 15–20 minutes.

## 17. Assumptions

See `EXAM-LIMITATIONS.md`. Principal assumption: a faithful simulation of devices and the blockchain
network, with real cryptography and real security controls, satisfies the specification's intent
for an academic demonstration, provided every simulated element is explicitly labelled.

## 18. Risks

| ID | Risk | Impact | Mitigation |
|---|---|---|---|
| R-1 | Simulated blockchain mistaken for production Fabric | Credibility | Explicit `REAL / DEMO / MOCK` markings; documented Fabric migration path in `Blockchain-integration.md` |
| R-2 | Synthetic AI data overstates model quality | Credibility | Report metrics on synthetic data only; state limitations |
| R-3 | Scope breadth reduces depth | Quality | Prioritise MUST requirements; ship vertical slices end to end |
| R-4 | Offline constraint blocks tooling | Delivery | Stdlib-first; CI tools declared but executed in CI, not locally |
| R-5 | Compliance rules misread as legal advice | Legal | Disclaimer in `docs/` and UI |

## 19. Future enhancements

Real Hyperledger Fabric deployment; X.509 device PKI with hardware root of trust; MQTT/TLS
ingestion at scale; federated learning across cooperatives; real satellite provider integration;
LIMS integration for laboratories; formal verification of chaincode; SIEM integration; mobile
consumer app with NFC.
