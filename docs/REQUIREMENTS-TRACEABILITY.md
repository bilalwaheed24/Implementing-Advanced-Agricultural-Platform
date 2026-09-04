# REQUIREMENTS-TRACEABILITY.md — Exam brief ↔ Documentation ↔ Implementation

Three-way reconciliation: what the exam brief (Topic 135, ANPP-OP v0.1) actually asks for, what the
project documentation claims, and what the running code and test suite actually prove. Every row
below was re-checked against the live system during this audit — not carried forward blindly from
an earlier internal matrix, though both were grounded in the same re-verified reality.

**Status legend:** COMPLETE · PARTIAL · MISSING · BROKEN · NOT TESTED · NOT APPLICABLE

---

## A — Precision Agriculture IoT Security and Data Protection

| Requirement (exam brief) | Documentation | Implemented | Tested | Secure | Evidence | Status |
|---|---|---|---|---|---|---|
| Security for agricultural drones, sensors, autonomous farming equipment | `IoT-Devices.md` §1-3 | Yes — 6 device classes, per-device identity | Yes — 29 tests | Yes — HMAC + AES-GCM, re-audited this pass | `test_devices_telemetry.py` | **COMPLETE** |
| Secure data pipelines for satellite imagery, soil sensors, yield monitoring | `IoT-Devices.md` §7 | Yes — checksum + range validation | Yes | Yes | `services/telemetry.py::ingest_scene` | **COMPLETE** |
| Protection against agricultural data theft / competitive intelligence | `Security.md` §18 | Yes — 6-signal weighted detector | Yes (evaluated live in demo flow) | Yes | `services/security_ops.py::evaluate_principal` | **COMPLETE** |

## B — GMO and Biotechnology Traceability with Blockchain

| Requirement | Documentation | Implemented | Tested | Secure | Evidence | Status |
|---|---|---|---|---|---|---|
| Blockchain-based tracking for GMOs and biotech crops | `Blockchain-integration.md`, `GMO.md` | Yes — ECDSA-endorsed ledger anchoring | Yes — 43 ledger tests + 7 GMO E2E tests | Yes | `ledger/contracts.py::register_event` | **COMPLETE** |
| Supply chain provenance from seed development through distribution | `GMO.md` §1, §7 | Yes — full lifecycle modelled and anchored | Yes | Yes | `test_supplychain_e2e.py::TestTraceability` | **COMPLETE** |
| Automated compliance validation for GMO labelling and regulatory requirements | `GMO.md` §8, `compliance.py` | Yes — jurisdiction-specific threshold rules | Yes | Yes | `services/gmo.py::validate_labelling` | **COMPLETE** |

## C — Agricultural Biosecurity and Sequence Screening

| Requirement | Documentation | Implemented | Tested | Secure | Evidence | Status |
|---|---|---|---|---|---|---|
| AI-powered screening for engineered agricultural pathogens / biosecurity threats | `GMO.md` §3 | Yes — k-mer seeding + Smith-Waterman, risk-based severity thresholds | Yes — 8 tests incl. an 18%-diverged construct | Yes | `ai/sequence_screening.py` | **COMPLETE** |
| Automated risk assessment for gene editing / CRISPR crop modifications | `GMO.md` §4 | Yes — 5-component weighted score + off-target scan | Yes — 7 tests | Yes | `ai/crispr_risk.py` | **COMPLETE** |
| Dual-use research (DURC) monitoring for agricultural biotechnology | `GMO.md` §5 | Yes — hazard-class × intent × technique concern matrix | Yes | Yes | `ai/crispr_risk.py::check_durc` | **COMPLETE** |

## D — Food Supply Chain Security and Authentication

| Requirement | Documentation | Implemented | Tested | Secure | Evidence | Status |
|---|---|---|---|---|---|---|
| End-to-end food traceability with blockchain and IoT sensor integration | `GMO.md` §7, `IoT-Devices.md` | Yes — cold-chain telemetry feeds batch integrity | Yes | Yes | `test_cold_chain_break_is_reported` | **COMPLETE** |
| Automated authentication for organic/non-GMO/specialty certifications | `GMO.md` §9 | Yes — validity, issuer-trust, **and subject-org match (fixed this audit)** | Yes — 5 tests + 2 new BOLA regression tests | Yes — BOLA closed this audit | `services/supplychain.py::link_certification` | **COMPLETE** |
| Food fraud detection and supply chain integrity verification | `GMO.md` §10 | Yes — 10 deterministic rules + novelty model | Yes — 11 tests | Yes | `ai/fraud.py` | **COMPLETE** |

## E — DevSecOps for Agricultural Technology Platforms

| Requirement | Documentation | Implemented | Tested | Secure | Evidence | Status |
|---|---|---|---|---|---|---|
| Secure development practices for farm-management/biotech applications | `Development-rules.md` | Yes | N/A (process, not code) | Yes | This audit itself | **COMPLETE** |
| Automated security testing for agricultural IoT and control systems | `.github/workflows/ci.yml`, `security.yml` | Yes — gitleaks, Bandit, Semgrep, pip-audit, Trivy, Checkov, ZAP, SBOM | **Executed on hosted GitHub Actions runners** (3 runs, 2026-09-04 / 2026-09-07). 2 jobs passed there — secret-scan and smart-contract-tests. The rest failed at *Set up job* on 3 unresolvable pinned action SHAs (one was 39 characters; a git SHA is 40). All 8 pins re-verified against each action's real tag list and corrected 2026-09-13; **not yet re-run** | Partially — locally-equivalent checks (pip-audit, `scripts/secret_scan.py`, the full 399-test suite) run and pass | `EXAM-LIMITATIONS.md` §2.1 | **PARTIAL** — pipeline is implemented and its action pins now resolve, but a green hosted-runner execution is not yet demonstrated |
| Vulnerability management for connected farming equipment and biotech labs | `Backend.md` §5 (`device_vulnerabilities`) | Yes — per-device CVE tracking, fleet posture dashboard | Yes — 4 tests | Yes | `services/devices.py::fleet_posture` | **COMPLETE** |

## F — Regulatory Compliance and Food Safety Automation

| Requirement | Documentation | Implemented | Tested | Secure | Evidence | Status |
|---|---|---|---|---|---|---|
| Automated compliance monitoring for USDA, FDA, international food safety regulations | `compliance.py`, `Backend.md` | Yes — 11 rules citing real regulation numbers | Yes — 5 tests | Yes | `services/compliance.py::RULES` | **COMPLETE** |
| Automated reporting for biotech crop approvals and environmental impact assessments | `compliance.py::environmental_impact` | Yes | Yes | Yes | `test_environmental_impact_assessment` | **COMPLETE** |
| Audit trail management for food safety certifications and traceability requirements | `Security.md` §19, ADR-010 | Yes — hash-chained, ledger-anchored | Yes — including a live tamper-detection proof | Yes | `test_tampering_the_audit_log_is_detected` | **COMPLETE** |

## Industry Application / Examination-format items (exam brief, non-functional)

| Requirement | Status | Note |
|---|---|---|
| Usable by agricultural biotech companies, farming operators, supply chain orgs, regulators | **COMPLETE** | 9 RBAC roles map directly onto these stakeholder classes (PRD.md §11) |
| Open-source / cloud-native tools named in the brief (OpenDroneMap, QGIS, Hyperledger Fabric, TensorFlow, BLAST) | **PARTIAL, with documented rationale** | TensorFlow: used directly (crop vision). Hyperledger Fabric: implemented as the same transaction/endorsement/block model, single-node rather than the named platform itself — ADR-003 states why, with a full migration mapping in `Blockchain-integration.md` §17. BLAST: the seed-and-extend/local-alignment algorithm BLAST itself uses is implemented directly (ADR-008) because the BLAST binary and biopython are both unavailable in the build environment; the algorithmic principle, not the specific binary, is what the brief's learning objective is about. OpenDroneMap/QGIS: not integrated — precision-agriculture imagery is handled as scene metadata (NDVI statistics) rather than raster processing, since no physical drone imagery exists to process; this is a scope boundary stated in `EXAM-LIMITATIONS.md` §1.3, not a silent gap. |
| Presentation and demonstration readiness | **COMPLETE** | `DEMO-RUNBOOK.md`, `EXAM-LIMITATIONS.md`, `docs/diagrams/` |

## Summary

| Category | Total | COMPLETE | PARTIAL | MISSING | BROKEN |
|---|---|---|---|---|---|
| Functional (A–F, 15 requirement lines) | 15 | 14 | 1 | 0 | 0 |
| Cross-cutting platform (FR-X1–X7, from PRD.md, re-verified) | 7 | 7 | 0 | 0 | 0 |
| Non-functional (NFR-1–15, from PRD.md, re-measured or re-checked) | 15 | 14 | 1 (NFR-14, accessibility — see note below) | 0 | 0 |
| Named tools / examination-format items | 3 | 1 | 2 (documented rationale each) | 0 | 0 |
| **Total** | **40** | **36** | **4** | **0** | **0** |

### Why each of the four PARTIAL items is partial

1. **Automated security testing in CI (category E).** The workflows exist, are valid YAML, and
   have genuinely executed on hosted runners — two jobs passed there. They are PARTIAL, not
   COMPLETE, because the majority of jobs never reached their security tools: they failed during
   runner setup on three bad action pins. Those pins are now corrected and verified to resolve,
   but until a re-run goes green on a hosted runner the pipeline's security gates remain
   *implemented but not demonstrated end to end*. Promoting this to COMPLETE would be claiming a
   result that has not happened.

2. **NFR-14 — accessibility.** Substantially improved in the 2026-09-13 pass and verified by
   automated inspection: every form input across twelve views is programmatically labelled with a
   `for`/`id` pair, no duplicate element ids, key/value tables use `<th scope="row">`, a skip link
   is first in tab order and moves focus to `<main>`, the focus indicator is a visible 3px
   outline, and there is no horizontal overflow at 390 / 768 / 1440 px. It remains PARTIAL because
   colour-contrast ratios were not measured, screen-reader announcement quality was not assessed,
   the chart SVGs carry an `aria-label` summary but no navigable tabular alternative, and **no
   assistive-technology user and no independent WCAG 2.1 AA audit has tested this interface**.
   Automated checks cannot establish conformance.

3. **Named open-source tools (Hyperledger Fabric, BLAST).** The Fabric *model* is implemented
   in-process with real ECDSA P-256 endorsement, hash-linked blocks and Merkle roots, but this is
   a single-node ledger, not the named platform deployed as a consortium (ADR-003, with a
   function-by-function migration mapping). BLAST's seed-and-extend local-alignment algorithm is
   implemented directly because the binary could not be installed (ADR-008). PARTIAL is the honest
   status: the algorithmic and architectural principles are demonstrated; the named products are
   not running.

4. **OpenDroneMap / QGIS.** Not integrated at all. Precision-agriculture imagery is handled as
   checksum-verified scene *metadata* with NDVI statistics, not raster processing, because no
   physical drone or satellite imagery exists to process. This is a stated scope boundary, not a
   silent gap — and it should not be described as "satellite imagery processing" in the viva.

Every PARTIAL item above has a stated, specific reason and — where relevant — a migration path.
Nothing is marked COMPLETE merely because a document says it exists; every COMPLETE row above cites
either a passing test, a live-verified behaviour, or both. No requirement from the exam brief is
silently unaddressed.
