# Security Policy

This is an academic demonstration platform (EduQual Level 6, Topic 135). It is not a
production deployment and should not be exposed to the public internet as-is.

## Reporting a concern

This repository has no production users. If you are reviewing it as part of an academic
assessment and believe you have found a security issue, please raise it with the module
supervisor rather than through a public channel.

## What is real versus simulated

See `docs/EXAM-LIMITATIONS.md` and `docs/Decision.md` (ADR-003, ADR-009) for an explicit,
itemised list of what is a real security control versus a documented simulation of
infrastructure this deployment cannot depend on (physical IoT hardware, a production
Hyperledger Fabric network).

## Security documentation

| Document | Content |
|---|---|
| `docs/Security.md` | Threat model, security architecture, and every control in this platform |
| `docs/Development-rules.md` §9–12 | Contributor-facing security rules (secrets, dependencies, coding practices) |
| `scripts/secret_scan.py` | Offline secret scanner — run before every commit |
| `.github/workflows/security.yml` | Gitleaks, OWASP ZAP baseline, smart-contract security tests |
| `zap-rules.tsv` (this directory) | ZAP baseline scan overrides, with the reason for each |

## Known, deliberate simplifications

Recorded honestly rather than hidden — see the final project report's "Known Limitations"
section and the `ponytail:` comments throughout the codebase for specific, named ceilings
(e.g. the in-process rate limiter, the single-node ledger).
