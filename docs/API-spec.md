# API-spec.md — API Specification

Complete API surface: **101 paths, 121 operations** across 17 route groups. The authoritative machine-readable specification is generated directly from the running application and committed alongside this document as [`openapi.json`](openapi.json) (OpenAPI 3.1) — regenerate it with:

```bash
curl http://127.0.0.1:8000/openapi.json > docs/openapi.json
```

This document is the human-readable index: purpose, authentication, authorisation and security notes per group, in the format required by the brief:

```
HTTP method · Endpoint · Purpose · Authentication · Authorization · Request ·
Validation · Response · Error responses · Status codes · Example · Security considerations
```

Full request/response schemas for every operation are in `openapi.json` (and interactively at `/docs` in a non-production deployment); this document gives the narrative that a schema alone cannot.

---

## AI (4 operations)

**Authentication:** Bearer JWT.  **Requirements:** FR-A5

**Authorization / security notes:** `ai:read`/`ai:run`. Crop-vision accepts either a caller-supplied pixel array or an explicitly-labelled synthetic patch (`simulate_label`), never silently.

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/api/v1/ai/analyses` | List AI analyses |
| POST | `/api/v1/ai/crop-vision` | Classify crop leaf condition from an image |
| GET | `/api/v1/ai/model-cards` | Model cards for every deployed model |
| GET | `/api/v1/ai/summary` | AI activity summary |

## Administration (8 operations)

**Authentication:** Bearer JWT.  **Requirements:** FR-X2, FR-X3

**Authorization / security notes:** `user:read`/`user:write`/`org:read`/`org:write` required per route. `PATCH /users/{id}` edits name/role only — status transitions (approve/suspend) are a separate, dedicated state machine and cannot be bypassed through this route. A role change immediately invalidates that user's outstanding tokens.

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/api/v1/admin/organizations` | List organisations |
| POST | `/api/v1/admin/organizations` | Create an organisation and its ledger identity |
| GET | `/api/v1/admin/roles` | Role to permission matrix |
| GET | `/api/v1/admin/users` | List users |
| GET | `/api/v1/admin/users/{user_id}` | Get one user |
| PATCH | `/api/v1/admin/users/{user_id}` | Update a user's name or role (status changes use /approve, /suspend) |
| POST | `/api/v1/admin/users/{user_id}/approve` | Approve a pending user |
| POST | `/api/v1/admin/users/{user_id}/suspend` | Suspend a user and revoke their sessions |

## Audit (4 operations)

**Authentication:** Bearer JWT.  **Requirements:** FR-F3, FR-X6

**Authorization / security notes:** `audit:read`. Non-cross-tenant roles see only their own organisation's entries; export includes a fresh chain-verification result.

| Method | Endpoint | Purpose |
|---|---|---|
| POST | `/api/v1/audit/anchor` | Anchor the current audit chain head to the ledger |
| GET | `/api/v1/audit/export` | Export the audit trail as JSON evidence |
| GET | `/api/v1/audit/logs` | List audit records |
| GET | `/api/v1/audit/verify` | Recompute the audit hash chain and report any divergence |

## Authentication (5 operations)

**Authentication:** None (public) for register/login/refresh; bearer JWT for `/auth/me` and `/auth/logout`.  **Requirements:** FR-X1

**Authorization / security notes:** Rate-limited (10/min/IP). Lockout after 5 failed logins. Refresh rotation with reuse detection kills the whole token family.

| Method | Endpoint | Purpose |
|---|---|---|
| POST | `/api/v1/auth/login` | Exchange credentials for an access and refresh token |
| POST | `/api/v1/auth/logout` | Revoke all refresh tokens |
| GET | `/api/v1/auth/me` | Current principal and effective permissions |
| POST | `/api/v1/auth/refresh` | Rotate a refresh token |
| POST | `/api/v1/auth/register` | Register a new account |

## Biosecurity (11 operations)

**Authentication:** Bearer JWT.  **Requirements:** FR-C1, FR-C2, FR-C3, FR-C4

**Authorization / security notes:** `biosecurity:submit` to screen; `biosecurity:review` to resolve a PENDING_REVIEW/BLOCKED record; `hazard:write` to extend the reference database. A submitted sequence is never returned in any response.

| Method | Endpoint | Purpose |
|---|---|---|
| POST | `/api/v1/biosecurity/crispr` | Assess the risk of a CRISPR gene-edit proposal |
| GET | `/api/v1/biosecurity/crispr` | List CRISPR assessments |
| POST | `/api/v1/biosecurity/crispr/{assessment_id}/review` | Review a flagged gene-edit proposal |
| GET | `/api/v1/biosecurity/hazards` | List the hazard database |
| POST | `/api/v1/biosecurity/hazards` | Add a hazard sequence to the reference database |
| POST | `/api/v1/biosecurity/screenings` | Screen a nucleotide sequence against the hazard database |
| GET | `/api/v1/biosecurity/screenings` | List screenings |
| GET | `/api/v1/biosecurity/screenings/queue` | Biosafety review queue |
| GET | `/api/v1/biosecurity/screenings/{screening_id}` | Screening detail with alignment evidence |
| POST | `/api/v1/biosecurity/screenings/{screening_id}/review` | Approve or reject a flagged or blocked screening |
| GET | `/api/v1/biosecurity/statistics` | Biosecurity dashboard statistics |

## Blockchain (9 operations)

**Authentication:** Bearer JWT.  **Requirements:** FR-B4

**Authorization / security notes:** `blockchain:read`. Read-only: no route can mutate the ledger directly. `POST /verify-record` is restricted to the record's own organisation(s) or a cross-tenant oversight role — an IDOR fix from the final security audit (see `SECURITY-ASSESSMENT.md`).

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/api/v1/blockchain/blocks` | Recent blocks |
| GET | `/api/v1/blockchain/blocks/{number}` | Get one block |
| GET | `/api/v1/blockchain/contracts` | Deployed chaincode functions and endorsement policies |
| GET | `/api/v1/blockchain/state/{key}` | Read a world-state key |
| GET | `/api/v1/blockchain/stats` | Ledger height, transactions and participants |
| GET | `/api/v1/blockchain/transactions/{tx_id}` | Get one transaction |
| GET | `/api/v1/blockchain/transactions/{tx_id}/proof` | Merkle inclusion proof for a transaction |
| GET | `/api/v1/blockchain/verify` | Replay and verify the whole chain |
| POST | `/api/v1/blockchain/verify-record` | Verify a stored record against its ledger anchor |

## Compliance (6 operations)

**Authentication:** Bearer JWT.  **Requirements:** FR-F1, FR-F2

**Authorization / security notes:** `compliance:read`/`compliance:run`. Reports cite the specific regulation each rule implements.

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/api/v1/compliance/dashboard` | Compliance dashboard |
| POST | `/api/v1/compliance/eia` | Generate an environmental impact assessment for a biotech crop |
| POST | `/api/v1/compliance/evaluate` | Evaluate a batch against a jurisdiction's rule set |
| GET | `/api/v1/compliance/reports` | List reports |
| GET | `/api/v1/compliance/reports/{report_id}` | Get a report |
| GET | `/api/v1/compliance/rules` | The implemented rule set and its citations |

## Dashboard (1 operation)

**Authentication:** Bearer JWT.  **Requirements:** FR-X5

**Authorization / security notes:** Tiles are filtered to permissions the caller's role actually holds.

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/api/v1/dashboard` | Dashboard tiles filtered to the caller's role and organisation |

## Devices (13 operations)

**Authentication:** Bearer JWT for management; device HMAC for telemetry (see Telemetry).  **Requirements:** FR-A1, FR-A4, FR-E3

**Authorization / security notes:** `device:read`/`device:write`/`device:contain`. The provisioning response contains the device secret exactly once.

| Method | Endpoint | Purpose |
|---|---|---|
| POST | `/api/v1/devices` | Register and provision a device; the secret is returned once |
| GET | `/api/v1/devices` | List devices |
| GET | `/api/v1/devices/posture` | Fleet security and vulnerability posture |
| POST | `/api/v1/devices/sweep/health` | Raise alerts for devices that have stopped reporting |
| GET | `/api/v1/devices/vulnerabilities` | List device vulnerabilities |
| POST | `/api/v1/devices/vulnerabilities` | Record a vulnerability against a device |
| POST | `/api/v1/devices/vulnerabilities/{vulnerability_id}/remediate` | Mark a vulnerability remediated |
| GET | `/api/v1/devices/{device_id}` | Get a device |
| POST | `/api/v1/devices/{device_id}/activate` | Activate a device |
| POST | `/api/v1/devices/{device_id}/quarantine` | Quarantine a device and revoke its credential (containment action) |
| POST | `/api/v1/devices/{device_id}/retire` | Retire a device |
| POST | `/api/v1/devices/{device_id}/rotate-secret` | Issue a new device secret and revoke the old |
| POST | `/api/v1/devices/{device_id}/suspend` | Suspend a device |

## Farms (7 operations)

**Authentication:** Bearer JWT.  **Requirements:** FR-B5

**Authorization / security notes:** `farm:read`/`farm:write`. Organisation-scoped: a farm belonging to another tenant returns 404, not 403 (T-05).

| Method | Endpoint | Purpose |
|---|---|---|
| POST | `/api/v1/crops` | Record a planting |
| GET | `/api/v1/crops` | List crops |
| POST | `/api/v1/farms` | Register a farm |
| GET | `/api/v1/farms` | List farms |
| GET | `/api/v1/farms/{farm_id}` | Get a farm |
| POST | `/api/v1/fields` | Add a field to a farm |
| GET | `/api/v1/fields` | List fields |

## GMO Registry (10 operations)

**Authentication:** Bearer JWT.  **Requirements:** FR-B1, FR-B3, FR-B5

**Authorization / security notes:** `gmo:write` to register/create; `gmo:approve` (regulator only) to record a jurisdictional approval. Registration is refused (422) without a passing biosecurity screening.

| Method | Endpoint | Purpose |
|---|---|---|
| POST | `/api/v1/gmo/events` | Register a GMO transformation event and anchor it to the ledger |
| GET | `/api/v1/gmo/events` | List GMO events |
| GET | `/api/v1/gmo/events/{event_id}` | Get a GMO event |
| POST | `/api/v1/gmo/events/{event_id}/approvals` | Record a jurisdictional approval |
| GET | `/api/v1/gmo/events/{event_id}/approvals` | List approvals for a GMO event |
| GET | `/api/v1/gmo/events/{event_id}/verify` | Verify a GMO event against its ledger anchor |
| GET | `/api/v1/gmo/labelling/{batch_id}` | Validate GMO labelling for a batch |
| POST | `/api/v1/gmo/labelling/{batch_id}/check-release` | Check and record whether a batch may be released into a jurisdiction |
| POST | `/api/v1/gmo/seed-lots` | Create a seed lot |
| GET | `/api/v1/gmo/seed-lots` | List seed lots |

## Notifications (4 operations)

**Authentication:** Bearer JWT.  **Requirements:** FR-X4

**Authorization / security notes:** Scoped to the caller; no permission beyond authentication.

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/api/v1/notifications` | List my notifications |
| POST | `/api/v1/notifications/read-all` | Mark every notification as read |
| GET | `/api/v1/notifications/unread-count` | Unread notification count |
| POST | `/api/v1/notifications/{notification_id}/read` | Mark as read |

## Operations (4 operations)

**Authentication:** None.  **Requirements:** FR-X7

**Authorization / security notes:** `/health`, `/health/live`, `/health/ready`, `/metrics` — no business data.

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/health` | Liveness and readiness summary |
| GET | `/health/live` | Liveness probe |
| GET | `/health/ready` | Readiness probe |
| GET | `/metrics` | Prometheus metrics |

## Public Verification (2 operations)

**Authentication:** None — deliberately unauthenticated.  **Requirements:** FR-D4

**Authorization / security notes:** IP rate-limited. Returns only non-sensitive fields: never farmer identity, coordinates, or commercial terms.

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/api/v1/verify/{code}` | Verify a product by its QR verification code |
| GET | `/api/v1/verify/{code}/qr` | QR code for the public verification page (SVG) |

## Security Operations (9 operations)

**Authentication:** Bearer JWT.  **Requirements:** FR-A3, FR-X4

**Authorization / security notes:** `alert:read`/`alert:write`/`incident:read`/`incident:write`. Evaluating another principal's access pattern requires the analyst role or a cross-tenant oversight role.

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/api/v1/security/alerts` | List alerts |
| POST | `/api/v1/security/alerts/{alert_id}/acknowledge` | Acknowledge an alert |
| POST | `/api/v1/security/alerts/{alert_id}/resolve` | Resolve an alert |
| GET | `/api/v1/security/dashboard` | Security operations dashboard |
| GET | `/api/v1/security/data-theft/evaluate` | Score a principal's access pattern for exfiltration |
| POST | `/api/v1/security/data-theft/sweep` | Score every recently active principal |
| GET | `/api/v1/security/incidents` | List incidents |
| GET | `/api/v1/security/incidents/{incident_id}` | Incident detail with its timeline |
| PATCH | `/api/v1/security/incidents/{incident_id}` | Update an incident |

## Supply Chain (17 operations)

**Authentication:** Bearer JWT.  **Requirements:** FR-B2, FR-D1, FR-D2, FR-D3

**Authorization / security notes:** `supply:read`/`supply:write`; `cert:issue`/`cert:revoke` for certifications. Every mutation is anchored to the ledger and validated against the batch's current lifecycle state. Linking a certification to a batch requires the certification's `subject_org_id` to match the batch's organisation — closing a BOLA finding from the final security audit (see `SECURITY-ASSESSMENT.md`).

| Method | Endpoint | Purpose |
|---|---|---|
| POST | `/api/v1/supply-chain/batches` | Create a traceable batch and anchor it |
| GET | `/api/v1/supply-chain/batches` | List batches |
| GET | `/api/v1/supply-chain/batches/{batch_id}` | Get a batch |
| GET | `/api/v1/supply-chain/batches/{batch_id}/custody` | Chain of custody and lineage for a batch |
| POST | `/api/v1/supply-chain/batches/{batch_id}/verify` | Verify supply-chain integrity and score for fraud |
| POST | `/api/v1/supply-chain/certifications` | Issue a certification |
| GET | `/api/v1/supply-chain/certifications` | List certifications |
| POST | `/api/v1/supply-chain/certifications/{certification_id}/link` | Claim a certification on a batch |
| POST | `/api/v1/supply-chain/certifications/{certification_id}/revoke` | Revoke a certification |
| POST | `/api/v1/supply-chain/events` | Record an EPCIS-shaped supply-chain event |
| GET | `/api/v1/supply-chain/events` | List events |
| GET | `/api/v1/supply-chain/fraud-assessments` | List fraud assessments |
| POST | `/api/v1/supply-chain/products` | Create a product |
| GET | `/api/v1/supply-chain/products` | List products |
| POST | `/api/v1/supply-chain/shipments` | Create a shipment |
| GET | `/api/v1/supply-chain/shipments` | List shipments |
| GET | `/api/v1/supply-chain/shipments/{shipment_id}/cold-chain` | Cold-chain evidence for a shipment |

## Telemetry (7 operations)

**Authentication:** Bearer JWT for reads; device identity (`X-Device-*` headers, HMAC-SHA256) for ingestion.  **Requirements:** FR-A2, FR-A5

**Authorization / security notes:** Ingestion checks device status, HMAC signature, timestamp window, nonce replay, then range-validates every channel before persisting encrypted.

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/api/v1/telemetry` | List telemetry |
| POST | `/api/v1/telemetry/batch` | Ingest a gateway batch; each message is individually signed |
| GET | `/api/v1/telemetry/devices/{device_id}/series` | Time series for one device |
| POST | `/api/v1/telemetry/ingest` | Ingest one signed telemetry message from a device |
| GET | `/api/v1/telemetry/insights/field-stress` | Precision-farming field stress ranking |
| POST | `/api/v1/telemetry/satellite/scenes` | Ingest satellite scene metadata (checksum verified) |
| GET | `/api/v1/telemetry/satellite/scenes` | List satellite scenes |

## Standard error responses


| Status | Meaning | When |
|---|---|---|
| 400 | Bad request | Malformed request structure |
| 401 | Unauthenticated | Missing/invalid/expired bearer token, or device authentication failure |
| 403 | Permission denied | Authenticated but lacking the required permission, or attempting an operation on a resource whose organisation does not match (BOLA guard) |
| 404 | Not found | Resource does not exist, or belongs to another tenant (never 403, to avoid leaking tenancy) |
| 409 | Conflict | Duplicate identifier, replayed nonce, already-resolved record |
| 422 | Validation / semantic failure | Schema violation, or a business rule rejection (e.g. failed screening gate, illegal lifecycle transition, inactive certification) |
| 429 | Rate limited | Per-identity or per-IP request budget exceeded; `Retry-After` header set |
| 503 | Integration unavailable | Ledger or AI dependency degraded; the business write still completes where possible |

Every error body is RFC-7807-shaped: `{type, title, status, detail, correlation_id}`, with an
`errors[]` array of `{field, message}` for schema validation failures. Internal errors (500)
never leak a stack trace or dependency detail — only a correlation id to quote when reporting.


## Example: authenticated request/response

```
POST /api/v1/biosecurity/screenings
Authorization: Bearer <jwt>
Content-Type: application/json

{"name": "Candidate insert", "sequence": "ACGT...", "intent": "drought tolerance improvement"}
```
```
201 Created
{
  "id": "6ec7b965-...", "verdict": "CLEAR", "status": "APPROVED_AUTO",
  "max_identity": 0.0, "hazard_classes": [], "sequence_length": 1200,
  "engine_version": "screening-1.0.0", "created_at": "2026-09-03T20:00:00Z"
}
```

## Example: device-authenticated telemetry

```
POST /api/v1/telemetry/ingest
X-Device-Id: <device-id>
X-Device-Timestamp: 2026-09-03T20:00:00+00:00
X-Device-Nonce: <32-byte hex>
X-Device-Signature: <hmac-sha256 hex>
Content-Type: application/json

{"recorded_at": "2026-09-03T20:00:00+00:00", "nonce": "<same nonce>",
 "readings": {"soil_moisture_pct": 31.2, "ph": 6.4}}
```
```
202 Accepted
{"accepted": true, "telemetry_id": "...", "quality": "OK", "anomaly_score": 0.04}
```

## Versioning

All routes are under `/api/v1`. A breaking change would introduce `/api/v2` alongside it
rather than mutating `/v1` in place; no breaking change has occurred in this project.
