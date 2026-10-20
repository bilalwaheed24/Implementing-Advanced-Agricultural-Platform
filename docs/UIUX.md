# UIUX.md — User Interface and Experience Design

Implementation: `frontend/`. Framework-free ES modules (ADR-004).

---

## 1. Design principles

1. **Trust is the product.** Every screen that shows a claim also shows whether it is verified, by
   whom, and when. Verification status is never implied by absence of a warning.
2. **Say what is simulated.** Demo and simulated data carry a visible badge. The platform never
   presents synthetic data as real.
3. **Explain every automated decision.** Any AI or rule verdict shows its reasons inline, not
   behind a modal.
4. **Severity drives visual weight.** Colour is never the only signal — severity also carries an
   icon and a text label (accessibility).
5. **Density with hierarchy.** Operators scan; a screen leads with what changed and what needs
   action.

## 2. Screens (derived from requirements, not invented)

| # | Screen | Serves | Requirement |
|---|---|---|---|
| 1 | Login | all | FR-X1 |
| 2 | Register | applicants | FR-X1 |
| 3 | Dashboard (role-aware) | all | FR-X5 |
| 4 | Farms and fields | operator, agronomist | FR-B5 |
| 5 | Farm/field detail with crops | operator, agronomist | FR-B5 |
| 6 | Devices (inventory, health, posture) | operator, analyst | FR-A1, FR-A4 |
| 7 | Device detail (telemetry, secret rotation, quarantine) | operator, analyst | FR-A1, FR-A5 |
| 8 | Device vulnerabilities | analyst | FR-E3 |
| 9 | Telemetry explorer (series, charts) | operator, agronomist | FR-A2 |
| 10 | Satellite scenes and NDVI | agronomist | FR-A2 |
| 11 | AI insights (anomalies, crop vision) | agronomist, analyst | FR-A5 |
| 12 | Security alerts | analyst | FR-A3, FR-X4 |
| 13 | Incidents | analyst | FR-X4 |
| 14 | Biosecurity: screening submission | researcher | FR-C1 |
| 15 | Biosecurity: screening detail with alignment evidence | researcher, biosafety officer | FR-C1 |
| 16 | Biosecurity: review queue | biosafety officer | FR-C4 |
| 17 | CRISPR risk assessment | researcher, biosafety officer | FR-C2, FR-C3 |
| 18 | GMO registry (events, approvals) | researcher, regulator | FR-B1 |
| 19 | GMO event detail with lineage and anchor | researcher, regulator | FR-B1, FR-B4 |
| 20 | Seed lots | researcher, operator | FR-B5 |
| 21 | Products and batches | supply operator | FR-B2 |
| 22 | Batch detail: custody chain, events, integrity | supply operator, regulator | FR-B2, FR-D3 |
| 23 | Supply-chain event recording | supply operator | FR-B2 |
| 24 | Shipments and cold chain | supply operator | FR-D1 |
| 25 | Certifications | certifier | FR-D2 |
| 26 | Fraud assessments | analyst, certifier | FR-D3 |
| 27 | Blockchain explorer and verification | all authenticated | FR-B4 |
| 28 | Compliance reports and EIA | regulator, supply operator | FR-F1, FR-F2 |
| 29 | Audit trail and chain verification | regulator, analyst | FR-F3 |
| 30 | Notifications | all | FR-X4 |
| 31 | User and organisation administration | admin | FR-X2, FR-X3 |
| 32 | Settings / profile | all | — |
| 33 | **Public verification** (`/verify.html`) | consumer, no login | FR-D4 |

## 3. Information architecture and navigation

```
Sidebar (role-filtered)
├── Overview            → Dashboard
├── Farm Operations     → Farms · Fields · Devices · Telemetry · Satellite
├── Intelligence        → AI Insights · Alerts · Incidents
├── Biosecurity         → Screenings · Review Queue · CRISPR
├── Biotechnology       → GMO Events · Approvals · Seed Lots
├── Supply Chain        → Products · Batches · Events · Shipments · Certifications · Fraud
├── Trust               → Blockchain · Compliance · Audit
└── Admin               → Users · Organisations · Settings
```

Navigation items a role cannot use are not rendered — and the server enforces the same rule, so
hiding is a convenience, never the control.

## 4. User flows in the UI

* **Provision a device:** Devices → New → form → secret shown once with a copy control and an
  explicit warning → activate → device appears with `ACTIVE` and a live-telemetry indicator.
* **Investigate an anomaly:** Alerts → row → device detail → telemetry chart with the anomalous
  window highlighted → Quarantine (confirmation dialog stating the consequence) → incident opened.
* **Screen a sequence:** Biosecurity → New screening → paste or upload → progress state → verdict
  card with per-hit alignment evidence table → if flagged, a review panel for the officer.
* **Trace a batch:** Batches → row → timeline of custody with each stage's organisation, time,
  location and anchor status → integrity verdict with reasons → QR code for the public page.
* **Consumer:** scan → `/verify.html?code=…` → product, origin, journey, certifications, GMO status,
  ledger verified badge.

## 5. Components

Header with correlation-safe error toasts; role-filtered sidebar; data table with sort, pagination
and page-size cap; filter bar; form controls with inline validation messages; verdict card
(score, level, reasons); timeline; stat tile; severity badge; anchor badge (`ANCHORED` /
`PENDING` / `FAILED` / `MISMATCH`); confirmation dialog for destructive or containment actions;
QR panel.

## 6. Charts

Hand-rendered inline SVG: time series with brushed anomaly bands, NDVI trend, alert severity
distribution, fleet posture bars, compliance pass-rate donut. All charts have a text summary and a
data table fallback for screen readers, and no chart uses colour alone to encode meaning.

## 7. Responsive behaviour

Single-column below 720 px with the sidebar collapsing to a menu; tables become stacked
definition lists below 600 px; the public verification page is designed mobile-first because it is
reached by scanning a QR code with a phone.

## 8. Accessibility (WCAG 2.1 AA target)

Semantic landmarks (`header`, `nav`, `main`), one `h1` per view, labelled form controls with
`aria-describedby` for errors, visible focus rings, full keyboard operability, `aria-live` for
toasts and async results, contrast ratio ≥ 4.5:1 for text in both palettes, no
information conveyed by colour alone, and `prefers-reduced-motion` respected.

## 9. States

| State | Treatment |
|---|---|
| Loading | Skeleton rows or an inline spinner with `aria-busy`; never a blank screen |
| Empty | Explains what the screen is for and the action that creates the first record |
| Error | Human-readable message plus the correlation id for support; never a stack trace |
| Partial | Where the ledger or AI is degraded, the data is shown with a clear "verification pending" banner rather than hidden |
| Unauthorised | The item is not rendered, and a direct URL yields a clear "not available to your role" view |
| Security | Quarantined devices, blocked screenings and failed integrity checks use the highest-emphasis treatment with the reason always visible |

## 10. Visual language

System font stack; 8-px spacing scale; CSS custom properties for colour with a light and dark
palette driven by `prefers-color-scheme`; severity palette (`info` blue, `warning` amber,
`high` orange, `critical` red, `verified` green) each paired with an icon and text label.
