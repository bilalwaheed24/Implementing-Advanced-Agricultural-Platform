-- 0010_alert_kind_backfill
-- Give kind-less legacy alerts the kind the code now raises them with.
--
-- 0007 added alerts.kind but back-filled nothing. Dedupe (find_open_alert) and automatic
-- resolution (resolve_alerts) match on kind, so an alert raised before 0007 was never folded
-- into, never resolved by a passing re-check, and a new kind-ed alert was raised beside it.
--
--  * DATA_THEFT  account lockout, refresh-token reuse and exfiltration, told apart by title
--  * FRAUD       the integrity check is the only FRAUD source, kind fraud
--  * COMPLIANCE  recall, parent_recalled, cold_chain_excursion by title.
--                compliance:J and labelling:J take the jurisdiction J from a compliance
--                report on the same batch whose jurisdiction ends the title, or from the
--                title after the batch code.
--
-- Once kinds are known, an unresolved alert that a newer unresolved alert of the same
-- category, entity and kind duplicates is resolved, leaving the newer one to carry the case.
-- Alerts whose kind cannot be derived are left as they are.
--
-- Forward-only (ADR-014). Only string functions common to SQLite and PostgreSQL are used.
-- (No semicolons in comments: run.py splits statements on them before removing comments.)

UPDATE alerts SET kind = 'account_lockout'
WHERE kind IS NULL AND category = 'DATA_THEFT' AND title LIKE 'Account locked after %';

UPDATE alerts SET kind = 'refresh_token_reuse'
WHERE kind IS NULL AND category = 'DATA_THEFT' AND title LIKE 'Refresh token reuse%';

UPDATE alerts SET kind = 'exfiltration'
WHERE kind IS NULL AND category = 'DATA_THEFT' AND title LIKE 'Possible data exfiltration%';

UPDATE alerts SET kind = 'fraud'
WHERE kind IS NULL AND category = 'FRAUD' AND entity_type = 'Batch';

UPDATE alerts SET kind = 'recall'
WHERE kind IS NULL AND category = 'COMPLIANCE' AND entity_type = 'Batch'
  AND title LIKE 'Batch % has been recalled';

UPDATE alerts SET kind = 'parent_recalled'
WHERE kind IS NULL AND category = 'COMPLIANCE' AND entity_type = 'Batch'
  AND title LIKE 'Batch % derives from recalled batch %';

UPDATE alerts SET kind = 'cold_chain_excursion'
WHERE kind IS NULL AND category = 'COMPLIANCE' AND entity_type = 'Shipment'
  AND title LIKE 'Cold-chain excursion on shipment %';

UPDATE alerts SET kind = (
    SELECT 'labelling:' || substr(alerts.title,
                                  length('Labelling non-compliance on batch ')
                                  + length(b.batch_code) + length(' in ') + 1)
    FROM batches b WHERE b.id = alerts.entity_id
      AND alerts.title LIKE 'Labelling non-compliance on batch ' || b.batch_code || ' in %')
WHERE kind IS NULL AND category = 'COMPLIANCE' AND entity_type = 'Batch'
  AND title LIKE 'Labelling non-compliance on batch % in %';

UPDATE alerts SET kind = (
    SELECT 'compliance:' || r.jurisdiction FROM compliance_reports r
    WHERE r.subject_type = 'BATCH' AND r.subject_id = alerts.entity_id
      AND alerts.title LIKE '% in ' || r.jurisdiction
    ORDER BY length(r.jurisdiction) DESC LIMIT 1)
WHERE kind IS NULL AND category = 'COMPLIANCE' AND entity_type = 'Batch'
  AND title LIKE 'Batch % is % in %' AND title NOT LIKE 'Batch % derives from %';

UPDATE alerts SET status = 'RESOLVED', resolved_at = CURRENT_TIMESTAMP
WHERE status IN ('OPEN', 'ACKNOWLEDGED') AND kind IS NOT NULL AND entity_id IS NOT NULL
  AND category IN ('DATA_THEFT', 'FRAUD', 'COMPLIANCE')
  AND EXISTS (SELECT 1 FROM alerts newer
              WHERE newer.category = alerts.category AND newer.entity_id = alerts.entity_id
                AND newer.kind = alerts.kind AND newer.id <> alerts.id
                AND newer.status IN ('OPEN', 'ACKNOWLEDGED')
                AND (newer.created_at > alerts.created_at
                     OR (newer.created_at = alerts.created_at AND newer.id > alerts.id)));
