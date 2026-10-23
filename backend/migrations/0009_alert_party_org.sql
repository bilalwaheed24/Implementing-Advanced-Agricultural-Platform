-- 0009_alert_party_org
-- A second party organisation on an alert.
--
--  * alerts.custodian_org_id names the organisation holding a batch whose alert is filed
--    under the batch owner (a recall, a failed integrity check, a compliance or labelling
--    failure). repositories.scoped() treats it as a party column, so the custodian sees the
--    alert and can acknowledge or resolve it, and it is counted on that organisation's board.
--  * incidents.custodian_org_id is copied from the alert that opened the incident, so the
--    custodian can follow the incident its alert links to.
--
-- Forward-only (ADR-014). Existing batch alerts are back-filled with the batch's current
-- custodian where that differs from the owner.
-- (No semicolons in comments: run.py splits statements on them before removing comments.)

ALTER TABLE alerts ADD COLUMN custodian_org_id VARCHAR(36) REFERENCES organizations (id);

UPDATE alerts SET custodian_org_id = (
    SELECT b.custodian_org_id FROM batches b
    WHERE b.id = alerts.entity_id AND b.custodian_org_id <> b.org_id)
WHERE entity_type = 'Batch' AND custodian_org_id IS NULL;

CREATE INDEX IF NOT EXISTS ix_alerts_custodian_org_id ON alerts (custodian_org_id);

ALTER TABLE incidents ADD COLUMN custodian_org_id VARCHAR(36) REFERENCES organizations (id);

UPDATE incidents SET custodian_org_id = (
    SELECT a.custodian_org_id FROM alerts a WHERE a.id = incidents.source_alert_id)
WHERE custodian_org_id IS NULL AND source_alert_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS ix_incidents_custodian_org_id ON incidents (custodian_org_id);
