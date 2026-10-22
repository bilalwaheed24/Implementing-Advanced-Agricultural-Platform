-- 0007_alert_incident_links
-- Alert de-duplication and alert <-> incident <-> entity linkage.
--
--  * alerts.kind distinguishes alerts of one category against one entity (a low-battery
--    DEVICE_HEALTH alert must not suppress a "stopped reporting" one). An unresolved alert
--    with the same (category, entity_id, kind) absorbs repeats, counted in occurrences and
--    timestamped by last_seen_at, instead of a new alert and incident per reading.
--  * incidents record the category and the entity they are about, the alert that opened
--    them, and an optional assignee, so status can be synchronised in both directions and a
--    later alert on the same entity (a quarantine, say) attaches to the incident already open.
--  * devices.offline_since flags an ACTIVE device the health sweep found silent.
--
-- Forward-only (ADR-014). Existing alerts count as one occurrence. Existing incidents are
-- back-filled from the earliest alert that references them, where there is one.
-- (No semicolons in comments: run.py splits statements on them before removing comments.)

ALTER TABLE alerts ADD COLUMN kind VARCHAR(80);

ALTER TABLE alerts ADD COLUMN occurrences INTEGER NOT NULL DEFAULT 1;

ALTER TABLE alerts ADD COLUMN last_seen_at TIMESTAMP WITH TIME ZONE;

ALTER TABLE incidents ADD COLUMN category VARCHAR(40);

ALTER TABLE incidents ADD COLUMN entity_type VARCHAR(40);

ALTER TABLE incidents ADD COLUMN entity_id VARCHAR(36);

ALTER TABLE incidents ADD COLUMN source_alert_id VARCHAR(36);

ALTER TABLE incidents ADD COLUMN assignee_id VARCHAR(36) REFERENCES users (id);

ALTER TABLE devices ADD COLUMN offline_since TIMESTAMP WITH TIME ZONE;

UPDATE incidents SET
    category = (SELECT a.category FROM alerts a WHERE a.incident_id = incidents.id
                ORDER BY a.created_at LIMIT 1),
    entity_type = (SELECT a.entity_type FROM alerts a WHERE a.incident_id = incidents.id
                   ORDER BY a.created_at LIMIT 1),
    entity_id = (SELECT a.entity_id FROM alerts a WHERE a.incident_id = incidents.id
                 ORDER BY a.created_at LIMIT 1),
    source_alert_id = (SELECT a.id FROM alerts a WHERE a.incident_id = incidents.id
                       ORDER BY a.created_at LIMIT 1)
WHERE source_alert_id IS NULL;

CREATE INDEX IF NOT EXISTS ix_alerts_kind ON alerts (kind);

CREATE INDEX IF NOT EXISTS ix_incidents_category ON incidents (category);

CREATE INDEX IF NOT EXISTS ix_incidents_entity_id ON incidents (entity_id);

CREATE INDEX IF NOT EXISTS ix_incidents_assignee_id ON incidents (assignee_id);
