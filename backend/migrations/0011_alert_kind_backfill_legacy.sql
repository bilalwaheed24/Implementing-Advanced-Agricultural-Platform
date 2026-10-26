-- 0011_alert_kind_backfill_legacy
-- Kinds for the legacy alert titles 0010 did not recognise.
--
--  * DATA_THEFT   the first exfiltration title, "Possible agricultural data exfiltration by
--                 principal ..." (kind exfiltration)
--  * COMPLIANCE   the first labelling title, "Labelling non-compliance on batch X", carried
--                 no jurisdiction. It is read from the detail, "Release into J blocked: ...",
--                 with a CASE over the known jurisdictions (labelling:J)
--  * DEVICE_AUTH  quarantined, auth_failures
--  * DEVICE_HEALTH low_battery, silent, vulnerability:CVE (the CVE is matched against the
--                 device's own device_vulnerabilities rows)
--  * DEVICE_ANOMALY anomaly
--  * AGRONOMY     low_ndvi
--
-- The kind strings are the ones the raise sites use today (services/devices.py,
-- telemetry.py, security_ops.py, gmo.py). Old and current titles are both matched.
-- Then, as in 0010, an unresolved alert that a newer unresolved alert of the same category,
-- entity and kind duplicates is resolved. Alerts whose kind cannot be derived stay as they are.
--
-- Forward-only (ADR-014). Only SQL common to SQLite and PostgreSQL is used. LIKE is
-- case-sensitive on PostgreSQL, so text whose case varied is compared through upper().
-- (No semicolons in comments: run.py splits statements on them before removing comments.)

UPDATE alerts SET kind = 'exfiltration'
WHERE kind IS NULL AND category = 'DATA_THEFT' AND entity_type = 'User'
  AND title LIKE 'Possible agricultural data exfiltration%';

UPDATE alerts SET kind = CASE
    WHEN upper(detail) LIKE 'RELEASE INTO US-USDA %' THEN 'labelling:US-USDA'
    WHEN upper(detail) LIKE 'RELEASE INTO US-FDA %' THEN 'labelling:US-FDA'
    WHEN upper(detail) LIKE 'RELEASE INTO EU %' THEN 'labelling:EU'
    WHEN upper(detail) LIKE 'RELEASE INTO CODEX %' THEN 'labelling:CODEX'
    WHEN upper(detail) LIKE 'RELEASE INTO GS1 %' THEN 'labelling:GS1'
    ELSE NULL END
WHERE kind IS NULL AND category = 'COMPLIANCE' AND entity_type = 'Batch'
  AND EXISTS (SELECT 1 FROM batches b WHERE b.id = alerts.entity_id
                AND alerts.title = 'Labelling non-compliance on batch ' || b.batch_code);

UPDATE alerts SET kind = 'quarantined'
WHERE kind IS NULL AND category = 'DEVICE_AUTH' AND entity_type = 'Device'
  AND title LIKE '% quarantined';

UPDATE alerts SET kind = 'auth_failures'
WHERE kind IS NULL AND category = 'DEVICE_AUTH' AND entity_type = 'Device'
  AND title LIKE 'Repeated authentication failures from %';

UPDATE alerts SET kind = 'low_battery'
WHERE kind IS NULL AND category = 'DEVICE_HEALTH' AND entity_type = 'Device'
  AND title LIKE 'Low battery on %';

UPDATE alerts SET kind = 'silent'
WHERE kind IS NULL AND category = 'DEVICE_HEALTH' AND entity_type = 'Device'
  AND title LIKE '% has stopped reporting';

UPDATE alerts SET kind = (
    SELECT substr('vulnerability:' || v.cve_id, 1, 80) FROM device_vulnerabilities v
    WHERE v.device_id = alerts.entity_id AND alerts.title LIKE '%' || v.cve_id || '%'
    ORDER BY length(v.cve_id) DESC LIMIT 1)
WHERE kind IS NULL AND category = 'DEVICE_HEALTH' AND entity_type = 'Device'
  AND upper(title) LIKE '%VULNERABILITY %';

UPDATE alerts SET kind = 'anomaly'
WHERE kind IS NULL AND category = 'DEVICE_ANOMALY' AND entity_type = 'Device'
  AND title LIKE 'Anomalous telemetry from %';

UPDATE alerts SET kind = 'low_ndvi'
WHERE kind IS NULL AND category = 'AGRONOMY' AND entity_type = 'Field'
  AND title LIKE 'Low vegetation index on field %';

UPDATE alerts SET status = 'RESOLVED', resolved_at = CURRENT_TIMESTAMP
WHERE status IN ('OPEN', 'ACKNOWLEDGED') AND kind IS NOT NULL AND entity_id IS NOT NULL
  AND category IN ('DATA_THEFT', 'COMPLIANCE', 'DEVICE_AUTH', 'DEVICE_HEALTH',
                   'DEVICE_ANOMALY', 'AGRONOMY')
  AND EXISTS (SELECT 1 FROM alerts newer
              WHERE newer.category = alerts.category AND newer.entity_id = alerts.entity_id
                AND newer.kind = alerts.kind AND newer.id <> alerts.id
                AND newer.status IN ('OPEN', 'ACKNOWLEDGED')
                AND (newer.created_at > alerts.created_at
                     OR (newer.created_at = alerts.created_at AND newer.id > alerts.id)));
