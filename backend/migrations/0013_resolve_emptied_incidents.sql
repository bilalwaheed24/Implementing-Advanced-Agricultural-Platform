-- 0013_resolve_emptied_incidents
-- Migration 0011 resolved an unresolved alert that a newer one duplicated, but left the
-- incident that alert had opened as it was. Where the duplicate was the incident's only alert,
-- the incident stayed OPEN with nothing on it to respond to.
--
-- An OPEN incident is resolved here when it has at least one linked alert (attached through
-- alerts.incident_id or as its source alert) and every linked alert is RESOLVED. A system
-- timeline entry (no actor) says why, written first so it names exactly the incidents the
-- UPDATE then resolves. Its id is derived from the incident id, so it is unique without a
-- UUID function common to SQLite and PostgreSQL.
--
-- Left alone
--  * data-theft and ledger incidents. An automatic resolution never closes those, security
--    operations do (services/notifications.resolve)
--  * an incident deliberately kept open after its last alert was resolved by someone who may
--    not close incidents. Its timeline carries the NOTE "Every linked alert is resolved. The
--    incident stays open ..." and it waits for an analyst.
--
-- Forward-only (ADR-014). Only SQL common to SQLite and PostgreSQL is used.
-- (No semicolons in comments: run.py splits statements on them before removing comments.)

INSERT INTO incident_events (id, incident_id, action, detail, actor_id, created_at)
SELECT 'm0013-' || substr(i.id, 1, 30), i.id, 'RESOLVED',
       'Resolved: every linked alert is resolved (a duplicate alert was closed by a data '
       || 'clean-up and nothing was left on this incident).',
       NULL, CURRENT_TIMESTAMP
FROM incidents i
WHERE i.status = 'OPEN'
  AND (i.category IS NULL OR i.category NOT IN ('DATA_THEFT', 'LEDGER'))
  AND EXISTS (SELECT 1 FROM alerts a
              WHERE a.incident_id = i.id OR a.id = i.source_alert_id)
  AND NOT EXISTS (SELECT 1 FROM alerts a
                  WHERE (a.incident_id = i.id OR a.id = i.source_alert_id)
                    AND (a.status <> 'RESOLVED' OR a.category IN ('DATA_THEFT', 'LEDGER')))
  AND NOT EXISTS (SELECT 1 FROM incident_events kept
                  WHERE kept.incident_id = i.id AND kept.action = 'NOTE'
                    AND kept.detail LIKE 'Every linked alert is resolved%')
  AND NOT EXISTS (SELECT 1 FROM incident_events e WHERE e.id = 'm0013-' || substr(i.id, 1, 30));

UPDATE incidents SET status = 'RESOLVED', closed_at = CURRENT_TIMESTAMP
WHERE status = 'OPEN'
  AND (category IS NULL OR category NOT IN ('DATA_THEFT', 'LEDGER'))
  AND EXISTS (SELECT 1 FROM alerts a
              WHERE a.incident_id = incidents.id OR a.id = incidents.source_alert_id)
  AND NOT EXISTS (SELECT 1 FROM alerts a
                  WHERE (a.incident_id = incidents.id OR a.id = incidents.source_alert_id)
                    AND (a.status <> 'RESOLVED' OR a.category IN ('DATA_THEFT', 'LEDGER')))
  AND NOT EXISTS (SELECT 1 FROM incident_events kept
                  WHERE kept.incident_id = incidents.id AND kept.action = 'NOTE'
                    AND kept.detail LIKE 'Every linked alert is resolved%');
