-- 0008_shipment_receiver_backfill
-- 0005 added shipments.to_org_id but left existing rows NULL, so the receiver of a shipment
-- made before it could neither see the shipment nor mark it arrived. The receiver is
-- recoverable from the batch's custody trail: a hand-over is a shipping event, recorded by the
-- sender, whose to_org_id names the receiving organisation.
--
-- Only where it is determinable, in two passes:
--   1. the sender's hand-over shipping event on the same batch at the shipment's departure
--      time (create_shipment records the shipping event at departed_at)
--   2. otherwise, when the sender made exactly one shipment of the batch and handed it to
--      exactly one other organisation, that organisation.
-- Anything else stays NULL (an internal move, or ambiguous history).
--
-- Forward-only (ADR-014). Plain UPDATEs: re-running finds nothing left to fill.

UPDATE shipments
SET to_org_id = (
    SELECT MIN(e.to_org_id) FROM supply_chain_events e
    WHERE e.batch_id = shipments.batch_id
      AND e.org_id = shipments.org_id
      AND e.biz_step = 'shipping'
      AND e.to_org_id IS NOT NULL
      AND e.to_org_id <> shipments.org_id
      AND e.occurred_at = shipments.departed_at)
WHERE to_org_id IS NULL
  AND EXISTS (
    SELECT 1 FROM supply_chain_events e
    WHERE e.batch_id = shipments.batch_id
      AND e.org_id = shipments.org_id
      AND e.biz_step = 'shipping'
      AND e.to_org_id IS NOT NULL
      AND e.to_org_id <> shipments.org_id
      AND e.occurred_at = shipments.departed_at);

UPDATE shipments
SET to_org_id = (
    SELECT MIN(e.to_org_id) FROM supply_chain_events e
    WHERE e.batch_id = shipments.batch_id
      AND e.org_id = shipments.org_id
      AND e.biz_step = 'shipping'
      AND e.to_org_id IS NOT NULL
      AND e.to_org_id <> shipments.org_id)
WHERE to_org_id IS NULL
  AND (SELECT COUNT(DISTINCT e.to_org_id) FROM supply_chain_events e
       WHERE e.batch_id = shipments.batch_id
         AND e.org_id = shipments.org_id
         AND e.biz_step = 'shipping'
         AND e.to_org_id IS NOT NULL
         AND e.to_org_id <> shipments.org_id) = 1
  AND (SELECT COUNT(*) FROM shipments s2
       WHERE s2.batch_id = shipments.batch_id
         AND s2.org_id = shipments.org_id) = 1;
