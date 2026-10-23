-- 0005_shipment_receiver
-- A shipment that hands a batch over to another organisation records the receiver, so the
-- receiving organisation sees the shipment and its cold-chain evidence (repositories.scoped
-- treats org_id and to_org_id as the two parties) and can mark it arrived.
--
-- Forward-only (ADR-014). Existing shipments stay NULL: an internal move with one party.

ALTER TABLE shipments ADD COLUMN to_org_id VARCHAR(36);

CREATE INDEX IF NOT EXISTS ix_shipments_to_org_id ON shipments (to_org_id);
