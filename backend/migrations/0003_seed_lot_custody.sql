-- 0003_seed_lot_custody
-- A seed lot can be supplied by the biotech developer to a farm. The receiving farm becomes
-- the lot's custodian, which makes the lot visible to it (repositories.scoped), so the farm
-- can plant from it and the planting carries the lot's GMO lineage.
--
-- Forward-only (ADR-014). Existing lots are still held by the organisation that produced them.

ALTER TABLE seed_lots ADD COLUMN custodian_org_id VARCHAR(36);

UPDATE seed_lots SET custodian_org_id = org_id WHERE custodian_org_id IS NULL;

CREATE INDEX IF NOT EXISTS ix_seed_lots_custodian_org_id ON seed_lots (custodian_org_id);
