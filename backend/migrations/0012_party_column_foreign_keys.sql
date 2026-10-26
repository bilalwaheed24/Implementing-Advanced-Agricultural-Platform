-- 0012_party_column_foreign_keys
-- Migrations 0003, 0005 and 0006 added organisation columns without REFERENCES
-- organizations (id), while a fresh database built by create_all() has those foreign keys.
-- This adds them to an upgraded PostgreSQL database, so both kinds of database refuse a
-- custody or party id that names no organisation:
--   * seed_lots.custodian_org_id            (0003)
--   * shipments.to_org_id                   (0005)
--   * fraud_assessments.custodian_org_id    (0006)
--   * compliance_reports.owner_org_id       (0006)
--   * compliance_reports.custodian_org_id   (0006)
--
-- Each constraint takes the name PostgreSQL gives the unnamed foreign key create_all() emits
-- (table_column_fkey). On a database built by create_all() it therefore already exists, and
-- run.py skips the statement ("already exists"), so no duplicate constraint is created.
--
-- NOT VALID: rows written before this migration are not re-checked (an old orphan id must not
-- stop the upgrade), while every new or changed row is. VALIDATE CONSTRAINT can be run later.
--
-- SQLite cannot add a constraint to an existing table (ALTER TABLE ... ADD CONSTRAINT is not
-- supported, and the only route is rebuilding each table). Each statement is therefore
-- marked for PostgreSQL only with the run.py dialect directive and skipped on SQLite, which
-- is used for local runs and tests and is built by create_all() with the keys in place.
-- (No semicolons in comments: run.py splits statements on them before removing comments.)

-- dialect: postgresql
ALTER TABLE seed_lots ADD CONSTRAINT seed_lots_custodian_org_id_fkey
    FOREIGN KEY (custodian_org_id) REFERENCES organizations (id) NOT VALID;

-- dialect: postgresql
ALTER TABLE shipments ADD CONSTRAINT shipments_to_org_id_fkey
    FOREIGN KEY (to_org_id) REFERENCES organizations (id) NOT VALID;

-- dialect: postgresql
ALTER TABLE fraud_assessments ADD CONSTRAINT fraud_assessments_custodian_org_id_fkey
    FOREIGN KEY (custodian_org_id) REFERENCES organizations (id) NOT VALID;

-- dialect: postgresql
ALTER TABLE compliance_reports ADD CONSTRAINT compliance_reports_owner_org_id_fkey
    FOREIGN KEY (owner_org_id) REFERENCES organizations (id) NOT VALID;

-- dialect: postgresql
ALTER TABLE compliance_reports ADD CONSTRAINT compliance_reports_custodian_org_id_fkey
    FOREIGN KEY (custodian_org_id) REFERENCES organizations (id) NOT VALID
