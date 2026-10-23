-- 0006_shared_reports
-- Fraud assessments and compliance reports are about a batch, so every party to the batch
-- must be able to read them, not only the organisation whose id happened to be stored:
--   * fraud_assessments.custodian_org_id: the batch's holder when the check ran (the processor
--     that usually runs it), alongside org_id = the batch owner.
--   * compliance_reports.owner_org_id / custodian_org_id: the subject's parties, alongside
--     org_id = the organisation that ran and anchored the report (often the regulator).
-- repositories.scoped() reads these columns, so no endpoint needs to change.
--
-- Forward-only (ADR-014). Existing rows are back-filled from the batch / GMO event.

ALTER TABLE fraud_assessments ADD COLUMN custodian_org_id VARCHAR(36);

ALTER TABLE compliance_reports ADD COLUMN owner_org_id VARCHAR(36);

ALTER TABLE compliance_reports ADD COLUMN custodian_org_id VARCHAR(36);

UPDATE fraud_assessments SET custodian_org_id =
    (SELECT batches.custodian_org_id FROM batches WHERE batches.id = fraud_assessments.batch_id)
    WHERE custodian_org_id IS NULL;

UPDATE compliance_reports SET
    owner_org_id = (SELECT batches.org_id FROM batches
                    WHERE batches.id = compliance_reports.subject_id),
    custodian_org_id = (SELECT batches.custodian_org_id FROM batches
                        WHERE batches.id = compliance_reports.subject_id)
    WHERE subject_type = 'BATCH' AND owner_org_id IS NULL;

UPDATE compliance_reports SET
    owner_org_id = (SELECT gmo_events.org_id FROM gmo_events
                    WHERE gmo_events.id = compliance_reports.subject_id)
    WHERE subject_type = 'GMO_EVENT' AND owner_org_id IS NULL;

CREATE INDEX IF NOT EXISTS ix_fraud_assessments_custodian_org_id
    ON fraud_assessments (custodian_org_id);

CREATE INDEX IF NOT EXISTS ix_compliance_reports_owner_org_id
    ON compliance_reports (owner_org_id);

CREATE INDEX IF NOT EXISTS ix_compliance_reports_custodian_org_id
    ON compliance_reports (custodian_org_id)
