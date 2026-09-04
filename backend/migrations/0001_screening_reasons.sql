-- 0001_screening_reasons
-- Persist the screening engine's rationale alongside the verdict.
--
-- Before this migration the reasons were attached to the ORM object in memory
-- (SequenceScreening._reasons) and were therefore returned only by the POST that
-- created the screening.  Any later GET returned an empty list, and the detail
-- view rendered "No stored rationale for this screening." even for BLOCK verdicts.
--
-- Forward-only (ADR-014).  Existing rows are backfilled with an empty JSON array
-- so that reads never see NULL.

ALTER TABLE sequence_screenings ADD COLUMN reasons JSON DEFAULT '[]';

UPDATE sequence_screenings SET reasons = '[]' WHERE reasons IS NULL;
