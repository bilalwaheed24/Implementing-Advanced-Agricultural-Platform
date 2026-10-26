-- 0002_aerial_imagery
-- Drone orthophotos from OpenDroneMap enter the same scene pipeline as satellite data.
-- Adds the imagery source, which vegetation index the ndvi_* columns hold (NDVI or the
-- RGB-only VARI), the SHA-256 of the actual image file, its footprint for QGIS, and the
-- ledger transaction that anchors the file hash.
--
-- Forward-only (ADR-014). Existing rows are satellite NDVI scenes.

ALTER TABLE satellite_scenes ADD COLUMN source VARCHAR(20) DEFAULT 'SATELLITE';

ALTER TABLE satellite_scenes ADD COLUMN index_name VARCHAR(10) DEFAULT 'NDVI';

ALTER TABLE satellite_scenes ADD COLUMN file_sha256 VARCHAR(64);

ALTER TABLE satellite_scenes ADD COLUMN footprint_geojson JSON;

ALTER TABLE satellite_scenes ADD COLUMN anchor_tx_id VARCHAR(64);
