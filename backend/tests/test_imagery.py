"""Drone (OpenDroneMap) imagery ingestion with ledger-anchored file hashes, and the QGIS
GeoJSON export."""
import hashlib
from datetime import datetime, timezone

import pytest

from app.models import Field
from app.services.telemetry import scene_checksum
from app.services import ledger_client

FOOTPRINT = {"type": "Polygon", "coordinates": [[[-93.64, 42.02], [-93.62, 42.02],
                                                  [-93.62, 42.04], [-93.64, 42.04],
                                                  [-93.64, 42.02]]]}


@pytest.fixture
def field_id(db, farm):
    return db.query(Field).filter(Field.farm_id == farm.id).first().id


def _scene(field_id, scene_id, file_sha256=None, **extra):
    captured = datetime(2026, 10, 1, 9, 30, tzinfo=timezone.utc)
    body = {"scene_id": scene_id, "field_id": field_id, "provider": "OpenDroneMap",
            "captured_at": captured.isoformat(), "ndvi_mean": 0.21, "ndvi_min": -0.1,
            "ndvi_max": 0.45, "cloud_cover_pct": 0.0,
            "checksum": scene_checksum(scene_id, field_id, captured, 0.21, file_sha256)}
    if file_sha256:
        body.update({"source": "DRONE", "index_name": "VARI", "file_sha256": file_sha256})
    body.update(extra)
    return body


def test_a_drone_orthophoto_hash_is_anchored_on_the_ledger(client, auth, field_id):
    file_hash = hashlib.sha256(b"orthophoto bytes").hexdigest()
    response = client.post("/api/v1/telemetry/satellite/scenes", headers=auth("FARM_OPERATOR"),
                           json=_scene(field_id, "ODM-TEST-001", file_hash,
                                       footprint_geojson=FOOTPRINT))
    assert response.status_code == 201, response.text
    scene = response.json()
    assert scene["source"] == "DRONE" and scene["index_name"] == "VARI"
    assert scene["is_simulated"] is False
    assert scene["anchor_tx_id"]
    on_chain = ledger_client.get_ledger().query("scene:ODM-TEST-001")
    assert on_chain["file_sha256"] == file_hash


def test_a_file_hash_not_covered_by_the_checksum_is_refused(client, auth, field_id):
    body = _scene(field_id, "ODM-TEST-002")               # checksum computed without the file
    body.update({"source": "DRONE", "index_name": "VARI",
                 "file_sha256": hashlib.sha256(b"other").hexdigest()})
    response = client.post("/api/v1/telemetry/satellite/scenes", headers=auth("FARM_OPERATOR"),
                           json=body)
    assert response.status_code == 422


def test_a_footprint_outside_wgs84_is_refused(client, auth, field_id):
    bad = {"type": "Polygon", "coordinates": [[[500000, 4650000], [500100, 4650000],
                                                [500100, 4650100], [500000, 4650000]]]}
    response = client.post("/api/v1/telemetry/satellite/scenes", headers=auth("FARM_OPERATOR"),
                           json=_scene(field_id, "ODM-TEST-003",
                                       hashlib.sha256(b"x").hexdigest(), footprint_geojson=bad))
    assert response.status_code == 422


def test_geojson_export_lists_fields_and_drone_footprints(client, auth, field_id):
    response = client.get("/api/v1/telemetry/satellite/geojson", headers=auth("FARM_OPERATOR"))
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/geo+json")
    collection = response.json()
    assert collection["type"] == "FeatureCollection"
    layers = {f["properties"]["layer"] for f in collection["features"]}
    assert "field" in layers
    assert any(f["properties"].get("scene_id") == "ODM-TEST-001" for f in collection["features"])


def test_geojson_export_is_tenant_scoped(client, rival_auth, field_id):
    response = client.get("/api/v1/telemetry/satellite/geojson", headers=rival_auth)
    if response.status_code == 403:                       # the rival role may lack telemetry:read
        return
    ids = {f["properties"].get("field_id") for f in response.json()["features"]}
    assert field_id not in ids


def test_drone_vari_does_not_distort_the_ndvi_stress_ranking(client, auth, field_id):
    ranking = client.get("/api/v1/telemetry/insights/field-stress",
                         headers=auth("FARM_OPERATOR")).json()["ranking"]
    assert all(row["ndvi_mean"] != 0.21 for row in ranking if row["field_id"] == field_id)


def _load_ingest_script():
    import importlib.util
    from pathlib import Path
    pytest.importorskip("numpy")
    path = Path(__file__).resolve().parents[2] / "scripts" / "odm_ingest.py"
    spec = importlib.util.spec_from_file_location("odm_ingest_under_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_ingest_script_checksum_matches_the_service():
    """The script restates scene_checksum so it runs without the backend's dependencies; the
    API refuses a scene whose checksum differs, so the two must never drift apart."""
    script = _load_ingest_script()
    captured = datetime(2026, 10, 26, 15, 51, 57, tzinfo=timezone.utc)
    digest = hashlib.sha256(b"ortho").hexdigest()
    for file_hash in (None, digest):
        assert script.scene_checksum("ODM-X", "field-1", captured, -0.0246, file_hash) == \
            scene_checksum("ODM-X", "field-1", captured, -0.0246, file_hash)


def test_ingest_script_does_not_import_the_backend():
    """Found on a real run: importing app.services.telemetry made the script need sqlalchemy
    on an operator's laptop that only has requirements/geo.txt."""
    import ast
    from pathlib import Path
    source = (Path(__file__).resolve().parents[2] / "scripts" / "odm_ingest.py").read_text()
    imported = {n.module.split(".")[0] for n in ast.walk(ast.parse(source))
                if isinstance(n, ast.ImportFrom) and n.module}
    imported |= {a.name.split(".")[0] for n in ast.walk(ast.parse(source))
                 if isinstance(n, ast.Import) for a in n.names}
    assert "app" not in imported and "sqlalchemy" not in imported
