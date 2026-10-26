"""Biotech lab equipment is a first-class device class: registration, validation, scoring."""
import random
from datetime import datetime, timezone

from ai import anomaly
from ai.data.generate import telemetry_reading


def test_a_normal_lab_reading_is_physically_valid():
    reading = telemetry_reading("LAB_INSTRUMENT", datetime.now(timezone.utc), random.Random(1))
    assert anomaly.validate_readings("LAB_INSTRUMENT", reading) == []


def test_an_impossible_cabinet_airflow_is_flagged():
    reading = telemetry_reading("LAB_INSTRUMENT", datetime.now(timezone.utc), random.Random(2))
    reading["cabinet_airflow_ms"] = 9.0
    assert anomaly.validate_readings("LAB_INSTRUMENT", reading)


def test_a_warming_freezer_scores_higher_than_a_healthy_one():
    rng = random.Random(3)
    healthy = telemetry_reading("LAB_INSTRUMENT", datetime.now(timezone.utc), rng)
    failing = telemetry_reading("LAB_INSTRUMENT", datetime.now(timezone.utc), rng, drift=1.0)
    healthy_score = anomaly.score("LAB_INSTRUMENT", healthy, None, 300.0, 10, model_dir="/nonexistent")
    failing_score = anomaly.score("LAB_INSTRUMENT", failing, None, 300.0, 10, model_dir="/nonexistent")
    assert failing_score["score"] > healthy_score["score"]


def test_a_lab_instrument_can_be_registered(client, auth, farm):
    response = client.post("/api/v1/devices", headers=auth("FARM_OPERATOR"),
                           json={"device_type": "LAB_INSTRUMENT", "model": "BioSafe LX-2",
                                 "firmware_version": "5.0.3", "farm_id": farm.id})
    assert response.status_code == 201, response.text
    assert response.json()["device"]["device_type"] == "LAB_INSTRUMENT"
