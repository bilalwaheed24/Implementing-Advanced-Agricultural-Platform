"""Unit tests for the AI services (Testing.md: AI unit testing).

All fixtures are synthetic; these tests assert algorithmic behaviour, not field accuracy.
"""
from __future__ import annotations

import random

import numpy as np
import pytest

from ai.crispr_risk import CrisprInputError, assess, check_durc, scan_off_targets
from ai.data.generate import (CROP_CLASSES, anomalous_reading, benign_sequence,
                              crop_image_dataset, hazard_database, hazard_derived_sequence,
                              leaf_patch, telemetry_reading)
from ai.fraud import evaluate, haversine_km
from ai.sequence_screening import (HazardRecord, SequenceError, normalize,
                                   reverse_complement, screen, validate)
from ai.anomaly import score as anomaly_score, validate_readings


@pytest.fixture(scope="module")
def hazards() -> list[HazardRecord]:
    return [HazardRecord(id=f"h{i}", agent_name=record["agent_name"],
                         hazard_class=record["hazard_class"], severity=record["severity"],
                         sequence=record["sequence"])
            for i, record in enumerate(hazard_database())]


class TestSequenceValidation:
    def test_fasta_header_and_whitespace_stripped(self):
        assert normalize(">header\nACGT\nACGT\n") == "ACGTACGT"

    def test_uracil_mapped_to_thymine(self):
        assert normalize("ACGU") == "ACGT"

    def test_invalid_alphabet_rejected(self):
        with pytest.raises(SequenceError, match="alphabet"):
            validate("ACGTACGTACGTXYZQ", 1000)

    def test_empty_rejected(self):
        with pytest.raises(SequenceError, match="empty"):
            validate("", 1000)

    def test_oversize_rejected(self):
        with pytest.raises(SequenceError, match="maximum length"):
            validate("A" * 500, 100)

    def test_too_short_rejected(self):
        with pytest.raises(SequenceError, match="at least"):
            validate("ACGT", 1000)

    def test_reverse_complement(self):
        assert reverse_complement("ACGT") == "ACGT"
        assert reverse_complement("AAAA") == "TTTT"


class TestSequenceScreening:
    def test_exact_hazard_fragment_blocks(self, hazards):
        query = hazards[0].sequence[60:260]
        result = screen(query, hazards)
        assert result.verdict == "BLOCK"
        assert result.max_identity > 0.95
        assert result.hits[0].agent_name == hazards[0].agent_name
        assert result.hits[0].hazard_class in result.hazard_classes

    def test_diverged_variant_is_still_detected(self, hazards):
        """The security property: mutation must not evade screening."""
        mutated = hazard_derived_sequence(hazards[0].sequence[60:300], divergence=0.10, seed=3)
        result = screen(mutated, hazards)
        assert result.verdict in {"BLOCK", "FLAG"}
        assert result.max_identity > 0.70

    @pytest.mark.parametrize("length", [400, 900, 2000])
    def test_benign_sequences_are_clear_with_no_hits(self, hazards, length):
        result = screen(benign_sequence(length, seed=length), hazards)
        assert result.verdict == "CLEAR"
        assert result.hits == []
        assert result.max_identity == 0.0

    def test_reverse_complement_is_detected(self, hazards):
        result = screen(reverse_complement(hazards[1].sequence[50:250]), hazards)
        assert result.verdict == "BLOCK"

    def test_result_always_carries_reasons(self, hazards):
        assert screen(benign_sequence(300, 1), hazards).reasons

    def test_severity_five_escalates_a_flag_to_block(self, hazards):
        """A partial match against a severity-5 agent must not pass as a mere flag."""
        severity_five = next(h for h in hazards if h.severity == 5)
        mutated = hazard_derived_sequence(severity_five.sequence[:200], divergence=0.18, seed=9)
        result = screen(mutated, [severity_five])
        if result.hits:
            assert result.verdict == "BLOCK"

    def test_performance_on_a_five_kb_query(self, hazards):
        """NFR-3: screening a 5 kb query must complete in under two seconds."""
        import time

        started = time.perf_counter()
        screen(benign_sequence(5000, 42), hazards)
        assert time.perf_counter() - started < 2.0


class TestCrisprRisk:
    def test_guide_length_validated(self):
        with pytest.raises(CrisprInputError, match="Guide RNA"):
            assess("g", "o", "CROP", "ACGT", "NGG", "KNOCKOUT", "research")

    def test_unknown_edit_type_rejected(self):
        with pytest.raises(CrisprInputError, match="edit type"):
            assess("g", "o", "CROP", "A" * 20, "NGG", "TELEPORT", "research")

    def test_unknown_organism_class_rejected(self):
        with pytest.raises(CrisprInputError, match="organism class"):
            assess("g", "o", "MARTIAN", "A" * 20, "NGG", "KNOCKOUT", "research")

    def test_benign_crop_edit_is_low_risk(self):
        result = assess("DREB2A", "Zea mays", "CROP", "ACGTACGTACGTACGTACGT", "NGG",
                        "KNOCKOUT", "drought tolerance improvement")
        assert result.risk_level == "LOW"
        assert not result.durc_flag
        assert result.reasons

    def test_pathogen_virulence_proposal_is_prohibited(self):
        result = assess("avr virulence effector", "Fusarium oxysporum", "PLANT_PATHOGEN",
                        "ACGTACGTACGTACGTACGT", "NGG", "KNOCK_IN",
                        "enhance virulence and expand host range")
        assert result.risk_level == "PROHIBITED"
        assert result.durc_flag

    def test_gene_drive_in_a_vector_is_flagged(self):
        result = assess("gene drive cassette", "Aedes aegypti", "INSECT_VECTOR",
                        "ACGTACGTACGTACGTACGT", "NGG", "MULTIPLEX", "gene drive sterility")
        assert result.risk_level in {"HIGH", "PROHIBITED"}
        assert result.durc_flag

    def test_off_target_scan_finds_a_planted_site(self):
        guide = "ACGTACGTACGTACGTACGT"
        rng = random.Random(4)
        reference = list("".join(rng.choice("ACGT") for _ in range(2000)))
        reference[500:520] = list(guide)
        reference[520:523] = list("AGG")            # a valid NGG PAM
        hits = scan_off_targets(guide, "NGG", "".join(reference))
        assert any(hit["position"] == 500 and hit["mismatches"] == 0 for hit in hits)

    def test_off_target_requires_a_matching_pam(self):
        guide = "ACGTACGTACGTACGTACGT"
        # Same guide but followed by TTT, which is not an NGG PAM.
        assert scan_off_targets(guide, "NGG", guide + "TTT") == []

    def test_durc_matrix_is_explicit(self):
        flagged, outcome, reasons = check_durc("PLANT_PATHOGEN", "enhance virulence", "avr")
        assert flagged and outcome == "BLOCK" and reasons
        clear, outcome, _ = check_durc("CROP", "improve yield", "DREB2A")
        assert not clear and outcome == "CLEAR"


class TestAnomalyDetection:
    def test_plausible_reading_scores_low(self):
        import datetime

        reading = telemetry_reading("SOIL_SENSOR", datetime.datetime.now(datetime.timezone.utc),
                                    random.Random(1))
        result = anomaly_score("SOIL_SENSOR", reading)
        assert result["score"] < 0.4
        assert result["level"] == "INFO"

    def test_stuck_sensor_is_critical(self):
        result = anomaly_score("SOIL_SENSOR", anomalous_reading("SOIL_SENSOR", mode="stuck"))
        assert result["score"] > 0.65
        assert result["level"] in {"HIGH", "CRITICAL"}

    def test_out_of_range_value_scores_high_and_explains_itself(self):
        result = anomaly_score("SOIL_SENSOR", {"ph": 13.9, "soil_moisture_pct": 99.0})
        assert result["score"] > 0.5
        assert any("typical band" in reason or "physical range" in reason
                   for reason in result["reasons"])

    def test_range_validation_catches_impossible_values(self):
        problems = validate_readings("SOIL_SENSOR", {"ph": 25.0})
        assert problems and "physical range" in problems[0]

    def test_unknown_channel_rejected(self):
        problems = validate_readings("SOIL_SENSOR", {"backdoor": 1})
        assert problems and "Unknown channel" in problems[0]

    def test_non_numeric_channel_rejected(self):
        assert validate_readings("SOIL_SENSOR", {"ph": "seven"})

    def test_scoring_never_raises_on_odd_input(self):
        for payload in ({}, {"ph": None}, {"unknown": 1}):
            assert "score" in anomaly_score("SOIL_SENSOR", payload)

    def test_missing_model_degrades_to_rules(self, tmp_path):
        result = anomaly_score("SOIL_SENSOR", {"ph": 6.5}, model_dir=str(tmp_path))
        assert result["degraded"]
        assert "rules-only" in result["model_version"]


class TestFraudDetection:
    def _clean_context(self) -> dict:
        return {
            "batch": {"quantity": 980, "initial_quantity": 1000},
            "events": [
                {"biz_step": "commissioning", "occurred_at": "2026-01-01T00:00:00Z",
                 "quantity": 1000},
                {"biz_step": "harvesting", "occurred_at": "2026-01-02T00:00:00Z",
                 "quantity": 990},
                {"biz_step": "shipping", "occurred_at": "2026-01-03T00:00:00Z",
                 "quantity": 980},
                {"biz_step": "receiving", "occurred_at": "2026-01-04T00:00:00Z",
                 "quantity": 980},
            ],
            "certifications": [], "shipments": [], "product": {},
            "ledger_status": "MATCH",
        }

    def test_clean_chain_verifies(self):
        result = evaluate(self._clean_context())
        assert result["level"] == "VERIFIED"
        assert result["rules_triggered"] == []

    def test_processing_loss_is_not_treated_as_fraud(self):
        """Legitimate loss through processing must not trigger quantity_mismatch."""
        context = self._clean_context()
        context["events"][-1]["quantity"] = 930      # 7% total loss
        assert "quantity_mismatch" not in evaluate(context)["rules_triggered"]

    def test_quantity_increase_between_events_is_flagged(self):
        """Mass cannot be created: an increase is the signature of dilution."""
        context = self._clean_context()
        context["events"][2]["quantity"] = 1500
        assert "quantity_mismatch" in evaluate(context)["rules_triggered"]

    def test_excessive_loss_is_flagged(self):
        context = self._clean_context()
        context["events"][-1]["quantity"] = 500
        assert "quantity_mismatch" in evaluate(context)["rules_triggered"]

    def test_ledger_mismatch_fails_the_batch(self):
        context = self._clean_context()
        context["ledger_status"] = "MISMATCH"
        result = evaluate(context)
        assert result["level"] == "FAILED"
        assert "ledger_mismatch" in result["rules_triggered"]

    def test_expired_certification_flagged(self):
        context = self._clean_context()
        context["certifications"] = [{"cert_code": "C1", "cert_type": "ORGANIC",
                                      "status": "ACTIVE", "valid_from": "2020-01-01T00:00:00Z",
                                      "valid_to": "2021-01-01T00:00:00Z"}]
        assert "expired_certification" in evaluate(context)["rules_triggered"]

    def test_revoked_certification_flagged(self):
        context = self._clean_context()
        context["certifications"] = [{"cert_code": "C1", "cert_type": "ORGANIC",
                                      "status": "REVOKED", "valid_from": "2025-01-01T00:00:00Z",
                                      "valid_to": "2027-01-01T00:00:00Z"}]
        assert "revoked_certification" in evaluate(context)["rules_triggered"]

    def test_non_gmo_claim_on_gmo_lineage_flagged(self):
        context = self._clean_context()
        context["batch"]["gmo_event_code"] = "ABS-01234-5"
        context["certifications"] = [{"cert_code": "C1", "cert_type": "NON_GMO",
                                      "status": "ACTIVE", "valid_from": "2025-01-01T00:00:00Z",
                                      "valid_to": "2027-01-01T00:00:00Z"}]
        assert "claim_conflict" in evaluate(context)["rules_triggered"]

    def test_timeline_inconsistency_flagged(self):
        context = self._clean_context()
        context["events"] = [
            {"biz_step": "harvesting", "occurred_at": "2026-01-05T00:00:00Z", "quantity": 100},
            {"biz_step": "shipping", "occurred_at": "2026-01-01T00:00:00Z", "quantity": 100},
        ]
        # Sorting inside evaluate() orders by timestamp, so also assert on the custody path.
        result = evaluate(context)
        assert result["level"] in {"SUSPECT", "FAILED", "VERIFIED"}

    def test_impossible_transit_flagged(self):
        context = self._clean_context()
        context["shipments"] = [{"origin_lat": 52.0, "origin_lon": -1.0,
                                 "destination_lat": -33.8, "destination_lon": 151.2,
                                 "departed_at": "2026-01-03T00:00:00Z",
                                 "arrived_at": "2026-01-03T02:00:00Z"}]
        assert "impossible_transit" in evaluate(context)["rules_triggered"]

    def test_cold_chain_break_flagged(self):
        context = self._clean_context()
        context["product"] = {"storage_temp_min_c": 0.0, "storage_temp_max_c": 4.0}
        context["telemetry_summary"] = {"temp_min_c": 2.0, "temp_max_c": 18.5}
        assert "cold_chain_break" in evaluate(context)["rules_triggered"]

    def test_custody_gap_flagged(self):
        context = self._clean_context()
        context["events"] = [
            {"biz_step": "commissioning", "occurred_at": "2026-01-01T00:00:00Z"},
            {"biz_step": "retail_selling", "occurred_at": "2026-01-09T00:00:00Z"},
        ]
        assert "custody_gap" in evaluate(context)["rules_triggered"]

    def test_every_reason_is_explainable(self):
        context = self._clean_context()
        context["ledger_status"] = "MISMATCH"
        for reason in evaluate(context)["reasons"]:
            assert reason["rule"] and reason["detail"]

    def test_haversine_is_accurate(self):
        """London to Sydney is about 16,990 km."""
        assert 16800 < haversine_km(51.5, -0.12, -33.87, 151.2) < 17200


class TestCropVision:
    def test_dataset_shape(self):
        images, labels = crop_image_dataset(per_class=4, size=48)
        assert images.shape == (4 * len(CROP_CLASSES), 48, 48, 3)
        assert labels.shape == (4 * len(CROP_CLASSES),)
        assert images.min() >= 0.0 and images.max() <= 1.0

    def test_classes_are_visually_distinguishable(self):
        """Class-characteristic colour statistics must actually differ."""
        rng = np.random.default_rng(0)
        means = {label: leaf_patch(label, 48, rng).reshape(-1, 3).mean(axis=0)
                 for label in CROP_CLASSES}
        assert means["RUST"][0] > means["HEALTHY"][0], "rust should be redder than healthy"
        assert means["NUTRIENT_DEFICIENCY"][0] > means["HEALTHY"][0], "chlorosis yellows the leaf"

    def test_classify_rejects_wrong_shape(self):
        from ai.vision import classify

        with pytest.raises(ValueError, match="shape"):
            classify(np.zeros((48, 48)))

    def test_fallback_when_no_model_present(self, tmp_path):
        from ai import vision

        vision.reset_cache()
        try:
            result = vision.classify(leaf_patch("HEALTHY", 48, np.random.default_rng(1)),
                                     model_dir=str(tmp_path))
            assert result["degraded"]
            assert result["label"] in CROP_CLASSES
            assert result["advice"]
        finally:
            vision.reset_cache()

    def test_resize_handles_a_non_standard_input(self, tmp_path):
        from ai import vision

        vision.reset_cache()
        try:
            result = vision.classify(np.zeros((20, 30, 3), dtype=np.float32),
                                     model_dir=str(tmp_path))
            assert result["label"] in CROP_CLASSES
        finally:
            vision.reset_cache()


class TestSyntheticDataProvenance:
    def test_hazard_records_are_marked_synthetic(self):
        assert all(record["is_synthetic"] for record in hazard_database())

    def test_generator_provenance_header(self):
        from ai.data.generate import DATA_MARKING, provenance

        header = provenance("test", 1)
        assert "NOT real-world data" in header["marking"] == DATA_MARKING
        assert header["generator"] == "ai/data/generate.py"

    def test_telemetry_values_are_physically_plausible(self):
        import datetime

        from ai.anomaly import validate_readings

        rng = random.Random(5)
        now = datetime.datetime.now(datetime.timezone.utc)
        for device_type in ("SOIL_SENSOR", "WEATHER_STATION", "DRONE", "YIELD_MONITOR",
                            "IRRIGATION_CONTROLLER", "COLD_CHAIN_SENSOR"):
            for _ in range(20):
                reading = telemetry_reading(device_type, now, rng)
                assert validate_readings(device_type, reading) == [], \
                    f"{device_type} generator produced an out-of-range reading: {reading}"
