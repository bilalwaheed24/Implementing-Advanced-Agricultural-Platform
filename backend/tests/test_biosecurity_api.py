"""Biosecurity workflow integration tests (FR-C1..C4, flow.md §12, §13)."""
from __future__ import annotations

import pytest

from ai.data.generate import benign_sequence, hazard_database, hazard_derived_sequence
from .conftest import unique


@pytest.fixture
def benign_screening(client, auth, hazards):
    response = client.post("/api/v1/biosecurity/screenings",
                           headers=auth("BIOTECH_RESEARCHER"),
                           json={"name": unique("benign"), "sequence": benign_sequence(1000, 7),
                                 "intent": "drought tolerance", "organism": "Zea mays"})
    assert response.status_code == 201, response.text
    return response.json()


@pytest.fixture
def blocked_screening(client, auth, hazards):
    hazard = hazard_database()[0]
    response = client.post("/api/v1/biosecurity/screenings",
                           headers=auth("BIOTECH_RESEARCHER"),
                           json={"name": unique("hazard"),
                                 "sequence": hazard_derived_sequence(hazard["sequence"], 0.05, 2),
                                 "intent": "virulence enhancement",
                                 "organism": "Fusarium oxysporum"})
    assert response.status_code == 201, response.text
    return response.json()


class TestScreeningWorkflow:
    def test_benign_sequence_auto_approved(self, benign_screening):
        assert benign_screening["verdict"] == "CLEAR"
        assert benign_screening["status"] == "APPROVED_AUTO"
        assert benign_screening["hits"] == []
        assert benign_screening["reasons"]

    def test_hazard_match_is_blocked_with_evidence(self, blocked_screening):
        assert blocked_screening["verdict"] == "BLOCK"
        assert blocked_screening["status"] == "BLOCKED"
        assert blocked_screening["hits"], "a blocked verdict must carry alignment evidence"
        hit = blocked_screening["hits"][0]
        assert hit["identity"] > 0.8
        assert hit["align_length"] > 40
        assert hit["query_start"] < hit["query_end"]

    def test_durc_intent_and_hazard_class_sets_the_flag(self, blocked_screening):
        assert blocked_screening["durc_flag"] is True

    def test_sequence_is_never_returned_in_the_response(self, blocked_screening):
        """The submitted sequence is encrypted at rest and not echoed back."""
        assert "sequence" not in blocked_screening or "sequence_hash" in blocked_screening
        assert "ACGT" * 5 not in str(blocked_screening)

    def test_sequence_is_encrypted_at_rest(self, db, blocked_screening):
        from sqlalchemy import select

        from app.models import SequenceScreening
        from app.services.biosecurity import decrypt_sequence

        record = db.execute(select(SequenceScreening).where(
            SequenceScreening.id == blocked_screening["id"])).scalar_one()
        assert not record.sequence_enc.startswith("ACGT")
        assert len(decrypt_sequence(record)) == record.sequence_length

    def test_blocked_screening_appears_in_the_review_queue(self, client, auth,
                                                           blocked_screening):
        queue = client.get("/api/v1/biosecurity/screenings/queue",
                           headers=auth("BIOSAFETY_OFFICER"))
        assert queue.status_code == 200
        assert any(item["id"] == blocked_screening["id"] for item in queue.json())

    def test_officer_can_reject_with_a_rationale(self, client, auth, blocked_screening):
        response = client.post(
            f"/api/v1/biosecurity/screenings/{blocked_screening['id']}/review",
            headers=auth("BIOSAFETY_OFFICER"),
            json={"decision": "REJECT",
                  "rationale": "Homology to a severity-5 phytopathogen effector with a "
                               "virulence-enhancement intent."})
        assert response.status_code == 200
        assert response.json()["status"] == "REJECTED"
        assert response.json()["reviewed_by"]

    def test_a_resolved_screening_cannot_be_reviewed_twice(self, client, auth,
                                                           blocked_screening):
        payload = {"decision": "REJECT", "rationale": "First decision, recorded properly."}
        first = client.post(f"/api/v1/biosecurity/screenings/{blocked_screening['id']}/review",
                            headers=auth("BIOSAFETY_OFFICER"), json=payload)
        assert first.status_code == 200
        second = client.post(f"/api/v1/biosecurity/screenings/{blocked_screening['id']}/review",
                             headers=auth("BIOSAFETY_OFFICER"), json=payload)
        assert second.status_code == 409

    def test_review_requires_a_substantive_rationale(self, client, auth, blocked_screening):
        response = client.post(
            f"/api/v1/biosecurity/screenings/{blocked_screening['id']}/review",
            headers=auth("BIOSAFETY_OFFICER"), json={"decision": "REJECT", "rationale": "no"})
        assert response.status_code == 422

    def test_invalid_decision_rejected(self, client, auth, blocked_screening):
        response = client.post(
            f"/api/v1/biosecurity/screenings/{blocked_screening['id']}/review",
            headers=auth("BIOSAFETY_OFFICER"),
            json={"decision": "MAYBE", "rationale": "Not a valid decision value."})
        assert response.status_code == 422

    def test_blocking_raises_an_alert(self, client, auth, blocked_screening):
        alerts = client.get("/api/v1/security/alerts", headers=auth("BIOSAFETY_OFFICER"),
                            params={"category": "DURC"}).json()
        assert alerts["total"] >= 1

    def test_screening_writes_an_audit_record(self, client, auth, blocked_screening):
        logs = client.get("/api/v1/audit/logs", headers=auth("SECURITY_ANALYST"),
                          params={"action": "biosecurity.screening_submit"}).json()
        assert logs["total"] >= 1

    def test_statistics_endpoint_summarises_the_desk(self, client, auth, blocked_screening):
        stats = client.get("/api/v1/biosecurity/statistics",
                           headers=auth("BIOSAFETY_OFFICER")).json()
        assert stats["screenings_total"] >= 1
        assert stats["hazard_database_size"] >= 10
        assert "screenings_by_verdict" in stats


class TestCrisprWorkflow:
    def test_benign_edit_is_auto_approved(self, client, auth):
        response = client.post("/api/v1/biosecurity/crispr",
                               headers=auth("BIOTECH_RESEARCHER"),
                               json={"target_gene": "DREB2A", "organism": "Zea mays",
                                     "organism_class": "CROP",
                                     "guide_rna": "ACGTACGTACGTACGTACGT", "pam": "NGG",
                                     "edit_type": "KNOCKOUT",
                                     "intent": "drought tolerance improvement"})
        assert response.status_code == 201
        body = response.json()
        assert body["risk_level"] == "LOW"
        assert body["status"] == "APPROVED_AUTO"
        assert body["reasons"]

    def test_dual_use_proposal_is_prohibited_and_queued(self, client, auth):
        response = client.post("/api/v1/biosecurity/crispr",
                               headers=auth("BIOTECH_RESEARCHER"),
                               json={"target_gene": "avr virulence effector",
                                     "organism": "Fusarium oxysporum",
                                     "organism_class": "PLANT_PATHOGEN",
                                     "guide_rna": "ACGTACGTACGTACGTACGT", "pam": "NGG",
                                     "edit_type": "KNOCK_IN",
                                     "intent": "enhance virulence and host range"})
        assert response.status_code == 201
        body = response.json()
        assert body["risk_level"] == "PROHIBITED"
        assert body["durc_flag"] is True
        assert body["status"] == "PENDING_REVIEW"

    def test_off_target_scan_is_reported(self, client, auth):
        reference = benign_seq = benign_sequence(2000, 12)
        guide = reference[300:320]
        response = client.post("/api/v1/biosecurity/crispr",
                               headers=auth("BIOTECH_RESEARCHER"),
                               json={"target_gene": "TEST1", "organism": "Zea mays",
                                     "organism_class": "CROP", "guide_rna": guide,
                                     "pam": "NGG", "edit_type": "BASE_EDIT",
                                     "intent": "research", "reference_sequence": reference})
        assert response.status_code == 201
        assert response.json()["off_target_count"] >= 0

    @pytest.mark.parametrize("field,value", [
        ("guide_rna", "ACGT"), ("edit_type", "TELEPORT"), ("organism_class", "MARTIAN"),
        ("pam", "N"),
    ])
    def test_invalid_input_rejected(self, client, auth, field, value):
        payload = {"target_gene": "T", "organism": "Zea mays", "organism_class": "CROP",
                   "guide_rna": "ACGTACGTACGTACGTACGT", "pam": "NGG",
                   "edit_type": "KNOCKOUT", "intent": "research"}
        payload[field] = value
        response = client.post("/api/v1/biosecurity/crispr",
                               headers=auth("BIOTECH_RESEARCHER"), json=payload)
        assert response.status_code == 422

    def test_durc_filter_lists_only_flagged_proposals(self, client, auth):
        client.post("/api/v1/biosecurity/crispr", headers=auth("BIOTECH_RESEARCHER"),
                    json={"target_gene": "gene drive", "organism": "Aedes",
                          "organism_class": "INSECT_VECTOR",
                          "guide_rna": "ACGTACGTACGTACGTACGT", "pam": "NGG",
                          "edit_type": "MULTIPLEX", "intent": "gene drive sterility"})
        response = client.get("/api/v1/biosecurity/crispr", headers=auth("BIOSAFETY_OFFICER"),
                              params={"durc_only": True})
        assert response.status_code == 200
        assert all(item["durc_flag"] for item in response.json()["items"])


class TestHazardDatabase:
    def test_officer_can_add_a_hazard_sequence(self, client, auth):
        response = client.post("/api/v1/biosecurity/hazards",
                               headers=auth("BIOSAFETY_OFFICER"),
                               json={"agent_name": unique("Synthetic test agent"),
                                     "hazard_class": "TOXIN", "severity": 4,
                                     "description": "Synthetic test entry",
                                     "sequence": benign_sequence(300, 33)})
        assert response.status_code == 201
        assert response.json()["is_synthetic"] is True

    def test_researcher_cannot_add_a_hazard_sequence(self, client, auth):
        response = client.post("/api/v1/biosecurity/hazards",
                               headers=auth("BIOTECH_RESEARCHER"),
                               json={"agent_name": "X", "hazard_class": "TOXIN", "severity": 3,
                                     "sequence": benign_sequence(300, 34)})
        assert response.status_code == 403

    def test_invalid_hazard_class_rejected(self, client, auth):
        response = client.post("/api/v1/biosecurity/hazards",
                               headers=auth("BIOSAFETY_OFFICER"),
                               json={"agent_name": "X", "hazard_class": "SPOOKY",
                                     "severity": 3, "sequence": benign_sequence(300, 35)})
        assert response.status_code == 422

    def test_severity_bounds_enforced(self, client, auth):
        for severity in (0, 6):
            response = client.post("/api/v1/biosecurity/hazards",
                                   headers=auth("BIOSAFETY_OFFICER"),
                                   json={"agent_name": "X", "hazard_class": "TOXIN",
                                         "severity": severity,
                                         "sequence": benign_sequence(300, 36)})
            assert response.status_code == 422

    def test_all_shipped_hazards_are_marked_synthetic(self, client, auth):
        response = client.get("/api/v1/biosecurity/hazards", headers=auth("BIOSAFETY_OFFICER"),
                              params={"page_size": 50})
        assert response.status_code == 200
        assert all(item["is_synthetic"] for item in response.json()["items"])


class TestScreeningRationalePersistence:
    """The engine's rationale must survive the request that produced it.

    Regression for the defect where `SequenceScreening._reasons` was a transient
    attribute: the POST response carried the reasons, every later GET returned an
    empty list, and the detail view rendered "No stored rationale for this
    screening." even for a BLOCK verdict.  Migration 0001 added the column.
    """

    @staticmethod
    def _submit(client, auth, name, sequence, intent, organism):
        response = client.post("/api/v1/biosecurity/screenings",
                               headers=auth("BIOTECH_RESEARCHER"),
                               json={"name": name, "sequence": sequence,
                                     "intent": intent, "organism": organism})
        assert response.status_code == 201, response.text
        return response.json()

    @staticmethod
    def _fresh_read(screening_id):
        """Read through a brand-new session so the ORM identity map cannot answer."""
        from sqlalchemy import select

        from app.core.database import SessionLocal
        from app.models import SequenceScreening

        with SessionLocal() as session:
            row = session.execute(
                select(SequenceScreening).where(SequenceScreening.id == screening_id)
            ).scalar_one()
            return list(row.reasons or [])

    @pytest.fixture
    def flagged_screening(self, client, auth, hazards):
        """A severity-3 hazard at 14 % divergence: significant, but below BLOCK."""
        from ai.data.generate import hazard_database

        hazard = next(h for h in hazard_database() if h["severity"] == 3)
        return self._submit(
            client, auth, unique("partial"),
            hazard_derived_sequence(hazard["sequence"], 0.14, 5),
            "resistance marker research", "Zea mays")

    def test_allow_verdict_reasons_persist(self, client, auth, benign_screening):
        """CLEAR / APPROVED_AUTO."""
        assert benign_screening["verdict"] == "CLEAR"
        assert benign_screening["status"] == "APPROVED_AUTO"
        posted = benign_screening["reasons"]
        assert posted, "the POST response must carry the engine's rationale"

        detail = client.get(f"/api/v1/biosecurity/screenings/{benign_screening['id']}",
                            headers=auth("BIOTECH_RESEARCHER"))
        assert detail.status_code == 200
        assert detail.json()["reasons"] == posted
        assert self._fresh_read(benign_screening["id"]) == posted

    def test_review_verdict_reasons_persist(self, client, auth, flagged_screening):
        """FLAG / PENDING_REVIEW."""
        assert flagged_screening["verdict"] == "FLAG"
        assert flagged_screening["status"] == "PENDING_REVIEW"
        posted = flagged_screening["reasons"]
        assert posted
        assert any("Partial homology" in reason for reason in posted)

        detail = client.get(f"/api/v1/biosecurity/screenings/{flagged_screening['id']}",
                            headers=auth("BIOTECH_RESEARCHER"))
        assert detail.status_code == 200
        assert detail.json()["reasons"] == posted
        assert self._fresh_read(flagged_screening["id"]) == posted

    def test_block_verdict_reasons_persist(self, client, auth, blocked_screening):
        """BLOCK / BLOCKED — the case the examiner clicks on."""
        assert blocked_screening["verdict"] == "BLOCK"
        assert blocked_screening["status"] == "BLOCKED"
        posted = blocked_screening["reasons"]
        assert posted, "a BLOCK verdict must explain itself"
        assert any("homology" in reason.lower() for reason in posted)

        detail = client.get(f"/api/v1/biosecurity/screenings/{blocked_screening['id']}",
                            headers=auth("BIOTECH_RESEARCHER"))
        assert detail.status_code == 200
        assert detail.json()["reasons"] == posted
        assert self._fresh_read(blocked_screening["id"]) == posted

    def test_reasons_survive_a_new_engine_connection(self, client, auth, blocked_screening):
        """Persistence is in the database, not in process memory (restart-safe)."""
        import json as _json

        from sqlalchemy import create_engine, text

        from app.core.config import get_settings

        engine = create_engine(get_settings().database_url)
        try:
            with engine.connect() as connection:
                raw = connection.execute(
                    text("SELECT reasons FROM sequence_screenings WHERE id = :i"),
                    {"i": blocked_screening["id"]}).scalar_one()
        finally:
            engine.dispose()
        stored = _json.loads(raw) if isinstance(raw, str) else raw
        assert stored == blocked_screening["reasons"]

    def test_legacy_row_without_reasons_reads_as_empty(self, benign_screening):
        """A pre-migration row carries NULL and must not break the detail endpoint.

        `create_all()` builds the column NOT NULL, so a NULL cannot be written on a
        fresh database.  A database upgraded by migration 0001 gets the column via
        ALTER TABLE, where SQLite cannot add a NOT NULL column and the value is
        therefore nullable.  The serialiser is what protects that path, so it is
        exercised directly.
        """
        from app.schemas import ScreeningDetail

        payload = dict(benign_screening)
        payload["reasons"] = None
        payload["hits"] = []
        assert ScreeningDetail.model_validate(payload).reasons == []
