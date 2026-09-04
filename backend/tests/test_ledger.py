"""Unit tests for the permissioned ledger (Blockchain-integration.md §16)."""
from __future__ import annotations

import secrets

import pytest

from ledger import Ledger
from ledger.block import (GENESIS_PREV_HASH, merkle_proof, merkle_root, sha256_hex,
                          verify_merkle_proof)
from ledger.chain import ContractError, EndorsementError, LedgerError
from ledger.identity import OrgIdentity


@pytest.fixture
def ledger(tmp_path) -> Ledger:
    return Ledger(tmp_path / "ledger", "test-channel")


def code(prefix: str) -> str:
    return f"{prefix}-{secrets.token_hex(3).upper()}"


class TestIdentity:
    def test_sign_and_verify(self):
        identity = OrgIdentity.generate("TestMSP", "Test Org")
        signature = identity.sign("payload")
        assert OrgIdentity.verify(identity.public_pem, "payload", signature)

    def test_signature_does_not_verify_for_other_content(self):
        identity = OrgIdentity.generate("TestMSP", "Test Org")
        signature = identity.sign("payload")
        assert not OrgIdentity.verify(identity.public_pem, "other payload", signature)

    def test_signature_does_not_verify_under_another_key(self):
        a, b = OrgIdentity.generate("A", "A"), OrgIdentity.generate("B", "B")
        assert not OrgIdentity.verify(b.public_pem, "payload", a.sign("payload"))

    def test_malformed_signature_returns_false(self):
        identity = OrgIdentity.generate("TestMSP", "Test Org")
        assert not OrgIdentity.verify(identity.public_pem, "payload", "not-hex")


class TestMerkle:
    @pytest.mark.parametrize("count", [1, 2, 3, 5, 8, 17])
    def test_proof_verifies_for_every_leaf(self, count):
        leaves = [sha256_hex(str(i)) for i in range(count)]
        root = merkle_root(leaves)
        for index, leaf in enumerate(leaves):
            assert verify_merkle_proof(leaf, merkle_proof(leaves, index), root)

    def test_proof_fails_for_a_leaf_not_in_the_tree(self):
        leaves = [sha256_hex(str(i)) for i in range(5)]
        root = merkle_root(leaves)
        assert not verify_merkle_proof(sha256_hex("absent"), merkle_proof(leaves, 2), root)

    def test_root_changes_when_any_leaf_changes(self):
        leaves = [sha256_hex(str(i)) for i in range(5)]
        original = merkle_root(leaves)
        leaves[3] = sha256_hex("altered")
        assert merkle_root(leaves) != original


class TestGenesisAndAppend:
    def test_genesis_block(self, ledger):
        assert ledger.height == 1
        assert ledger.blocks[0].previous_hash == GENESIS_PREV_HASH
        assert ledger.blocks[0].number == 0

    def test_all_four_organisations_are_registered(self, ledger):
        assert set(ledger.msp.all()) == {"BiotechMSP", "FarmMSP", "SupplyMSP", "RegulatorMSP"}

    def test_append_links_blocks(self, ledger):
        before = ledger.height
        receipt = ledger.submit("provenance", "CreateBatch",
                                {"batch_code": code("B"), "quantity": 100}, "FarmMSP")
        assert receipt["block_number"] == before
        assert ledger.height == before + 1
        assert ledger.blocks[-1].previous_hash == ledger.blocks[-2].block_hash

    def test_state_is_committed(self, ledger):
        batch = code("B")
        ledger.submit("provenance", "CreateBatch", {"batch_code": batch, "quantity": 50},
                      "FarmMSP")
        assert ledger.query(f"batch:{batch}")["quantity"] == 50

    def test_persistence_across_reload(self, tmp_path):
        first = Ledger(tmp_path / "l", "c")
        batch = code("B")
        first.submit("provenance", "CreateBatch", {"batch_code": batch, "quantity": 7},
                     "FarmMSP")
        height = first.height
        second = Ledger(tmp_path / "l", "c")
        assert second.height == height
        assert second.query(f"batch:{batch}")["quantity"] == 7
        assert second.verify_chain()["valid"]


class TestEndorsementAndAuthorisation:
    def test_and_policy_collects_both_signatures(self, ledger):
        receipt = ledger.submit("gmo_registry", "RegisterEvent", {
            "event_code": code("ABS"), "crop_type": "Maize", "trait": "t",
            "donor_organism": "d", "developer": "dev", "screening_hash": "a" * 64},
            "BiotechMSP")
        assert set(receipt["endorsers"]) == {"BiotechMSP", "RegulatorMSP"}

    def test_unauthorised_submitter_rejected(self, ledger):
        with pytest.raises(ContractError, match="not authorised"):
            ledger.submit("certification", "Issue", {
                "cert_code": code("C"), "cert_type": "ORGANIC", "valid_from": "2026-01-01",
                "valid_to": "2027-01-01"}, "FarmMSP")

    def test_unknown_organisation_rejected(self, ledger):
        with pytest.raises(LedgerError):
            ledger.submit("provenance", "CreateBatch", {"batch_code": code("B"), "quantity": 1},
                          "GhostMSP")

    def test_unknown_function_rejected(self, ledger):
        with pytest.raises(ContractError):
            ledger.submit("provenance", "NoSuchFunction", {}, "FarmMSP")


class TestContractRules:
    def test_duplicate_identifier_rejected(self, ledger):
        event = code("ABS")
        args = {"event_code": event, "crop_type": "Maize", "trait": "t", "donor_organism": "d",
                "developer": "dev", "screening_hash": "a" * 64}
        ledger.submit("gmo_registry", "RegisterEvent", args, "BiotechMSP")
        with pytest.raises(ContractError, match="already registered"):
            ledger.submit("gmo_registry", "RegisterEvent", args, "BiotechMSP")

    def test_screening_hash_must_be_a_digest(self, ledger):
        with pytest.raises(ContractError, match="SHA-256"):
            ledger.submit("gmo_registry", "RegisterEvent", {
                "event_code": code("ABS"), "crop_type": "M", "trait": "t", "donor_organism": "d",
                "developer": "dev", "screening_hash": "short"}, "BiotechMSP")

    def test_quantity_conservation_across_parents(self, ledger):
        parent = code("B")
        ledger.submit("provenance", "CreateBatch", {"batch_code": parent, "quantity": 100},
                      "FarmMSP")
        with pytest.raises(ContractError, match="exceeds"):
            ledger.submit("provenance", "CreateBatch",
                          {"batch_code": code("B"), "quantity": 500, "parents": [parent]},
                          "FarmMSP")

    def test_negative_quantity_rejected(self, ledger):
        with pytest.raises(ContractError, match="negative"):
            ledger.submit("provenance", "CreateBatch",
                          {"batch_code": code("B"), "quantity": -5}, "FarmMSP")

    def test_illegal_state_transition_rejected(self, ledger):
        """A batch cannot move backwards through its lifecycle."""
        batch = code("B")
        ledger.submit("provenance", "CreateBatch", {"batch_code": batch, "quantity": 10},
                      "FarmMSP")
        # CREATED -> HARVESTED is legal.
        ledger.submit("provenance", "RecordEvent",
                      {"batch_code": batch, "event_id": code("E"), "biz_step": "harvesting"},
                      "FarmMSP")
        assert ledger.query(f"batch:{batch}")["state"] == "HARVESTED"
        # HARVESTED -> CREATED (commissioning) is not.
        with pytest.raises(ContractError, match="Illegal transition"):
            ledger.submit("provenance", "RecordEvent",
                          {"batch_code": batch, "event_id": code("E"),
                           "biz_step": "commissioning"}, "FarmMSP")

    def test_skipping_ahead_in_the_lifecycle_is_rejected(self, ledger):
        """A freshly created batch cannot jump straight to retail."""
        batch = code("B")
        ledger.submit("provenance", "CreateBatch", {"batch_code": batch, "quantity": 10},
                      "FarmMSP")
        with pytest.raises(ContractError, match="Illegal transition"):
            ledger.submit("provenance", "RecordEvent",
                          {"batch_code": batch, "event_id": code("E"),
                           "biz_step": "retail_selling"}, "SupplyMSP")

    def test_event_quantity_cannot_exceed_the_batch(self, ledger):
        batch = code("B")
        ledger.submit("provenance", "CreateBatch", {"batch_code": batch, "quantity": 10},
                      "FarmMSP")
        with pytest.raises(ContractError, match="conservation"):
            ledger.submit("provenance", "RecordEvent",
                          {"batch_code": batch, "event_id": code("E"),
                           "biz_step": "harvesting", "quantity": 99}, "FarmMSP")

    def test_event_on_unknown_batch_rejected(self, ledger):
        with pytest.raises(ContractError, match="Unknown batch"):
            ledger.submit("provenance", "RecordEvent",
                          {"batch_code": "does-not-exist", "event_id": code("E"),
                           "biz_step": "harvesting"}, "FarmMSP")

    def test_custody_transfer_requires_the_current_custodian(self, ledger):
        batch = code("B")
        ledger.submit("provenance", "CreateBatch", {"batch_code": batch, "quantity": 10},
                      "FarmMSP")
        with pytest.raises(ContractError, match="custodian"):
            ledger.submit("provenance", "TransferCustody",
                          {"batch_code": batch, "from_org": "SupplyMSP",
                           "to_org": "SupplyMSP"}, "SupplyMSP")

    def test_custody_transfer_succeeds_and_updates_state(self, ledger):
        batch = code("B")
        ledger.submit("provenance", "CreateBatch", {"batch_code": batch, "quantity": 10},
                      "FarmMSP")
        ledger.submit("provenance", "TransferCustody",
                      {"batch_code": batch, "from_org": "FarmMSP", "to_org": "SupplyMSP",
                       "occurred_at": "2026-01-01T00:00:00Z"}, "FarmMSP")
        assert ledger.query(f"batch:{batch}")["custodian"] == "SupplyMSP"

    def test_only_the_issuer_may_revoke(self, ledger):
        cert = code("C")
        ledger.submit("certification", "Issue", {
            "cert_code": cert, "cert_type": "ORGANIC", "standard": "USDA-NOP",
            "valid_from": "2026-01-01", "valid_to": "2027-01-01"}, "RegulatorMSP")
        assert ledger.query(f"cert:{cert}")["status"] == "ACTIVE"
        ledger.submit("certification", "Revoke", {"cert_code": cert, "reason": "audit finding"},
                      "RegulatorMSP")
        assert ledger.query(f"cert:{cert}")["status"] == "REVOKED"

    def test_certification_validity_window_is_checked(self, ledger):
        with pytest.raises(ContractError, match="valid_to must be after"):
            ledger.submit("certification", "Issue", {
                "cert_code": code("C"), "cert_type": "ORGANIC", "valid_from": "2027-01-01",
                "valid_to": "2026-01-01"}, "RegulatorMSP")

    def test_audit_head_cannot_go_backwards(self, ledger):
        ledger.submit("compliance_anchor", "AnchorAuditHead",
                      {"seq": 10, "head_hash": "a" * 64}, "RegulatorMSP")
        with pytest.raises(ContractError, match="backwards"):
            ledger.submit("compliance_anchor", "AnchorAuditHead",
                          {"seq": 5, "head_hash": "b" * 64}, "RegulatorMSP")

    def test_rejected_transaction_produces_no_block(self, ledger):
        before = ledger.height
        with pytest.raises(ContractError):
            ledger.submit("provenance", "CreateBatch",
                          {"batch_code": code("B"), "quantity": -1}, "FarmMSP")
        assert ledger.height == before, "a rejected transaction must not be committed"


class TestVerificationAndTamperDetection:
    def test_clean_chain_verifies(self, ledger):
        for _ in range(3):
            ledger.submit("provenance", "CreateBatch",
                          {"batch_code": code("B"), "quantity": 10}, "FarmMSP")
        result = ledger.verify_chain()
        assert result["valid"]
        assert result["signatures_verified"] > 0
        assert result["first_divergence"] is None

    def test_altered_transaction_argument_is_detected(self, ledger):
        ledger.submit("provenance", "CreateBatch", {"batch_code": code("B"), "quantity": 10},
                      "FarmMSP")
        ledger.blocks[-1].transactions[0].args["quantity"] = 9999
        result = ledger.verify_chain()
        assert not result["valid"]
        assert result["first_divergence"]["issue"] == "tx_id_mismatch"

    def test_broken_block_linkage_is_detected(self, ledger):
        ledger.submit("provenance", "CreateBatch", {"batch_code": code("B"), "quantity": 1},
                      "FarmMSP")
        ledger.blocks[-1].previous_hash = "0" * 64
        assert ledger.verify_chain()["first_divergence"]["issue"] == "previous_hash_mismatch"

    def test_forged_endorsement_is_detected(self, ledger):
        ledger.submit("provenance", "CreateBatch", {"batch_code": code("B"), "quantity": 1},
                      "FarmMSP")
        ledger.blocks[-1].transactions[0].endorsements[0]["signature"] = "00" * 70
        result = ledger.verify_chain()
        assert not result["valid"]
        assert "invalid_endorsement" in result["first_divergence"]["issue"]

    def test_content_hash_verification(self, ledger):
        receipt = ledger.submit("provenance", "CreateBatch",
                                {"batch_code": code("B"), "quantity": 1,
                                 "content_hash": "c" * 64}, "FarmMSP")
        assert ledger.verify_content_hash("c" * 64, receipt["tx_id"])["result"] == "MATCH"
        assert ledger.verify_content_hash("d" * 64, receipt["tx_id"])["result"] == "MISMATCH"
        assert ledger.verify_content_hash("c" * 64, "unknown-tx")["result"] == "NOT_ANCHORED"

    def test_inclusion_proof_for_a_committed_transaction(self, ledger):
        receipt = ledger.submit("provenance", "CreateBatch",
                                {"batch_code": code("B"), "quantity": 1}, "FarmMSP")
        proof = ledger.proof(receipt["tx_id"])
        assert proof["merkle_root"]
        assert verify_merkle_proof(receipt["tx_id"], proof["proof"], proof["merkle_root"])

    def test_stats_report_the_demo_marking(self, ledger):
        assert ledger.stats()["network"] == "single-node-demo"
