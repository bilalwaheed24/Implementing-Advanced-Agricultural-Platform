"""Alert and incident lifecycles, and the tenant scoping of the two sweeps.

These four fixes were implemented during the remediation but shipped without regression
tests, so nothing stopped them silently regressing. Covers audit P1 (sweep cross-tenant
leakage and cross-tenant alert writes) and audit P2 (alert and incident state machines).
"""
from __future__ import annotations

from datetime import timedelta

import pytest

from .conftest import unique


@pytest.fixture
def alert(db, orgs):
    """An OPEN alert owned by the regulator organisation the analyst belongs to."""
    from app.services import notifications

    raised = notifications.raise_alert(
        db, "DATA_THEFT", "WARNING", f"Lifecycle probe {unique('AL')}",
        detail="Raised by the alert lifecycle regression test.",
        org_id=orgs["REGULATOR"].id, notify=False, open_incident=False)
    db.commit()
    return raised


@pytest.fixture
def incident(db, orgs):
    """An OPEN incident owned by the regulator organisation."""
    from app.models import Incident

    created = Incident(title=f"Incident probe {unique('IN')}", severity="CRITICAL",
                       org_id=orgs["REGULATOR"].id, summary="Incident lifecycle regression test.")
    db.add(created)
    db.commit()
    return created


class TestAlertStateMachine:
    """Both transitions used to be applied unconditionally, so resolve-then-acknowledge
    walked a RESOLVED alert back to ACKNOWLEDGED while leaving resolved_at set (audit P2)."""

    def test_open_to_acknowledged_to_resolved(self, client, auth, alert):
        acked = client.post(f"/api/v1/security/alerts/{alert.id}/acknowledge",
                            headers=auth("SECURITY_ANALYST"))
        assert acked.status_code == 200, acked.text
        assert acked.json()["status"] == "ACKNOWLEDGED"

        resolved = client.post(f"/api/v1/security/alerts/{alert.id}/resolve",
                               headers=auth("SECURITY_ANALYST"))
        assert resolved.status_code == 200, resolved.text
        assert resolved.json()["status"] == "RESOLVED"

    def test_resolved_cannot_go_back_to_acknowledged(self, client, auth, alert):
        resolved = client.post(f"/api/v1/security/alerts/{alert.id}/resolve",
                               headers=auth("SECURITY_ANALYST"))
        assert resolved.status_code == 200, resolved.text

        reopened = client.post(f"/api/v1/security/alerts/{alert.id}/acknowledge",
                               headers=auth("SECURITY_ANALYST"))
        assert reopened.status_code == 409, reopened.text
        assert "cannot move to ACKNOWLEDGED" in reopened.json()["detail"]

        after = client.get("/api/v1/security/alerts", headers=auth("SECURITY_ANALYST")).json()
        states = {a["id"]: a["status"] for a in after["items"]}
        assert states[alert.id] == "RESOLVED", "the alert must still be resolved"

    def test_open_may_resolve_directly(self, client, auth, alert):
        """A responder who has already dealt with the cause need not acknowledge first."""
        resolved = client.post(f"/api/v1/security/alerts/{alert.id}/resolve",
                               headers=auth("SECURITY_ANALYST"))
        assert resolved.status_code == 200, resolved.text
        assert resolved.json()["status"] == "RESOLVED"

    def test_acknowledging_twice_is_refused(self, client, auth, alert):
        first = client.post(f"/api/v1/security/alerts/{alert.id}/acknowledge",
                            headers=auth("SECURITY_ANALYST"))
        assert first.status_code == 200, first.text
        second = client.post(f"/api/v1/security/alerts/{alert.id}/acknowledge",
                             headers=auth("SECURITY_ANALYST"))
        assert second.status_code == 409, second.text
        assert "already ACKNOWLEDGED" in second.json()["detail"]


class TestIncidentStateMachine:
    """Any status was previously accepted, so a CLOSED incident could be walked back to OPEN
    and closed_at was left set on a reopened incident (audit P2)."""

    def test_the_legitimate_path_through_to_closed(self, client, auth, incident):
        for target in ("TRIAGED", "CONTAINED", "RESOLVED", "CLOSED"):
            response = client.patch(f"/api/v1/security/incidents/{incident.id}",
                                    headers=auth("SECURITY_ANALYST"),
                                    json={"status": target, "note": f"moving to {target}"})
            assert response.status_code == 200, f"{target}: {response.text}"
            assert response.json()["status"] == target

    def test_closed_cannot_be_reopened(self, client, auth, incident):
        for target in ("RESOLVED", "CLOSED"):
            assert client.patch(f"/api/v1/security/incidents/{incident.id}",
                                headers=auth("SECURITY_ANALYST"),
                                json={"status": target}).status_code == 200

        response = client.patch(f"/api/v1/security/incidents/{incident.id}",
                                headers=auth("SECURITY_ANALYST"), json={"status": "OPEN"})
        assert response.status_code == 409, response.text
        assert "cannot move to OPEN" in response.json()["detail"]

        after = client.get(f"/api/v1/security/incidents/{incident.id}",
                           headers=auth("SECURITY_ANALYST")).json()
        assert after["incident"]["status"] == "CLOSED"

    def test_skipping_from_open_to_a_later_stage_is_allowed(self, client, auth, incident):
        """Containment without a separate triage step is legitimate under time pressure."""
        response = client.patch(f"/api/v1/security/incidents/{incident.id}",
                                headers=auth("SECURITY_ANALYST"), json={"status": "CONTAINED"})
        assert response.status_code == 200, response.text

    def test_reopening_a_resolved_incident_clears_closed_at(self, client, auth, db, incident):
        """closed_at is not part of the response model, so it is read from the row."""
        from app.models import Incident

        resolved = client.patch(f"/api/v1/security/incidents/{incident.id}",
                                headers=auth("SECURITY_ANALYST"), json={"status": "RESOLVED"})
        assert resolved.status_code == 200, resolved.text
        db.expire_all()
        assert db.get(Incident, incident.id).closed_at is not None, \
            "resolving records a closed_at"

        reopened = client.patch(f"/api/v1/security/incidents/{incident.id}",
                                headers=auth("SECURITY_ANALYST"),
                                json={"status": "OPEN", "note": "new evidence"})
        assert reopened.status_code == 200, reopened.text
        assert reopened.json()["status"] == "OPEN"
        db.expire_all()
        assert db.get(Incident, incident.id).closed_at is None, \
            "a reopened incident must not keep a close timestamp"

    def test_an_unknown_status_is_rejected(self, client, auth, incident):
        response = client.patch(f"/api/v1/security/incidents/{incident.id}",
                                headers=auth("SECURITY_ANALYST"), json={"status": "WONTFIX"})
        assert response.status_code == 422, response.text


class TestDeviceHealthSweepIsTenantScoped:
    """Unscoped, a farm operator's sweep disclosed other tenants' device ids and created
    alert and notification rows inside those organisations (audit P1)."""

    @pytest.fixture
    def silent_devices(self, db, orgs, second_farm_org, farm):
        """One stale ACTIVE device in each of the two farm organisations."""
        from app.core.security import generate_device_secret, encrypt_at_rest, utcnow
        from app.models import Device, Farm

        rival_farm = db.query(Farm).filter(Farm.org_id == second_farm_org.id).first()
        if rival_farm is None:
            rival_farm = Farm(org_id=second_farm_org.id, name="Rival Farm", region="Iowa",
                              country="US", latitude=41.0, longitude=-93.0, area_ha=50.0)
            db.add(rival_farm)
            db.flush()

        made = {}
        for key, org_id, farm_id in (("own", orgs["FARM"].id, farm.id),
                                     ("rival", second_farm_org.id, rival_farm.id)):
            device = Device(
                device_type="SOIL_SENSOR", model="T-1000", firmware_version="1.0.0",
                org_id=org_id, farm_id=farm_id,
                secret_enc=encrypt_at_rest(generate_device_secret()), status="ACTIVE",
                interval_seconds=60, last_seen_at=utcnow() - timedelta(hours=12))
            db.add(device)
            db.flush()
            made[key] = device.id
        db.commit()
        return made

    def test_a_farm_operator_sweep_touches_only_its_own_organisation(
            self, client, auth, silent_devices):
        response = client.post("/api/v1/devices/sweep/health", headers=auth("FARM_OPERATOR"))
        assert response.status_code == 200, response.text
        swept = set(response.json()["silent_devices"])

        assert silent_devices["own"] in swept
        assert silent_devices["rival"] not in swept, \
            "a tenant sweep must not reach another organisation's devices"

    def test_the_rival_tenant_receives_no_alert_from_that_sweep(
            self, client, auth, db, silent_devices, second_farm_org):
        from app.models import Alert

        client.post("/api/v1/devices/sweep/health", headers=auth("FARM_OPERATOR"))
        db.commit()
        leaked = db.query(Alert).filter(Alert.org_id == second_farm_org.id,
                                        Alert.category == "DEVICE_HEALTH").all()
        assert leaked == [], "the sweep created alert rows inside another tenant"

    def test_an_oversight_role_may_sweep_the_whole_platform(
            self, client, auth, silent_devices):
        response = client.post("/api/v1/devices/sweep/health", headers=auth("ADMIN"))
        assert response.status_code == 200, response.text
        swept = set(response.json()["silent_devices"])
        assert silent_devices["own"] in swept and silent_devices["rival"] in swept


class TestDataTheftSweepIsTenantScoped:
    """The findings carry principal ids, scores and signal detail; unscoped, a tenant role
    received that for users of other organisations (audit P1)."""

    @pytest.fixture
    def access_records(self, db, orgs, second_farm_org):
        """Enough access volume in each organisation to cross the detection threshold.

        Synthetic principal ids are used rather than the fixture users': the access-recording
        middleware writes a row for every request the rest of the suite makes, and that real
        traffic dilutes the most-recent-25 window the scorer looks at, so a test keyed to a
        real user passes alone and fails in a full run.
        """
        import uuid

        from app.core.security import utcnow
        from app.models import AccessRecord

        principals = {"own": str(uuid.uuid4()), "rival": str(uuid.uuid4())}
        orgs_by_key = {"own": orgs["FARM"].id, "rival": second_farm_org.id}
        # max_page_size_streak (0.20) combined with cross_tenant_attempts (0.45) scores
        # 0.56, which clears DETECTION_THRESHOLD of 0.5.
        for key, principal_id in principals.items():
            for index in range(25):
                db.add(AccessRecord(
                    principal_id=principal_id, org_id=orgs_by_key[key],
                    route="/api/v1/supply-chain/batches", method="GET",
                    page_size=200, result_count=200, status_code=200, hour=12,
                    cross_tenant_attempt=True,
                    created_at=utcnow() - timedelta(minutes=15 * index)))
        db.commit()
        return principals

    def test_a_tenant_sweep_returns_only_its_own_principals(self, client, auth,
                                                            access_records):
        response = client.post("/api/v1/security/data-theft/sweep",
                               headers=auth("FARM_OPERATOR"))
        assert response.status_code == 200, response.text
        found = {f["principal_id"] for f in response.json()["findings"]}

        assert access_records["rival"] not in found, \
            "a tenant sweep disclosed a principal from another organisation"
        assert access_records["own"] in found, "its own flagged principal must be reported"

    def test_an_oversight_sweep_covers_every_organisation(self, client, auth, access_records):
        response = client.post("/api/v1/security/data-theft/sweep",
                               headers=auth("SECURITY_ANALYST"))
        assert response.status_code == 200, response.text
        found = {f["principal_id"] for f in response.json()["findings"]}
        assert access_records["own"] in found and access_records["rival"] in found


class TestShipmentCannotReferenceAForeignBatch:
    """A shipment used to accept any batch id, which both created a shipment against another
    tenant's batch and confirmed that the batch existed (audit P1)."""

    @pytest.fixture
    def foreign_batch(self, db, second_farm_org, product):
        from app.core.security import utcnow, verification_code
        from app.models import Batch

        batch = Batch(batch_code=unique("FGN"), product_id=product.id,
                      verification_code=verification_code(),
                      org_id=second_farm_org.id, custodian_org_id=second_farm_org.id,
                      quantity=500.0, initial_quantity=500.0, unit="kg", state="CREATED",
                      origin_region="Iowa", origin_country="US", harvested_at=utcnow())
        db.add(batch)
        db.commit()
        return batch

    def _payload(self, batch_id):
        from datetime import datetime, timezone
        return {"sscc": unique("SSCC")[:18], "batch_id": batch_id, "carrier": "Test Carrier",
                "origin_name": "Origin Depot", "origin_lat": 42.0, "origin_lon": -93.6,
                "destination_name": "Destination Depot", "destination_lat": 41.0,
                "destination_lon": -92.0,
                "departed_at": datetime.now(timezone.utc).isoformat()}

    def test_a_foreign_batch_is_an_indistinguishable_404(self, client, auth, foreign_batch):
        response = client.post("/api/v1/supply-chain/shipments",
                               headers=auth("SUPPLY_CHAIN_OPERATOR"),
                               json=self._payload(foreign_batch.id))
        assert response.status_code == 404, response.text
        assert "batch" in response.json()["detail"].lower()

    def test_an_unknown_batch_gives_the_same_answer(self, client, auth):
        """The two responses must match, or the difference is an existence oracle."""
        import uuid

        response = client.post("/api/v1/supply-chain/shipments",
                               headers=auth("SUPPLY_CHAIN_OPERATOR"),
                               json=self._payload(str(uuid.uuid4())))
        assert response.status_code == 404, response.text

    def test_no_shipment_row_is_created(self, client, auth, db, foreign_batch):
        from app.models import Shipment

        client.post("/api/v1/supply-chain/shipments", headers=auth("SUPPLY_CHAIN_OPERATOR"),
                    json=self._payload(foreign_batch.id))
        db.commit()
        leaked = db.query(Shipment).filter(Shipment.batch_id == foreign_batch.id).all()
        assert leaked == [], "a shipment was created against another tenant's batch"


class TestDeviceSecretRotationIsOwnerOnly:
    """get_or_404 lets an oversight role reach any device, which is right for containment but
    wrong for credential issuance: it handed an administrator another tenant's plaintext
    device secret and invalidated the working one (audit P2)."""

    def test_the_owning_organisation_may_rotate(self, client, auth, provisioned_device):
        response = client.post(f"/api/v1/devices/{provisioned_device['id']}/rotate-secret",
                               headers=auth("FARM_OPERATOR"))
        assert response.status_code == 200, response.text
        assert response.json()["device_secret"] != provisioned_device["secret"]

    def test_a_cross_tenant_oversight_role_is_refused(self, client, auth, provisioned_device):
        response = client.post(f"/api/v1/devices/{provisioned_device['id']}/rotate-secret",
                               headers=auth("ADMIN"))
        assert response.status_code == 403, response.text
        assert "owns the device" in response.json()["detail"]

    def test_the_refused_rotation_leaves_the_working_secret_intact(
            self, client, auth, db, provisioned_device):
        from app.models import Device

        # The stored ciphertext is compared directly: a rotation rewrites the column, so an
        # unchanged value is proof the credential was left alone.
        before = db.get(Device, provisioned_device["id"]).secret_enc
        client.post(f"/api/v1/devices/{provisioned_device['id']}/rotate-secret",
                    headers=auth("ADMIN"))
        db.expire_all()
        after = db.get(Device, provisioned_device["id"]).secret_enc
        assert before == after, "a refused rotation must not invalidate the device"

    def test_containment_remains_available_platform_wide(self, client, auth,
                                                         provisioned_device):
        """Quarantine is deliberately still reachable by an oversight role."""
        response = client.post(f"/api/v1/devices/{provisioned_device['id']}/quarantine",
                               headers=auth("ADMIN"), json={"reason": "containment regression"})
        assert response.status_code == 200, response.text
        assert response.json()["status"] == "QUARANTINED"


class TestApprovedOnlyEventFilter:
    """The seed-lot selector is built from this filter, so it must agree exactly with the rule
    `gmo.require_approved_event` applies on write: anything it offers must be creatable."""

    @pytest.fixture
    def gmo_event(self, client, auth, hazards):
        from ai.data.generate import benign_sequence

        screening = client.post("/api/v1/biosecurity/screenings",
                                headers=auth("BIOTECH_RESEARCHER"),
                                json={"name": unique("SCR"), "sequence": benign_sequence(600),
                                      "organism": "Zea mays", "intent": "Approved-filter test"})
        assert screening.status_code == 201, screening.text
        event = client.post("/api/v1/gmo/events", headers=auth("BIOTECH_RESEARCHER"), json={
            "event_code": f"ABS-{unique('')[-5:].rjust(5, '0')}-1", "crop_type": "Maize",
            "trait": "Drought tolerance", "donor_organism": "Bacillus subtilis",
            "developer": "Test Dev", "screening_id": screening.json()["id"]})
        assert event.status_code == 201, event.text
        return event.json()

    def _listed(self, client, auth, approved_only):
        query = "?approved_only=true" if approved_only else ""
        response = client.get(f"/api/v1/gmo/events{query}",
                              headers=auth("BIOTECH_RESEARCHER"))
        assert response.status_code == 200, response.text
        return {row["id"] for row in response.json()["items"]}

    def test_an_unapproved_event_is_listed_but_not_offered(self, client, auth, gmo_event):
        assert gmo_event["id"] in self._listed(client, auth, approved_only=False)
        assert gmo_event["id"] not in self._listed(client, auth, approved_only=True), \
            "an event with no approval must not be offered as seed-lot lineage"

    def test_a_rejected_event_is_still_not_offered(self, client, auth, gmo_event):
        rejected = client.post(f"/api/v1/gmo/events/{gmo_event['id']}/approvals",
                               headers=auth("REGULATOR"),
                               json={"jurisdiction": "EU", "status": "REJECTED",
                                     "reference": "EU-REJ-FILTER"})
        assert rejected.status_code in (200, 201), rejected.text
        assert gmo_event["id"] not in self._listed(client, auth, approved_only=True)

    def test_an_approved_event_is_offered_and_is_creatable(self, client, auth, gmo_event):
        approved = client.post(f"/api/v1/gmo/events/{gmo_event['id']}/approvals",
                               headers=auth("REGULATOR"),
                               json={"jurisdiction": "EU", "status": "APPROVED",
                                     "reference": "EU-OK-FILTER"})
        assert approved.status_code in (200, 201), approved.text
        assert gmo_event["id"] in self._listed(client, auth, approved_only=True)

        # Anything the selector offers must actually be accepted by the write endpoint.
        from datetime import datetime, timezone
        lot = client.post("/api/v1/gmo/seed-lots", headers=auth("BIOTECH_RESEARCHER"),
                          json={"lot_code": unique("SL"), "gmo_event_id": gmo_event["id"],
                                "crop_type": "Maize", "variety": "V1", "quantity_kg": 500.0,
                                "produced_at": datetime.now(timezone.utc).isoformat()})
        assert lot.status_code == 201, lot.text

    def test_the_filter_does_not_cross_tenants(self, client, auth, gmo_event):
        """A farm role must not see the biotech tenant's events through the new parameter."""
        response = client.get("/api/v1/gmo/events?approved_only=true",
                              headers=auth("FARM_OPERATOR"))
        assert response.status_code in (200, 403), response.text
        if response.status_code == 200:
            assert gmo_event["id"] not in {row["id"] for row in response.json()["items"]}
