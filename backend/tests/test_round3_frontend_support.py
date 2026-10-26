"""List filters behind the dashboard tiles: each tile opens a list filtered to what it counts
(devices offline, GMO batches, hand-overs not yet booked in)."""
from __future__ import annotations

from datetime import datetime, timezone

from app.models import Batch, Device, GMOEvent, SupplyChainEvent
from .conftest import unique


def _ids(response) -> set[str]:
    assert response.status_code == 200, response.text
    return {row["id"] for row in response.json()["items"]}


class TestOfflineDeviceFilter:
    def test_offline_true_lists_only_silent_devices(self, client, auth, db, provisioned_device):
        quiet = db.get(Device, provisioned_device["id"])
        quiet.offline_since = datetime.now(timezone.utc)
        db.commit()
        headers = auth("FARM_OPERATOR")
        offline = client.get("/api/v1/devices?offline=true&page_size=200", headers=headers)
        assert provisioned_device["id"] in _ids(offline)
        assert all(row["offline_since"] for row in offline.json()["items"])
        reporting = client.get("/api/v1/devices?offline=false&page_size=200", headers=headers)
        assert provisioned_device["id"] not in _ids(reporting)
        assert all(not row["offline_since"] for row in reporting.json()["items"])

    def test_no_offline_parameter_lists_both(self, client, auth, db, provisioned_device):
        quiet = db.get(Device, provisioned_device["id"])
        quiet.offline_since = datetime.now(timezone.utc)
        db.commit()
        everything = client.get("/api/v1/devices?page_size=200", headers=auth("FARM_OPERATOR"))
        assert provisioned_device["id"] in _ids(everything)


def _batch(db, orgs, product, *, custodian="FARM", gmo_event_id=None) -> Batch:
    batch = Batch(org_id=orgs["FARM"].id, custodian_org_id=orgs[custodian].id,
                  batch_code=unique("R3"), verification_code=unique("V3"),
                  product_id=product.id, quantity=10, initial_quantity=10, unit="kg",
                  gmo_event_id=gmo_event_id)
    db.add(batch)
    db.commit()
    return batch


class TestBatchListFilters:
    def test_gmo_filter(self, client, auth, db, orgs, product):
        event = db.query(GMOEvent).first()
        plain = _batch(db, orgs, product)
        listed = client.get("/api/v1/supply-chain/batches?gmo=false&page_size=200",
                            headers=auth("FARM_OPERATOR"))
        assert plain.id in _ids(listed)
        gmo_rows = client.get("/api/v1/supply-chain/batches?gmo=true&page_size=200",
                              headers=auth("FARM_OPERATOR"))
        assert plain.id not in _ids(gmo_rows)
        # GMO lineage, not only a direct event: a batch may carry it through its seed lot or a
        # parent (round 4), so the list's own lineage flag is what must be set.
        assert all(row["gmo_lineage"] for row in gmo_rows.json()["items"])
        if event is not None:
            modified = _batch(db, orgs, product, gmo_event_id=event.id)
            again = client.get("/api/v1/supply-chain/batches?gmo=true&page_size=200",
                               headers=auth("FARM_OPERATOR"))
            assert modified.id in _ids(again)

    def test_awaiting_receipt_lists_unbooked_handovers_for_the_holder(
            self, client, auth, db, orgs, product):
        pending = _batch(db, orgs, product, custodian="SUPPLY")
        booked = _batch(db, orgs, product, custodian="SUPPLY")
        db.add(SupplyChainEvent(batch_id=booked.id, org_id=orgs["SUPPLY"].id,
                                event_type="OBJECT", biz_step="receiving",
                                disposition="in_progress", content_hash="0" * 64,
                                occurred_at=datetime.now(timezone.utc)))
        db.commit()
        own = _batch(db, orgs, product)
        rows = _ids(client.get(
            "/api/v1/supply-chain/batches?awaiting_receipt=true&page_size=200",
            headers=auth("SUPPLY_CHAIN_OPERATOR")))
        assert pending.id in rows
        assert booked.id not in rows
        assert own.id not in rows
        # The originator does not see a batch it handed away as one *it* must book in.
        farm_rows = _ids(client.get(
            "/api/v1/supply-chain/batches?awaiting_receipt=true&page_size=200",
            headers=auth("FARM_OPERATOR")))
        assert pending.id not in farm_rows
