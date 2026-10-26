"""Round 6: notification and alert text reads as words, not stored codes."""
from types import SimpleNamespace

from app.services import biosecurity, gmo, notifications, telemetry


def test_human_quantity_uses_thousands_separators():
    assert notifications.human_quantity(2400.0, "kg") == "2,400 kg"
    assert notifications.human_quantity(1234567) == "1,234,567"
    assert notifications.human_quantity(12.5, "t") == "12.5 t"
    assert notifications.human_quantity(None, "kg") == "an unknown quantity"


def test_risk_sentence_is_plain_words_and_a_percentage():
    text = biosecurity.risk_sentence("PROHIBITED", 0.9)
    assert text.startswith("Risk: prohibited (score 90%);")
    assert "PROHIBITED" not in text and "0.9" not in text
    low = biosecurity.risk_sentence("LOW", 0.05)
    assert low.startswith("Risk: low (score 5%);") and "LOW" not in low


def test_gmo_decision_sentence():
    assert gmo.decision_sentence("APPROVED") == "approved the event"
    assert gmo.decision_sentence("REJECTED") == "rejected the event"
    assert "pending" in gmo.decision_sentence("PENDING")
    assert "APPROVED" not in gmo.decision_sentence("APPROVED")


def test_field_label_names_the_farm():
    farm = SimpleNamespace(name="Green Valley South")
    assert telemetry.field_label(SimpleNamespace(name="Block C", farm=farm)) \
        == "Block C (Green Valley South)"
    assert telemetry.field_label(SimpleNamespace(name="Block C", farm=None)) == "Block C"
