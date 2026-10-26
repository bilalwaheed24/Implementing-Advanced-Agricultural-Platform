"""GS1 GTIN check-digit validation."""
import pytest

from app import gs1


@pytest.mark.parametrize("gtin", ["09501101530003", "09501101530027", "4006381333931",
                                  "036000291452", "96385074"])
def test_real_gtins_pass(gtin):
    assert gs1.is_valid_gtin(gtin)


@pytest.mark.parametrize("gtin", ["09501101530004", "4006381333932", "123456789",
                                  "0950110153002A", ""])
def test_wrong_check_digit_length_or_characters_fail(gtin):
    assert not gs1.is_valid_gtin(gtin)


def test_swapping_two_neighbouring_digits_is_caught():
    assert not gs1.is_valid_gtin("09501101350027")


def test_generator_appends_the_correct_digit():
    assert gs1.with_check_digit("0950110153002") == "09501101530027"


def test_api_rejects_a_product_with_a_bad_check_digit(client, auth):
    response = client.post("/api/v1/supply-chain/products", headers=auth("SUPPLY_CHAIN_OPERATOR"),
                           json={"gtin": "09501101530004", "name": "Bad GTIN corn",
                                 "category": "Vegetables"})
    assert response.status_code == 422
    assert "check digit" in response.text
