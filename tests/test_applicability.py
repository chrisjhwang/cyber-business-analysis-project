import pytest

from app.scoring.applicability import (
    match_technology,
    parse_technologies,
    parse_technology,
    product_candidates,
)


def matches(techs, vendor=None, product=None, affected=None):
    return match_technology(parse_technologies(techs), product_candidates(vendor, product, affected))


def test_exact_cpe_product_matches():
    assert matches(["apache:log4j"], affected=["apache:log4j"]) == "apache:log4j"


def test_product_is_a_prefix_match():
    assert matches(["microsoft:windows_server"], affected=["microsoft:windows_server_2019"])


def test_prefix_does_not_match_a_different_product():
    assert matches(["microsoft:windows_server"], affected=["microsoft:windows_10"]) is None


def test_vendor_must_match_exactly():
    assert matches(["apache:log4j"], affected=["notapache:log4j"]) is None


def test_vendor_wildcard():
    assert matches(["citrix:*"], affected=["citrix:netscaler_gateway"]) == "citrix:*"


def test_kev_display_names_are_normalized_as_fallback():
    # NVD not analysed yet: only KEV's "Apache" / "Log4j2" is available.
    assert matches(["apache:log4j"], vendor="Apache", product="Log4j2")
    assert matches(["pulse_secure:pulse_connect_secure"], vendor="Pulse Secure",
                   product="Pulse Connect Secure")


def test_asset_without_technologies_matches_nothing():
    assert matches([], affected=["apache:log4j"]) is None


@pytest.mark.parametrize("bad", ["log4j", ":log4j", ""])
def test_malformed_technology_rejected(bad):
    with pytest.raises(ValueError):
        parse_technology(bad)
