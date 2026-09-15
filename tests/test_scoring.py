"""FAIR-lite formulas: known inputs -> hand-computed known outputs.

Each expected number below was worked out by hand from the constants in
fair_lite.py and docs/assumptions.md, NOT by running the code and pasting the
result. That is what makes these tests catch formula bugs rather than just
freeze whatever the code currently does.
"""
from math import exp

import pytest

from app.scoring import fair_lite as fl

LOG4J = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
HEARTBLEED = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
DIRTY_COW = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"


# --- CVSS parsing and sub-scores --------------------------------------------
def test_max_exploitability_matches_cvss_spec():
    # 8.22 x 0.85 x 0.77 x 0.85 x 0.85
    assert fl.MAX_EXPLOITABILITY == pytest.approx(3.8870, abs=1e-4)


def test_worst_case_exploitability_normalizes_to_one():
    assert fl.exploitability(fl.parse_vector(LOG4J)) == pytest.approx(1.0)


def test_local_low_privilege_exploitability():
    # 8.22 x 0.55 x 0.77 x 0.62 x 0.85 = 1.83458 ; / 3.88704 = 0.47197
    assert fl.exploitability(fl.parse_vector(DIRTY_COW)) == pytest.approx(0.47197, abs=1e-4)


def test_scope_changed_uses_higher_privilege_weight():
    unchanged = fl.parse_vector("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H")
    changed = fl.parse_vector("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H")
    assert fl.exploitability(changed) / fl.exploitability(unchanged) == pytest.approx(0.68 / 0.62)


def test_impact_subscore():
    assert fl.impact_subscore(fl.parse_vector(LOG4J)) == pytest.approx(1 - 0.44**3)  # 0.914816
    assert fl.impact_subscore(fl.parse_vector(HEARTBLEED)) == pytest.approx(0.56)


def test_parse_v2_vector_maps_onto_v3_categories():
    f = fl.parse_vector("AV:N/AC:M/Au:N/C:C/I:C/A:C")
    assert (f.attack_complexity, f.privileges_required, f.user_interaction) == ("H", "N", "N")
    assert (f.confidentiality, f.integrity, f.availability) == ("H", "H", "H")
    # Only AC differs from the worst case: 0.44 / 0.77
    assert fl.exploitability(f) == pytest.approx(0.44 / 0.77)


def test_parse_v4_vector_folds_attack_requirements_into_complexity():
    f = fl.parse_vector("CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:A/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N")
    assert f.attack_complexity == "H"
    assert f.user_interaction == "R"
    assert (f.confidentiality, f.integrity, f.availability) == ("H", "L", "N")


@pytest.mark.parametrize("vector", [
    None,
    "",
    "garbage",
    "CVSS:3.1/AV:N",                                          # missing metrics
    "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",           # bad value
    "CVSS:9.9/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",           # unknown version
])
def test_unparseable_vectors_raise(vector):
    with pytest.raises(ValueError):
        fl.parse_vector(vector)


# --- Individual FAIR factors ------------------------------------------------
@pytest.mark.parametrize("iss, band, fraction", [
    (0.9148, "high", 1.0),
    (0.80, "high", 1.0),      # boundary is inclusive
    (0.7999, "medium", 0.5),
    (0.56, "medium", 0.5),
    (0.50, "medium", 0.5),
    (0.22, "low", 0.15),
    (0.0, "none", 0.0),
])
def test_primary_loss_bands(iss, band, fraction):
    assert fl.primary_loss_band(iss) == (band, fraction)


def test_exploit_probability_kev_multiplier():
    assert fl.exploit_probability(1.0, kev_flag=False) == pytest.approx(0.10)
    assert fl.exploit_probability(1.0, kev_flag=True) == pytest.approx(0.60)
    assert fl.exploit_probability(0.5, kev_flag=True) == pytest.approx(0.30)


def test_threat_event_frequency():
    assert fl.threat_event_frequency("api", known_ransomware_use=False) == pytest.approx(0.60)
    assert fl.threat_event_frequency("api", known_ransomware_use=True) == pytest.approx(0.90)
    assert fl.threat_event_frequency("unknown_type", False) == fl.DEFAULT_THREAT_EVENT_FREQUENCY


def test_secondary_loss_scales_with_tier_and_confidentiality():
    # 4,880,000 x 0.4 x 3/3 x 1.0
    assert fl.secondary_loss(3, "H") == pytest.approx(1_952_000)
    # 4,880,000 x 0.4 x 1/3 x 0.2
    assert fl.secondary_loss(1, "N") == pytest.approx(130_133.33, abs=0.01)


@pytest.mark.parametrize("tier", [0, 4])
def test_secondary_loss_rejects_out_of_range_tier(tier):
    with pytest.raises(ValueError):
        fl.secondary_loss(tier, "H")


# --- Whole scenarios ---------------------------------------------------------
def test_log4j_on_payment_api_known_answer():
    """KEV + ransomware, full C/I/A impact, internet-facing tier-3 API.

    exploitability 1.0 -> p = 1.0 x 0.10 x 6          = 0.60
    TEF = 0.60 (api) x 1.5 (ransomware)                = 0.90
    LEF = 0.90 x 0.60                                  = 0.54
    primary   = 4,880,000 x 0.6 x 1.0 (high band)      = 2,928,000
    secondary = 4,880,000 x 0.4 x 3/3 x 1.0 (C:H)      = 1,952,000
    LM  = 4,880,000     ALE = 0.54 x 4,880,000         = 2,635,200
    """
    b = fl.score_scenario(
        factors=fl.parse_vector(LOG4J), kev_flag=True, known_ransomware_use=True,
        asset_type="api", sensitivity_tier=3,
    )
    assert b.exploit_probability == pytest.approx(0.60)
    assert b.tef == pytest.approx(0.90)
    assert b.lef == pytest.approx(0.54)
    assert b.impact_band == "high"
    assert b.primary_loss == pytest.approx(2_928_000)
    assert b.secondary_loss == pytest.approx(1_952_000)
    assert b.lm == pytest.approx(4_880_000)
    assert b.ale == pytest.approx(2_635_200)


def test_heartbleed_not_in_kev_on_internal_database_known_answer():
    """Confidentiality-only impact, no exploitation evidence, tier-2 database.

    p = 1.0 x 0.10 = 0.10 ; TEF = 0.15 ; LEF = 0.015
    primary   = 4,880,000 x 0.6 x 0.5 (medium: ISS 0.56) = 1,464,000
    secondary = 4,880,000 x 0.4 x 2/3 x 1.0               = 1,301,333.33
    LM = 2,765,333.33 ; ALE = 0.015 x LM                  = 41,480
    """
    b = fl.score_scenario(
        factors=fl.parse_vector(HEARTBLEED), kev_flag=False, known_ransomware_use=False,
        asset_type="database", sensitivity_tier=2,
    )
    assert b.lef == pytest.approx(0.015)
    assert b.impact_band == "medium"
    assert b.lm == pytest.approx(2_765_333.33, abs=0.01)
    assert b.ale == pytest.approx(41_480, abs=0.01)


def test_kev_outranks_higher_cvss_without_kev():
    """The core thesis: exploitation evidence matters more than theoretical score."""
    kev_high = fl.score_scenario(
        factors=fl.parse_vector("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"),  # 8.1
        kev_flag=True, known_ransomware_use=False, asset_type="api", sensitivity_tier=3,
    )
    non_kev_critical = fl.score_scenario(
        factors=fl.parse_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),  # 9.8
        kev_flag=False, known_ransomware_use=False, asset_type="api", sensitivity_tier=3,
    )
    assert kev_high.ale > non_kev_critical.ale


def test_probability_of_loss_event_is_poisson():
    assert fl.probability_of_loss_event(0) == 0
    assert fl.probability_of_loss_event(1.0) == pytest.approx(1 - exp(-1))
    assert fl.probability_of_loss_event(50) == pytest.approx(1.0)


# --- Asset-level aggregation ("one open door", assumptions A7) ---------------
def test_single_scenario_aggregate_equals_scenario_ale():
    b = fl.score_scenario(
        factors=fl.parse_vector(LOG4J), kev_flag=True, known_ransomware_use=True,
        asset_type="api", sensitivity_tier=3,
    )
    agg = fl.aggregate_asset_risk("api", [(b.exploit_probability, b.lm, True)])
    assert agg.ale == pytest.approx(b.ale)


def test_two_scenario_aggregate_known_answer():
    """p1 = 0.6, LM1 = 4,880,000 ; p2 = 0.1, LM2 = 2,000,000 ; api, no ransomware.

    P(any) = 1 - 0.4 x 0.9                                = 0.64
    LEF    = 0.60 x 0.64                                  = 0.384
    LM     = (0.6 x 4,880,000 + 0.1 x 2,000,000) / 0.7    = 4,468,571.43
    ALE    = 0.384 x 4,468,571.43                         = 1,715,931.43
    """
    agg = fl.aggregate_asset_risk("api", [(0.6, 4_880_000, False), (0.1, 2_000_000, False)])
    assert agg.p_any == pytest.approx(0.64)
    assert agg.lef == pytest.approx(0.384)
    assert agg.lm == pytest.approx(4_468_571.43, abs=0.01)
    assert agg.ale == pytest.approx(1_715_931.43, abs=0.01)


def test_aggregate_lef_is_capped_by_threat_frequency():
    """300 near-certain doors cannot produce more loss events than attempts."""
    agg = fl.aggregate_asset_risk("api", [(0.6, 1_000_000, True)] * 300)
    assert agg.lef <= fl.threat_event_frequency("api", True) + 1e-12


def test_aggregate_of_nothing_is_zero():
    assert fl.aggregate_asset_risk("api", []).ale == 0


def test_ale_without_each_matches_naive_recompute():
    scenarios = [(0.6, 4_880_000, True), (0.1, 2_000_000, False), (0.3, 900_000, False),
                 (1.0, 500_000, False)]  # p = 1.0 exercises the no-division path
    fast = fl.ale_without_each("web_app", scenarios)
    naive = [
        fl.aggregate_asset_risk("web_app", scenarios[:i] + scenarios[i + 1:]).ale
        for i in range(len(scenarios))
    ]
    assert fast == pytest.approx(naive)
