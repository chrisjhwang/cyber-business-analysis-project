"""FAIR-lite point-estimate scoring.

Every function in this module is PURE: plain values in, a number out, no
database, no network, no clock. That is what makes the formulas testable with
hand-computed "known inputs -> known outputs" cases (tests/test_scoring.py), and
it is why the database loop lives in a separate module (engine.py).

FAIR vocabulary used below:
  TEF  threat event frequency  -- attempts per year against this scenario
  Vuln exploit probability     -- chance an attempt becomes a loss event
  LEF  loss event frequency    -- TEF x Vuln, loss events per year
  LM   loss magnitude          -- dollars per loss event (primary + secondary)
  ALE  annualized loss expect. -- LEF x LM, dollars per year

Every constant is justified in docs/assumptions.md. The A-numbers in the
comments below are section references into that file. Change a constant here
and update its entry there in the same commit.
"""
from dataclasses import dataclass
from math import exp

# --- A1. CVSS v3.1 metric weights -------------------------------------------
# Copied from the FIRST CVSS v3.1 specification, section 7.4. These are not
# our assumptions; they are the published standard, reused so that
# "exploitability" means exactly what CVSS means by it.
AV_WEIGHTS = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
AC_WEIGHTS = {"L": 0.77, "H": 0.44}
PR_WEIGHTS_SCOPE_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
PR_WEIGHTS_SCOPE_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}
UI_WEIGHTS = {"N": 0.85, "R": 0.62}
CIA_WEIGHTS = {"H": 0.56, "L": 0.22, "N": 0.0}
EXPLOITABILITY_COEFFICIENT = 8.22
# 3.887 -- network, low complexity, no privileges, no user interaction.
MAX_EXPLOITABILITY = (
    EXPLOITABILITY_COEFFICIENT
    * AV_WEIGHTS["N"]
    * AC_WEIGHTS["L"]
    * PR_WEIGHTS_SCOPE_UNCHANGED["N"]
    * UI_WEIGHTS["N"]
)

# --- A2. Translating CVSS v2 and v4 vectors onto v3 categories --------------
# About 1 in 10 KEV entries is old enough that NVD only has a v2 vector, and
# new CVEs increasingly ship v4 only. Rather than drop them, map each onto the
# closest v3 category and reuse the A1 weights.
V2_ACCESS_COMPLEXITY = {"L": "L", "M": "H", "H": "H"}  # v3 has no "medium"
V2_AUTHENTICATION = {"N": "N", "S": "L", "M": "H"}     # Au -> PR
V2_IMPACT = {"N": "N", "P": "L", "C": "H"}             # None/Partial/Complete
V4_USER_INTERACTION = {"N": "N", "P": "R", "A": "R"}   # Passive/Active -> Required


@dataclass(frozen=True)
class CvssFactors:
    """The CVSS base metrics FAIR-lite needs, normalized to v3 letter codes."""

    attack_vector: str
    attack_complexity: str
    privileges_required: str
    user_interaction: str
    scope_changed: bool
    confidentiality: str
    integrity: str
    availability: str


def parse_vector(vector: str | None) -> CvssFactors:
    """Parse a CVSS v2, v3.x or v4.0 vector string. Raises ValueError if it
    cannot, so callers can count and skip unscorable CVEs rather than guess."""
    if not vector or not vector.strip():
        raise ValueError("empty CVSS vector")
    parts = vector.strip().split("/")
    version = None
    if parts[0].upper().startswith("CVSS:"):
        version = parts[0].split(":", 1)[1]
        parts = parts[1:]
    try:
        m = dict(part.split(":", 1) for part in parts)
    except ValueError:
        raise ValueError(f"malformed CVSS vector: {vector!r}") from None

    try:
        if version is None:  # v2 vectors carry no "CVSS:" prefix
            factors = CvssFactors(
                attack_vector=m["AV"],
                attack_complexity=V2_ACCESS_COMPLEXITY[m["AC"]],
                privileges_required=V2_AUTHENTICATION[m["Au"]],
                user_interaction="N",  # v2 has no UI metric
                scope_changed=False,   # v2 has no scope metric
                confidentiality=V2_IMPACT[m["C"]],
                integrity=V2_IMPACT[m["I"]],
                availability=V2_IMPACT[m["A"]],
            )
        elif version.startswith("3."):
            factors = CvssFactors(
                attack_vector=m["AV"],
                attack_complexity=m["AC"],
                privileges_required=m["PR"],
                user_interaction=m["UI"],
                scope_changed=m["S"] == "C",
                confidentiality=m["C"],
                integrity=m["I"],
                availability=m["A"],
            )
        elif version.startswith("4."):
            # v4 split "attack complexity" into AC and AT (attack requirements).
            # Either one being hard makes the attack harder, so fold AT:P into AC:H.
            complexity = "H" if m["AC"] == "H" or m.get("AT") == "P" else "L"
            factors = CvssFactors(
                attack_vector=m["AV"],
                attack_complexity=complexity,
                privileges_required=m["PR"],
                user_interaction=V4_USER_INTERACTION[m["UI"]],
                scope_changed=False,  # v4 replaced scope with subsequent-system metrics
                confidentiality=m["VC"],
                integrity=m["VI"],
                availability=m["VA"],
            )
        else:
            raise ValueError(f"unsupported CVSS version {version!r} in {vector!r}")
    except KeyError as exc:
        raise ValueError(f"CVSS vector {vector!r} is missing or has bad metric {exc}") from None

    _validate(factors, vector)
    return factors


def _validate(f: CvssFactors, vector: str) -> None:
    checks = (
        (f.attack_vector, AV_WEIGHTS),
        (f.attack_complexity, AC_WEIGHTS),
        (f.privileges_required, PR_WEIGHTS_SCOPE_UNCHANGED),
        (f.user_interaction, UI_WEIGHTS),
        (f.confidentiality, CIA_WEIGHTS),
        (f.integrity, CIA_WEIGHTS),
        (f.availability, CIA_WEIGHTS),
    )
    for value, allowed in checks:
        if value not in allowed:
            raise ValueError(f"unexpected metric value {value!r} in CVSS vector {vector!r}")


def exploitability(f: CvssFactors) -> float:
    """CVSS v3.1 exploitability sub-score, rescaled to [0, 1]."""
    pr_weights = PR_WEIGHTS_SCOPE_CHANGED if f.scope_changed else PR_WEIGHTS_SCOPE_UNCHANGED
    raw = (
        EXPLOITABILITY_COEFFICIENT
        * AV_WEIGHTS[f.attack_vector]
        * AC_WEIGHTS[f.attack_complexity]
        * pr_weights[f.privileges_required]
        * UI_WEIGHTS[f.user_interaction]
    )
    return raw / MAX_EXPLOITABILITY


def impact_subscore(f: CvssFactors) -> float:
    """CVSS v3.1 Impact Sub-Score (ISS): 1 - (1-C)(1-I)(1-A). Range 0 .. 0.9148."""
    return 1 - (
        (1 - CIA_WEIGHTS[f.confidentiality])
        * (1 - CIA_WEIGHTS[f.integrity])
        * (1 - CIA_WEIGHTS[f.availability])
    )


# --- A3. Exploit probability (FAIR "Vulnerability") -------------------------
# Most published CVEs are never exploited in the wild, so even a maximally
# exploitable CVE with no exploitation evidence gets at most a 10% chance that
# a given attempt succeeds. Being in CISA KEV is direct evidence of real-world
# exploitation, which multiplies that by 6 (max 60%).
NON_KEV_EXPLOIT_SCALE = 0.10
KEV_MULTIPLIER = 6.0


def exploit_probability(exploitability_norm: float, kev_flag: bool) -> float:
    p = exploitability_norm * NON_KEV_EXPLOIT_SCALE
    if kev_flag:
        p *= KEV_MULTIPLIER
    return min(p, 1.0)  # invariant guard; the current constants top out at 0.6


# --- A4. Threat event frequency, per asset type -----------------------------
# Attempts per year to exploit ONE specific vulnerability on ONE asset. Driven
# by exposure: internet-facing assets see far more attack traffic than systems
# only reachable from inside the network.
THREAT_EVENT_FREQUENCY = {
    "web_app": 0.80,        # public, indexed, constantly scanned
    "api": 0.60,            # public, but needs endpoint knowledge
    "infrastructure": 0.40, # partly exposed (VPN, CI webhooks)
    "internal_tool": 0.25,  # needs a foothold inside first
    "database": 0.15,       # should never face the internet directly
}
DEFAULT_THREAT_EVENT_FREQUENCY = 0.25
# Ransomware crews weaponize and mass-scan for the CVEs they use.
RANSOMWARE_TEF_MULTIPLIER = 1.5


def threat_event_frequency(asset_type: str, known_ransomware_use: bool) -> float:
    tef = THREAT_EVENT_FREQUENCY.get(asset_type, DEFAULT_THREAT_EVENT_FREQUENCY)
    if known_ransomware_use:
        tef *= RANSOMWARE_TEF_MULTIPLIER
    return tef


# --- A5. Loss magnitude -----------------------------------------------------
# Anchor: IBM Security / Ponemon "Cost of a Data Breach Report 2024", global
# average total cost of a breach. Verify against the current edition before
# quoting it externally -- see docs/assumptions.md A5.
BREACH_COST_BENCHMARK = 4_880_000
# The report's cost categories, sorted into FAIR's two loss types.
# Primary (detection/escalation + post-breach response) is roughly 60%.
# Secondary (lost business + notification) is roughly 40%.
PRIMARY_LOSS_SHARE = 0.60
SECONDARY_LOSS_SHARE = 0.40

# (minimum ISS, band name, fraction of the primary-loss pool)
# high:   e.g. C:H/I:H/A:H (0.915) or C:H/I:H/A:N (0.806)
# medium: e.g. one H alone (0.56), or L/L/L (0.53)
# low:    e.g. one L alone (0.22)
IMPACT_BANDS = (
    (0.80, "high", 1.00),
    (0.50, "medium", 0.50),
    (0.00, "low", 0.15),
)

# Regulatory fines, notification and customer churn are driven by data
# exposure. A pure availability or integrity hit still costs reputation, just
# less.
CONFIDENTIALITY_SECONDARY_FACTOR = {"H": 1.0, "L": 0.5, "N": 0.2}
MAX_SENSITIVITY_TIER = 3


def primary_loss_band(iss: float) -> tuple[str, float]:
    """Map an Impact Sub-Score to (band name, fraction of the primary pool)."""
    if iss <= 0:
        return "none", 0.0
    for threshold, name, fraction in IMPACT_BANDS:
        if iss >= threshold:
            return name, fraction
    raise AssertionError("unreachable: the lowest band threshold is 0")


def primary_loss(iss: float) -> float:
    _, fraction = primary_loss_band(iss)
    return BREACH_COST_BENCHMARK * PRIMARY_LOSS_SHARE * fraction


def secondary_loss(sensitivity_tier: int, confidentiality: str) -> float:
    if not 1 <= sensitivity_tier <= MAX_SENSITIVITY_TIER:
        raise ValueError(f"sensitivity_tier must be 1..3, got {sensitivity_tier}")
    return (
        BREACH_COST_BENCHMARK
        * SECONDARY_LOSS_SHARE
        * (sensitivity_tier / MAX_SENSITIVITY_TIER)
        * CONFIDENTIALITY_SECONDARY_FACTOR[confidentiality]
    )


# --- Putting it together ----------------------------------------------------
@dataclass(frozen=True)
class RiskBreakdown:
    """Every intermediate value, kept so a report can show its working."""

    exploitability: float
    exploit_probability: float
    tef: float
    lef: float
    impact_band: str
    primary_loss: float
    secondary_loss: float
    lm: float
    ale: float


def score_scenario(
    *,
    factors: CvssFactors,
    kev_flag: bool,
    known_ransomware_use: bool,
    asset_type: str,
    sensitivity_tier: int,
) -> RiskBreakdown:
    """ALE for one (vulnerability, asset) scenario.

    LEF x LM, multiplied not added: LEF is events/year, LM is dollars/event, so
    the product is dollars/year.
    """
    expl = exploitability(factors)
    p = exploit_probability(expl, kev_flag)
    tef = threat_event_frequency(asset_type, known_ransomware_use)
    lef = tef * p

    iss = impact_subscore(factors)
    band, _ = primary_loss_band(iss)
    primary = primary_loss(iss)
    secondary = secondary_loss(sensitivity_tier, factors.confidentiality)
    lm = primary + secondary

    return RiskBreakdown(
        exploitability=expl,
        exploit_probability=p,
        tef=tef,
        lef=lef,
        impact_band=band,
        primary_loss=primary,
        secondary_loss=secondary,
        lm=lm,
        ale=lef * lm,
    )


def probability_of_loss_event(lef: float) -> float:
    """P(at least one loss event in a year), modelling loss events as a Poisson
    process with rate lef: 1 - P(zero events) = 1 - e^(-rate)."""
    return 1 - exp(-max(lef, 0.0))


# --- A7. Aggregating scenarios into one asset-level figure ------------------
# Summing scenario ALEs treats every CVE as a separate, independent attack. An
# asset with 280 applicable CVEs would then suffer ~70 breaches a year.
# Real attackers need ONE working door: a threat event against the asset
# succeeds if ANY applicable vulnerability can be exploited.
#
#   asset TEF = TEF(asset type), x1.5 if any applicable CVE is ransomware-linked
#   P(any)    = 1 - product(1 - p_i)
#   asset LEF = asset TEF x P(any)
#   asset LM  = sum(p_i x LM_i) / sum(p_i)   (the door used is more likely an easy one)
#   asset ALE = asset LEF x asset LM
#
# With a single scenario this reduces exactly to that scenario's ALE.
Scenario = tuple[float, float, bool]  # (exploit_probability, lm, known_ransomware_use)


@dataclass(frozen=True)
class AssetAggregate:
    tef: float
    p_any: float
    lef: float
    lm: float
    ale: float


def _aggregate(asset_type: str, p_none: float, weight: float, weighted_lm: float,
               ransomware: bool) -> AssetAggregate:
    if weight <= 0:
        return AssetAggregate(0.0, 0.0, 0.0, 0.0, 0.0)
    tef = threat_event_frequency(asset_type, ransomware)
    p_any = 1 - p_none
    lm = weighted_lm / weight
    lef = tef * p_any
    return AssetAggregate(tef=tef, p_any=p_any, lef=lef, lm=lm, ale=lef * lm)


def aggregate_asset_risk(asset_type: str, scenarios: list[Scenario]) -> AssetAggregate:
    p_none = 1.0
    for p, _, _ in scenarios:
        p_none *= 1 - p
    return _aggregate(
        asset_type,
        p_none=p_none,
        weight=sum(p for p, _, _ in scenarios),
        weighted_lm=sum(p * lm for p, lm, _ in scenarios),
        ransomware=any(r for _, _, r in scenarios),
    )


def ale_without_each(asset_type: str, scenarios: list[Scenario]) -> list[float]:
    """Asset ALE if scenario i alone were remediated, for every i.

    Recomputing the aggregate once per removed scenario would be O(n^2) (and the
    product inside makes it O(n^3) for a naive loop). Instead, remove each
    scenario's contribution from running totals: divide it out of the product,
    subtract it from the sums, decrement the ransomware count.
    """
    p_none = 1.0
    for p, _, _ in scenarios:
        p_none *= 1 - p
    weight = sum(p for p, _, _ in scenarios)
    weighted_lm = sum(p * lm for p, lm, _ in scenarios)
    ransomware_count = sum(1 for _, _, r in scenarios if r)

    results = []
    for i, (p, lm, rw) in enumerate(scenarios):
        if p < 1.0:
            p_none_without = p_none / (1 - p)
        else:  # cannot divide out a zero factor; recompute this one directly
            p_none_without = 1.0
            for j, (pj, _, _) in enumerate(scenarios):
                if j != i:
                    p_none_without *= 1 - pj
        results.append(_aggregate(
            asset_type,
            p_none=p_none_without,
            weight=weight - p,
            weighted_lm=weighted_lm - p * lm,
            ransomware=ransomware_count - (1 if rw else 0) > 0,
        ).ale)
    return results
