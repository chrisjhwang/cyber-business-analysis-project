"""Read-side queries shared by the API and the report.

Both answer the same business questions ("which asset is riskiest?", "what
should we patch first?"). Keeping the SQL in one place means the web page and
the written report cannot disagree about a number.
"""
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from app.models import Asset, RiskScore, Vulnerability
from app.scoring.fair_lite import (
    AssetAggregate,
    aggregate_asset_risk,
    ale_without_each,
    probability_of_loss_event,
)


@dataclass
class ScenarioPoint:
    cve_id: str
    exploit_probability: float
    lm: float
    ale: float
    kev_flag: bool
    known_ransomware_use: bool


@dataclass
class AssetSummary:
    asset: Asset
    scenarios: list[ScenarioPoint]
    aggregate: AssetAggregate

    @property
    def scenario_count(self) -> int:
        return len(self.scenarios)

    @property
    def kev_count(self) -> int:
        return sum(1 for s in self.scenarios if s.kev_flag)

    @property
    def max_ale(self) -> float:
        return max((s.ale for s in self.scenarios), default=0.0)

    @property
    def scenario_ale_sum(self) -> float:
        """Independent-attacks upper bound. Kept for transparency, not the headline."""
        return sum(s.ale for s in self.scenarios)

    @property
    def total_ale(self) -> float:
        return self.aggregate.ale

    @property
    def expected_loss_events(self) -> float:
        return self.aggregate.lef

    @property
    def prob_loss_event(self) -> float:
        return probability_of_loss_event(self.aggregate.lef)

    def as_scenarios(self) -> list[tuple[float, float, bool]]:
        return [(s.exploit_probability, s.lm, s.known_ransomware_use) for s in self.scenarios]


def asset_summaries(
    session: Session, asset_id: int | None = None, exclude_cves: Iterable[str] = ()
) -> list[AssetSummary]:
    """One row per asset, riskiest first, using the "one open door" aggregation
    (fair_lite A7). Assets with no applicable CVEs still appear, because
    "nothing we know of applies" is a finding too.

    exclude_cves: pretend these CVEs are patched (for "what if" figures).
    """
    asset_stmt = select(Asset).order_by(Asset.id)
    score_stmt = select(
        RiskScore.asset_id,
        RiskScore.cve_id,
        RiskScore.exploit_probability,
        RiskScore.lm,
        RiskScore.ale,
        Vulnerability.kev_flag,
        Vulnerability.known_ransomware_use,
    ).join(Vulnerability, Vulnerability.cve_id == RiskScore.cve_id)
    if asset_id is not None:
        asset_stmt = asset_stmt.where(Asset.id == asset_id)
        score_stmt = score_stmt.where(RiskScore.asset_id == asset_id)

    excluded = set(exclude_cves)
    by_asset: dict[int, list[ScenarioPoint]] = defaultdict(list)
    for row in session.execute(score_stmt).all():
        if row.cve_id not in excluded:
            by_asset[row.asset_id].append(ScenarioPoint(*row[1:]))

    summaries = []
    for asset in session.scalars(asset_stmt).all():
        points = sorted(by_asset[asset.id], key=lambda p: p.ale, reverse=True)
        summary = AssetSummary(asset, points, AssetAggregate(0.0, 0.0, 0.0, 0.0, 0.0))
        summary.aggregate = aggregate_asset_risk(asset.type, summary.as_scenarios())
        summaries.append(summary)
    return sorted(summaries, key=lambda s: (-s.total_ale, s.asset.name))


def top_scenarios(
    session: Session, n: int, asset_id: int | None = None
) -> list[tuple[RiskScore, Vulnerability, Asset]]:
    stmt = (
        select(RiskScore, Vulnerability, Asset)
        .join(Vulnerability, Vulnerability.cve_id == RiskScore.cve_id)
        .join(Asset, Asset.id == RiskScore.asset_id)
        .order_by(desc(RiskScore.ale), RiskScore.cve_id)
        .limit(n)
    )
    if asset_id is not None:
        stmt = stmt.where(RiskScore.asset_id == asset_id)
    return [tuple(row) for row in session.execute(stmt).all()]


def remediation_priorities(
    session: Session, n: int, summaries: list[AssetSummary] | None = None
) -> list[dict[str, Any]]:
    """CVEs ranked by standalone exposure: the sum of their scenario ALEs across
    every asset they touch. This answers "how dangerous is this hole?".

    `reduction` answers a different question: how much would asset-level ALE
    actually drop if ONLY this CVE were patched? On an asset riddled with other
    exploitable CVEs, close to nothing, because the attacker uses another door.
    A big gap between the two numbers means the asset needs a systemic fix
    (upgrade, isolate, replace), not one more patch.
    """
    summaries = summaries if summaries is not None else asset_summaries(session)
    per_cve: dict[str, dict[str, Any]] = defaultdict(
        lambda: {"standalone_ale": 0.0, "reduction": 0.0, "assets": []}
    )
    for summary in summaries:
        without = ale_without_each(summary.asset.type, summary.as_scenarios())
        for point, ale_without in zip(summary.scenarios, without, strict=True):
            entry = per_cve[point.cve_id]
            entry["standalone_ale"] += point.ale
            entry["reduction"] += summary.total_ale - ale_without
            entry["assets"].append(summary.asset.name)

    ranked = sorted(per_cve.items(), key=lambda kv: (-kv[1]["standalone_ale"], kv[0]))[:n]
    vulns = {
        v.cve_id: v
        for v in session.scalars(
            select(Vulnerability).where(Vulnerability.cve_id.in_([cve for cve, _ in ranked]))
        )
    }
    return [
        {
            "vulnerability": vulns[cve],
            "asset_count": len(entry["assets"]),
            "standalone_ale": entry["standalone_ale"],
            "reduction": entry["reduction"],
            "assets": sorted(entry["assets"]),
        }
        for cve, entry in ranked
    ]


def severity_breakdown(session: Session) -> list[dict[str, Any]]:
    """ALE by CVSS severity x KEV status. Shows how far the dollar ranking
    departs from a CVSS-only ranking."""
    severity = func.coalesce(Vulnerability.cvss_severity, "UNKNOWN")
    stmt = (
        select(
            severity,
            Vulnerability.kev_flag,
            func.count(RiskScore.id),
            func.avg(RiskScore.ale),
            func.sum(RiskScore.ale),
        )
        .join(RiskScore, RiskScore.cve_id == Vulnerability.cve_id)
        .group_by(severity, Vulnerability.kev_flag)
    )
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    rows = [
        {"severity": sev, "kev_flag": kev, "scenarios": count, "avg_ale": avg, "total_ale": total}
        for sev, kev, count, avg, total in session.execute(stmt).all()
    ]
    return sorted(rows, key=lambda r: (order.get(r["severity"], 9), not r["kev_flag"]))


def cwe_breakdown(session: Session, n: int) -> list[dict[str, Any]]:
    """Weakness classes (CWEs) carrying the most exposure. A CVE with several
    CWEs counts toward each, so these totals overlap and do not sum to the
    portfolio total."""
    stmt = select(Vulnerability.cwe_ids, RiskScore.ale, Vulnerability.cve_id).join(
        RiskScore, RiskScore.cve_id == Vulnerability.cve_id
    )
    totals: dict[str, float] = defaultdict(float)
    cves: dict[str, set[str]] = defaultdict(set)
    for cwe_ids, ale, cve_id in session.execute(stmt).all():
        for cwe in cwe_ids or ["(unclassified)"]:
            totals[cwe] += ale
            cves[cwe].add(cve_id)
    ranked = sorted(totals.items(), key=lambda kv: kv[1], reverse=True)[:n]
    return [{"cwe": cwe, "total_ale": ale, "cve_count": len(cves[cwe])} for cwe, ale in ranked]


def coverage(session: Session) -> dict[str, Any]:
    """How much of the data could actually be scored. A report should say what
    it could NOT see, not just what it found."""
    v = Vulnerability
    row = session.execute(
        select(
            func.count(),
            func.count().filter(v.kev_flag.is_(True)),
            func.count().filter(v.cvss_vector.is_not(None)),
            func.count().filter(v.kev_flag.is_(True), v.cvss_vector.is_(None)),
            func.count().filter(v.known_ransomware_use.is_(True), v.kev_flag.is_(True)),
            func.max(v.kev_date_added),
            func.max(v.nvd_last_modified),
        )
    ).one()
    scores = session.execute(
        select(
            func.count(RiskScore.id),
            func.count(func.distinct(RiskScore.cve_id)),
            func.max(RiskScore.computed_at),
        )
    ).one()
    return {
        "vulnerabilities": row[0],
        "kev": row[1],
        "with_cvss": row[2],
        "kev_without_cvss": row[3],
        "kev_ransomware": row[4],
        "latest_kev_added": row[5],
        "latest_nvd_modified": row[6],
        "scenarios": scores[0],
        "applicable_cves": scores[1],
        "last_scored": scores[2],
    }
