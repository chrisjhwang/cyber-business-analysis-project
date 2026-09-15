"""Build the executive cyber-risk report from the database.

build_report() gathers every number once, as plain data. Two Jinja templates
render that data as Markdown (to edit into your own write-up) and HTML (served
at /report). Neither template runs a query, so both show identical figures.

    python -m app.cli report
"""
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape
from sqlalchemy.orm import Session

from app import queries
from app.scoring import fair_lite

TEMPLATE_DIR = Path(__file__).parent / "templates"
TOP_SCENARIOS = 15
TOP_REMEDIATIONS = 10
SCENARIOS_PER_ASSET = 5
TOP_CWES = 10


@dataclass
class Report:
    generated_at: datetime
    coverage: dict[str, Any]
    portfolio: dict[str, Any]
    assets: list[queries.AssetSummary]
    top_scenarios: list[tuple]
    remediations: list[dict[str, Any]]
    asset_details: list[dict[str, Any]]
    severity: list[dict[str, Any]]
    cwes: list[dict[str, Any]]
    assumptions: dict[str, Any] = field(default_factory=dict)


def build_report(session: Session) -> Report:
    assets = queries.asset_summaries(session)
    remediations = queries.remediation_priorities(session, TOP_REMEDIATIONS, summaries=assets)
    total_ale = sum(a.total_ale for a in assets)
    scored = [a for a in assets if a.scenario_count]
    # "What if we patched the whole top-N list?" Needs a full recompute, because
    # the reductions of individual CVEs on the same asset do not add up.
    after_top = queries.asset_summaries(
        session, exclude_cves=[r["vulnerability"].cve_id for r in remediations]
    )
    reduction = total_ale - sum(a.total_ale for a in after_top)

    portfolio = {
        "total_ale": total_ale,
        "scenario_ale_sum": sum(a.scenario_ale_sum for a in assets),
        "asset_count": len(assets),
        "assets_exposed": len(scored),
        "riskiest": scored[0] if scored else None,
        "top_remediation_reduction": reduction,
        "top_remediation_share": reduction / total_ale if total_ale else 0.0,
    }

    return Report(
        generated_at=datetime.now(UTC),
        coverage=queries.coverage(session),
        portfolio=portfolio,
        assets=assets,
        top_scenarios=queries.top_scenarios(session, TOP_SCENARIOS),
        remediations=remediations,
        asset_details=[
            {"summary": a, "scenarios": queries.top_scenarios(session, SCENARIOS_PER_ASSET, a.asset.id)}
            for a in scored
        ],
        severity=queries.severity_breakdown(session),
        cwes=queries.cwe_breakdown(session, TOP_CWES),
        assumptions={
            "benchmark": fair_lite.BREACH_COST_BENCHMARK,
            "primary_share": fair_lite.PRIMARY_LOSS_SHARE,
            "secondary_share": fair_lite.SECONDARY_LOSS_SHARE,
            "non_kev_scale": fair_lite.NON_KEV_EXPLOIT_SCALE,
            "kev_multiplier": fair_lite.KEV_MULTIPLIER,
            "ransomware_multiplier": fair_lite.RANSOMWARE_TEF_MULTIPLIER,
            "tef": fair_lite.THREAT_EVENT_FREQUENCY,
        },
    )


# --- formatting filters -----------------------------------------------------
def money(value: float | None) -> str:
    if value is None:
        return "–"
    for threshold, suffix in ((1e9, "B"), (1e6, "M"), (1e3, "K")):
        if abs(value) >= threshold:
            return f"${value / threshold:,.2f}{suffix}"
    return f"${value:,.0f}"


def pct(value: float | None, digits: int = 1) -> str:
    return "–" if value is None else f"{value * 100:.{digits}f}%"


def num(value: float | None, digits: int = 2) -> str:
    return "–" if value is None else f"{value:,.{digits}f}"


def datefmt(value: date | datetime | None) -> str:
    if value is None:
        return "–"
    return value.strftime("%Y-%m-%d %H:%M UTC") if isinstance(value, datetime) else value.isoformat()


def md_escape(value: Any) -> str:
    """Pipes would break Markdown table cells."""
    return "" if value is None else str(value).replace("|", "\\|").replace("\n", " ")


def _env(autoescape: bool) -> Environment:
    env = Environment(
        loader=FileSystemLoader(TEMPLATE_DIR),
        autoescape=select_autoescape(["html"]) if autoescape else False,
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.filters.update(money=money, pct=pct, num=num, datefmt=datefmt, md=md_escape)
    return env


def render_markdown(report: Report) -> str:
    return _env(autoescape=False).get_template("report.md.j2").render(r=report)


def render_html(report: Report) -> str:
    return _env(autoescape=True).get_template("report.html.j2").render(r=report)
