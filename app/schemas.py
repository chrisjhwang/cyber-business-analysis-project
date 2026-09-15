"""Pydantic schemas: the shape of what the API sends back.

These look like the SQLAlchemy models but do a different job. A model is a
table. A schema is a public contract: it picks which fields leave the server,
and FastAPI uses it to validate responses and generate the /docs page.
`from_attributes=True` lets a schema be built straight from an ORM object.
"""
from datetime import date, datetime

from pydantic import BaseModel, ConfigDict


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class VulnerabilityOut(ORMModel):
    cve_id: str
    cvss_score: float | None
    cvss_vector: str | None
    cvss_severity: str | None
    cvss_version: str | None
    published_date: date | None
    kev_flag: bool
    kev_date_added: date | None
    kev_due_date: date | None
    known_ransomware_use: bool
    vendor_project: str | None
    product: str | None
    vulnerability_name: str | None
    short_description: str | None
    required_action: str | None
    cwe_ids: list[str] | None
    affected_products: list[str] | None
    last_updated: datetime


class AssetOut(ORMModel):
    id: int
    name: str
    type: str
    sensitivity_tier: int
    description: str | None
    technologies: list[str]


class AssetRiskSummary(BaseModel):
    """Asset-level FAIR figures, aggregated with the "one open door" model
    (docs/assumptions.md A7)."""

    scenario_count: int
    kev_count: int
    max_ale: float
    tef: float
    p_any_exploit: float
    expected_loss_events: float
    loss_per_event: float
    total_ale: float
    prob_loss_event: float
    scenario_ale_sum: float  # independent-attacks upper bound, for comparison


class RankedAsset(BaseModel):
    asset: AssetOut
    summary: AssetRiskSummary


class ScenarioOut(BaseModel):
    """One (asset, CVE) risk score with every intermediate FAIR value."""

    asset_id: int
    asset_name: str
    cve_id: str
    vulnerability_name: str | None
    cvss_score: float | None
    cvss_severity: str | None
    kev_flag: bool
    known_ransomware_use: bool
    matched_technology: str
    tef: float
    exploit_probability: float
    lef: float
    primary_loss: float
    secondary_loss: float
    lm: float
    ale: float
    computed_at: datetime


class AssetRiskOut(BaseModel):
    asset: AssetOut
    summary: AssetRiskSummary
    scenarios: list[ScenarioOut]


class RescoreOut(BaseModel):
    assets: int
    vulnerabilities_considered: int
    unscorable: int
    scores_written: int
    stale_removed: int
    computed_at: datetime
