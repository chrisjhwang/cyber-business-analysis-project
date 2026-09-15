"""Convert query results into response schemas. Shared by the routers."""
from app.models import Asset, RiskScore, Vulnerability
from app.queries import AssetSummary
from app.schemas import AssetOut, AssetRiskSummary, RankedAsset, ScenarioOut


def summary_out(s: AssetSummary) -> AssetRiskSummary:
    return AssetRiskSummary(
        scenario_count=s.scenario_count,
        kev_count=s.kev_count,
        max_ale=s.max_ale,
        tef=s.aggregate.tef,
        p_any_exploit=s.aggregate.p_any,
        expected_loss_events=s.expected_loss_events,
        loss_per_event=s.aggregate.lm,
        total_ale=s.total_ale,
        prob_loss_event=s.prob_loss_event,
        scenario_ale_sum=s.scenario_ale_sum,
    )


def ranked_asset_out(s: AssetSummary) -> RankedAsset:
    return RankedAsset(asset=AssetOut.model_validate(s.asset), summary=summary_out(s))


def scenario_out(score: RiskScore, vuln: Vulnerability, asset: Asset) -> ScenarioOut:
    return ScenarioOut(
        asset_id=asset.id,
        asset_name=asset.name,
        cve_id=vuln.cve_id,
        vulnerability_name=vuln.vulnerability_name,
        cvss_score=vuln.cvss_score,
        cvss_severity=vuln.cvss_severity,
        kev_flag=vuln.kev_flag,
        known_ransomware_use=vuln.known_ransomware_use,
        matched_technology=score.matched_technology,
        tef=score.tef,
        exploit_probability=score.exploit_probability,
        lef=score.lef,
        primary_loss=score.primary_loss,
        secondary_loss=score.secondary_loss,
        lm=score.lm,
        ale=score.ale,
        computed_at=score.computed_at,
    )
