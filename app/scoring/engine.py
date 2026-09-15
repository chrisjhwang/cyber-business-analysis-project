"""The thin, impure layer around fair_lite: read DB -> score -> write DB.

All the maths lives in fair_lite.py and applicability.py. This module only
loops over (asset, vulnerability) pairs and persists the results, which is why
it has no formulas in it.

    python -m app.cli rescore      or      POST /rescore
"""
import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app.models import Asset, RiskScore, Vulnerability
from app.scoring.applicability import match_technology, parse_technologies, product_candidates
from app.scoring.fair_lite import parse_vector, score_scenario

log = logging.getLogger(__name__)

BATCH_SIZE = 1000
SCORE_COLUMNS = (
    "matched_technology", "tef", "exploit_probability", "lef",
    "primary_loss", "secondary_loss", "lm", "ale", "computed_at",
)


@dataclass
class RescoreResult:
    assets: int
    vulnerabilities_considered: int
    unscorable: int
    scores_written: int
    stale_removed: int
    computed_at: datetime


def rescore(session: Session) -> RescoreResult:
    """Recompute every applicable (asset, CVE) score from current DB state.

    Idempotent. Rows are upserted on the (asset_id, cve_id) unique constraint,
    all stamped with one `computed_at`. Afterwards, any row with an older stamp
    is a pair that no longer applies (asset stack changed, CVE lost its CVSS
    data) and is deleted, so the table always matches what one fresh run would
    produce.
    """
    computed_at = datetime.now(UTC).replace(tzinfo=None)
    assets = session.scalars(select(Asset)).all()
    asset_techs = [(asset, parse_technologies(asset.technologies or [])) for asset in assets]

    vulns = session.execute(
        select(
            Vulnerability.cve_id,
            Vulnerability.cvss_vector,
            Vulnerability.kev_flag,
            Vulnerability.known_ransomware_use,
            Vulnerability.vendor_project,
            Vulnerability.product,
            Vulnerability.affected_products,
        )
    ).all()

    rows: list[dict[str, Any]] = []
    unscorable = 0
    for v in vulns:
        try:
            factors = parse_vector(v.cvss_vector)
        except ValueError:
            # No CVSS yet (NVD analysis backlog) or an unparseable vector. A
            # guessed score would be worse than an honest gap in the report.
            unscorable += 1
            continue
        candidates = product_candidates(v.vendor_project, v.product, v.affected_products)
        for asset, techs in asset_techs:
            matched = match_technology(techs, candidates)
            if matched is None:
                continue
            b = score_scenario(
                factors=factors,
                kev_flag=v.kev_flag,
                known_ransomware_use=v.known_ransomware_use,
                asset_type=asset.type,
                sensitivity_tier=asset.sensitivity_tier,
            )
            rows.append({
                "asset_id": asset.id,
                "cve_id": v.cve_id,
                "matched_technology": matched,
                "tef": b.tef,
                "exploit_probability": b.exploit_probability,
                "lef": b.lef,
                "primary_loss": b.primary_loss,
                "secondary_loss": b.secondary_loss,
                "lm": b.lm,
                "ale": b.ale,
                "computed_at": computed_at,
            })

    for start in range(0, len(rows), BATCH_SIZE):
        stmt = insert(RiskScore).values(rows[start:start + BATCH_SIZE])
        stmt = stmt.on_conflict_do_update(
            constraint="uq_risk_scores_asset_cve",
            set_={col: getattr(stmt.excluded, col) for col in SCORE_COLUMNS},
        )
        session.execute(stmt)

    stale = session.execute(delete(RiskScore).where(RiskScore.computed_at < computed_at))

    result = RescoreResult(
        assets=len(assets),
        vulnerabilities_considered=len(vulns),
        unscorable=unscorable,
        scores_written=len(rows),
        stale_removed=stale.rowcount,
        computed_at=computed_at,
    )
    log.info("rescore: %s", result)
    return result
