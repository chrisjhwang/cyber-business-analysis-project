from typing import Annotated

from fastapi import APIRouter, Query

from app.deps import DbSession
from app.queries import asset_summaries, top_scenarios
from app.routers.serialize import ranked_asset_out, scenario_out
from app.schemas import RankedAsset, RescoreOut, ScenarioOut
from app.scoring.engine import rescore

router = APIRouter(tags=["risk"])


@router.get("/risk/top", response_model=list[RankedAsset])
def top_assets(db: DbSession, n: Annotated[int, Query(ge=1, le=100)] = 5):
    """Top-N riskiest assets by total annualized loss expectancy."""
    return [ranked_asset_out(s) for s in asset_summaries(db)[:n]]


@router.get("/risk/scenarios", response_model=list[ScenarioOut])
def top_risk_scenarios(db: DbSession, n: Annotated[int, Query(ge=1, le=500)] = 20):
    """Top-N individual (asset, CVE) scenarios by ALE, across all assets."""
    return [scenario_out(*row) for row in top_scenarios(db, n)]


@router.post("/rescore", response_model=RescoreOut)
def trigger_rescore(db: DbSession):
    """Recompute every risk score from the current vulnerabilities and assets."""
    result = rescore(db)
    db.commit()
    return RescoreOut(**vars(result))
