from typing import Annotated

from fastapi import APIRouter, HTTPException, Query
from sqlalchemy import select

from app.deps import DbSession
from app.models import Asset
from app.queries import asset_summaries, top_scenarios
from app.routers.serialize import scenario_out, summary_out
from app.schemas import AssetOut, AssetRiskOut

router = APIRouter(prefix="/assets", tags=["assets"])


@router.get("", response_model=list[AssetOut])
def list_assets(db: DbSession):
    return db.scalars(select(Asset).order_by(Asset.id)).all()


@router.get("/{asset_id}/risk", response_model=AssetRiskOut)
def get_asset_risk(
    asset_id: int,
    db: DbSession,
    limit: Annotated[int, Query(ge=1, le=500)] = 20,
):
    """An asset's aggregate exposure plus its highest-ALE scenarios."""
    summaries = asset_summaries(db, asset_id=asset_id)
    if not summaries:
        raise HTTPException(status_code=404, detail=f"asset {asset_id} not found")
    summary = summaries[0]
    return AssetRiskOut(
        asset=AssetOut.model_validate(summary.asset),
        summary=summary_out(summary),
        scenarios=[scenario_out(*row) for row in top_scenarios(db, limit, asset_id=asset_id)],
    )
