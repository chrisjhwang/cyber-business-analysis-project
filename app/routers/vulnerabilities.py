from typing import Annotated

from fastapi import APIRouter, HTTPException, Query, Response
from sqlalchemy import func, or_, select

from app.deps import DbSession
from app.models import Vulnerability
from app.schemas import VulnerabilityOut

router = APIRouter(prefix="/vulnerabilities", tags=["vulnerabilities"])


@router.get("", response_model=list[VulnerabilityOut])
def list_vulnerabilities(
    db: DbSession,
    response: Response,
    kev_flag: bool | None = None,
    min_cvss: Annotated[float | None, Query(ge=0, le=10)] = None,
    search: Annotated[str | None, Query(description="Matches vendor, product or name")] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
):
    """List CVEs, most severe first. Total match count is in `X-Total-Count`."""
    stmt = select(Vulnerability)
    if kev_flag is not None:
        stmt = stmt.where(Vulnerability.kev_flag.is_(kev_flag))
    if min_cvss is not None:
        stmt = stmt.where(Vulnerability.cvss_score >= min_cvss)
    if search:
        pattern = f"%{search}%"
        stmt = stmt.where(or_(
            Vulnerability.vendor_project.ilike(pattern),
            Vulnerability.product.ilike(pattern),
            Vulnerability.vulnerability_name.ilike(pattern),
            Vulnerability.cve_id.ilike(pattern),
        ))

    total = db.scalar(select(func.count()).select_from(stmt.subquery()))
    response.headers["X-Total-Count"] = str(total)
    stmt = (
        stmt.order_by(Vulnerability.cvss_score.desc().nulls_last(), Vulnerability.cve_id)
        .limit(limit)
        .offset(offset)
    )
    return db.scalars(stmt).all()


@router.get("/{cve_id}", response_model=VulnerabilityOut)
def get_vulnerability(cve_id: str, db: DbSession):
    vuln = db.get(Vulnerability, cve_id.upper())
    if vuln is None:
        raise HTTPException(status_code=404, detail=f"{cve_id} not found")
    return vuln
