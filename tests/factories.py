"""Tiny helpers for building rows in DB tests."""
from sqlalchemy.orm import Session

from app.models import Asset, Vulnerability

LOG4J_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
HEARTBLEED_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"


def add_asset(
    db: Session,
    name: str = "payment API",
    type: str = "api",
    sensitivity_tier: int = 3,
    technologies: list[str] | None = None,
) -> Asset:
    asset = Asset(
        name=name,
        type=type,
        sensitivity_tier=sensitivity_tier,
        technologies=technologies if technologies is not None else ["apache:log4j"],
    )
    db.add(asset)
    db.flush()
    return asset


def add_vuln(
    db: Session,
    cve_id: str,
    *,
    vector: str | None = LOG4J_VECTOR,
    score: float | None = 10.0,
    severity: str | None = "CRITICAL",
    kev: bool = True,
    ransomware: bool = True,
    affected: list[str] | None = None,
    name: str | None = None,
    cwe_ids: list[str] | None = None,
) -> Vulnerability:
    vuln = Vulnerability(
        cve_id=cve_id,
        cvss_vector=vector,
        cvss_score=score,
        cvss_severity=severity,
        kev_flag=kev,
        known_ransomware_use=ransomware,
        affected_products=affected if affected is not None else ["apache:log4j"],
        vulnerability_name=name or f"{cve_id} test vulnerability",
        cwe_ids=cwe_ids or ["CWE-917"],
    )
    db.add(vuln)
    db.flush()
    return vuln
