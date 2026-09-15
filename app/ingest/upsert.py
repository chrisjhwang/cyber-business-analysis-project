"""Idempotent writes into `vulnerabilities`.

This module is the only place that writes to that table. Both ingesters (and
the dummy-data seeder) go through it, so "running it twice changes nothing" is
a property of one piece of code rather than something each caller has to
remember.

The important idea: a row in `vulnerabilities` is co-owned. KEV knows whether a
CVE is being exploited; NVD knows how severe it is technically. Each upsert
below lists ONLY the columns its source owns in the DO UPDATE SET clause. If
KEV's upsert set every column, re-running it after NVD had populated the CVSS
data would overwrite those columns with NULL -- the row would still exist, no
error would be raised, and the data would silently be gone.
"""
from collections.abc import Iterable
from typing import Any

from sqlalchemy import func, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app.models import Vulnerability

# Columns each source is allowed to overwrite on conflict.
KEV_OWNED = (
    "kev_flag",
    "kev_date_added",
    "kev_due_date",
    "known_ransomware_use",
    "vendor_project",
    "product",
    "vulnerability_name",
    "short_description",
    "required_action",
)
NVD_OWNED = (
    "cvss_score",
    "cvss_vector",
    "cvss_severity",
    "cvss_version",
    "published_date",
    "nvd_last_modified",
    "affected_products",
)

# Postgres caps one statement at 65,535 bind parameters. 500 rows x ~17
# columns stays well under that.
BATCH_SIZE = 500


def _dedupe(rows: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Last row wins per cve_id. Postgres refuses an ON CONFLICT statement that
    would update the same row twice ("cannot affect row a second time")."""
    return list({row["cve_id"]: row for row in rows}.values())


def _upsert(session: Session, rows: Iterable[dict[str, Any]], owned: tuple[str, ...],
            cwe_wins: bool) -> int:
    """Insert rows, updating only `owned` columns when the cve_id already exists.

    cwe_wins: both feeds carry CWEs. NVD's are authoritative, so its upsert
    overwrites; KEV's only fill the column in when it is still empty.
    """
    rows = _dedupe(rows)
    for start in range(0, len(rows), BATCH_SIZE):
        stmt = insert(Vulnerability).values(rows[start:start + BATCH_SIZE])

        # `stmt.excluded` is the row Postgres *would have* inserted -- the standard
        # way to reference the incoming values inside DO UPDATE.
        set_ = {col: getattr(stmt.excluded, col) for col in owned}
        set_["cwe_ids"] = (
            stmt.excluded.cwe_ids
            if cwe_wins
            else func.coalesce(Vulnerability.cwe_ids, stmt.excluded.cwe_ids)
        )
        # onupdate= on the model only fires for ORM flushes, not Core ON CONFLICT.
        set_["last_updated"] = func.now()

        session.execute(stmt.on_conflict_do_update(index_elements=["cve_id"], set_=set_))
    return len(rows)


def upsert_kev(session: Session, rows: Iterable[dict[str, Any]]) -> int:
    """Write KEV-sourced facts. Never touches CVSS columns."""
    return _upsert(session, rows, KEV_OWNED, cwe_wins=False)


def upsert_nvd(session: Session, rows: Iterable[dict[str, Any]]) -> int:
    """Write NVD-sourced facts. Never touches KEV columns."""
    return _upsert(session, rows, NVD_OWNED, cwe_wins=True)


def clear_stale_kev_flags(session: Session, current_cve_ids: set[str]) -> int:
    """Un-flag CVEs that are no longer in the KEV catalog.

    An upsert can only ADD or CHANGE facts. It cannot notice that something
    vanished from the feed, so without this a CVE CISA removed would stay
    flagged forever. The KEV-specific columns are kept as history; only the
    flag the scoring engine reads is flipped.
    """
    if not current_cve_ids:
        # An empty set would un-flag everything. That is a broken feed, not news.
        raise ValueError("refusing to clear KEV flags against an empty catalog")
    result = session.execute(
        update(Vulnerability)
        .where(Vulnerability.kev_flag.is_(True), Vulnerability.cve_id.not_in(current_cve_ids))
        .values(kev_flag=False, last_updated=func.now())
    )
    return result.rowcount
