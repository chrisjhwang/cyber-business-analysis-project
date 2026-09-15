"""CISA Known Exploited Vulnerabilities (KEV) ingestion.

KEV answers one question: is this CVE being exploited in the wild right now?
It is a single static JSON file with no auth and no pagination, so the hard
parts are not fetching. They are:
  - trusting the feed only when it is complete (count check below)
  - handling a CVE being REMOVED from the catalog (clear_stale_kev_flags)
  - never touching the CVSS columns NVD owns (enforced in upsert.py)

    python -m app.cli ingest-kev
"""
import logging
from dataclasses import dataclass
from datetime import date
from typing import Any, Protocol

from sqlalchemy.orm import Session

from app.ingest.upsert import clear_stale_kev_flags, upsert_kev

log = logging.getLogger(__name__)

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


class JsonClient(Protocol):
    def get_json(self, url: str, params: dict[str, Any] | None = None) -> Any: ...


@dataclass
class KevResult:
    catalog_version: str | None
    upserted: int
    flags_cleared: int


def _parse_date(value: str | None) -> date | None:
    return date.fromisoformat(value[:10]) if value else None


def parse_kev_entry(entry: dict[str, Any]) -> dict[str, Any]:
    """One feed entry -> one row dict. Every row has the same keys, which a
    multi-row INSERT requires."""
    cwes = [c for c in entry.get("cwes") or [] if c.startswith("CWE-")]
    return {
        "cve_id": entry["cveID"].strip(),
        "kev_flag": True,
        "kev_date_added": _parse_date(entry.get("dateAdded")),
        "kev_due_date": _parse_date(entry.get("dueDate")),
        # The feed says "Known" or "Unknown". Unproven counts as no, see models.py.
        "known_ransomware_use": (entry.get("knownRansomwareCampaignUse") or "").strip().lower()
        == "known",
        "vendor_project": entry.get("vendorProject"),
        "product": entry.get("product"),
        "vulnerability_name": entry.get("vulnerabilityName"),
        "short_description": entry.get("shortDescription"),
        "required_action": entry.get("requiredAction"),
        "cwe_ids": cwes or None,
    }


def parse_kev_feed(doc: dict[str, Any]) -> list[dict[str, Any]]:
    entries = doc["vulnerabilities"]
    declared = doc.get("count")
    # A truncated download would otherwise look like "CISA removed 900 CVEs",
    # and clear_stale_kev_flags would faithfully un-flag all of them.
    if declared is not None and declared != len(entries):
        raise ValueError(f"KEV feed declares count={declared} but contains {len(entries)} entries")
    return [parse_kev_entry(e) for e in entries]


def ingest_kev(session: Session, client: JsonClient) -> KevResult:
    doc = client.get_json(KEV_URL)
    rows = parse_kev_feed(doc)
    upserted = upsert_kev(session, rows)
    cleared = clear_stale_kev_flags(session, {r["cve_id"] for r in rows})
    result = KevResult(doc.get("catalogVersion"), upserted, cleared)
    log.info(
        "KEV catalog %s: upserted %d rows, cleared %d stale flags",
        result.catalog_version, result.upserted, result.flags_cleared,
    )
    return result
