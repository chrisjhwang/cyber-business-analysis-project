"""NVD CVE API 2.0 ingestion.

NVD answers a different question from KEV: how severe is this CVE
technically, and what software does it affect? Three query modes:

  default               every CVE in CISA KEV (hasKev filter), about 1-2 pages
  --cve CVE-...         specific CVEs, one request each
  --modified-since-days N
                        everything NVD changed in the last N days (non-KEV too)

    python -m app.cli ingest-nvd

Rate limits: 5 requests / 30s without an API key, 50 / 30s with one. The
client paces itself below that and backs off if NVD still pushes back.
"""
import logging
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from typing import Any

from sqlalchemy.orm import Session

from app.ingest.http import RateLimitedClient
from app.ingest.kev import JsonClient
from app.ingest.upsert import upsert_nvd

log = logging.getLogger(__name__)

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
PAGE_SIZE = 2000        # NVD maximum
MAX_WINDOW_DAYS = 120   # NVD rejects date ranges longer than this

# Seconds between requests: 30s/50 and 30s/5, plus a safety margin.
INTERVAL_WITH_KEY = 0.7
INTERVAL_WITHOUT_KEY = 6.5

# Newest scoring system NVD has analysed first. v4 sits below v3 because
# NVD's own analysts still publish v3.1 as the primary score for most CVEs.
METRIC_PREFERENCE = ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40", "cvssMetricV2")


@dataclass
class NvdResult:
    requests: int
    upserted: int
    skipped: int


def make_nvd_client(api_key: str | None) -> RateLimitedClient:
    return RateLimitedClient(
        min_interval=INTERVAL_WITH_KEY if api_key else INTERVAL_WITHOUT_KEY,
        headers={"apiKey": api_key} if api_key else None,
    )


# --- parsing (pure) ----------------------------------------------------------
def _pick_metric(metrics: dict[str, Any]) -> dict[str, Any] | None:
    for key in METRIC_PREFERENCE:
        entries = metrics.get(key) or []
        if entries:
            # "Primary" is NVD's own assessment. "Secondary" comes from the
            # vendor or CNA, used only when NVD has not scored the CVE itself.
            return next((m for m in entries if m.get("type") == "Primary"), entries[0])
    return None


def _cwes(cve: dict[str, Any]) -> list[str]:
    # NVD's own CWE assignments first, then the CNA's. Drop the placeholder
    # values NVD uses for "unclassifiable".
    weaknesses = sorted(cve.get("weaknesses") or [], key=lambda w: w.get("source") != "nvd@nist.gov")
    found: list[str] = []
    for weakness in weaknesses:
        for desc in weakness.get("description") or []:
            value = desc.get("value", "")
            if value.startswith("CWE-") and value not in found:
                found.append(value)
    return found


def _affected_products(cve: dict[str, Any]) -> list[str]:
    """cpe:2.3:a:apache:log4j:2.0:... -> "apache:log4j", vulnerable entries only."""
    found: set[str] = set()
    for config in cve.get("configurations") or []:
        for node in config.get("nodes") or []:
            for match in node.get("cpeMatch") or []:
                if not match.get("vulnerable"):
                    continue  # platform context ("runs on Windows"), not the flaw itself
                parts = match.get("criteria", "").split(":")
                if len(parts) > 4:
                    found.add(f"{parts[3]}:{parts[4]}")
    return sorted(found)


def parse_nvd_cve(cve: dict[str, Any]) -> dict[str, Any] | None:
    """One NVD `cve` object -> one row dict, or None for rejected CVEs."""
    if cve.get("vulnStatus") == "Rejected":
        return None
    metric = _pick_metric(cve.get("metrics") or {})
    data = metric["cvssData"] if metric else {}
    published = cve.get("published")
    modified = cve.get("lastModified")
    return {
        "cve_id": cve["id"],
        "cvss_score": data.get("baseScore"),
        "cvss_vector": data.get("vectorString"),
        # v3/v4 put severity inside cvssData, v2 one level up.
        "cvss_severity": data.get("baseSeverity") or (metric or {}).get("baseSeverity"),
        "cvss_version": data.get("version"),
        "published_date": date.fromisoformat(published[:10]) if published else None,
        "nvd_last_modified": datetime.fromisoformat(modified).replace(tzinfo=None)
        if modified
        else None,
        "cwe_ids": _cwes(cve) or None,
        "affected_products": _affected_products(cve) or None,
    }


def build_queries(
    *,
    cve_ids: Iterable[str] | None = None,
    modified_since_days: int | None = None,
    now: datetime | None = None,
) -> list[dict[str, Any]]:
    """Turn CLI options into NVD query-parameter sets (pagination added later)."""
    if cve_ids:
        return [{"cveId": c.strip().upper()} for c in cve_ids]
    if modified_since_days:
        end = (now or datetime.now(UTC)).replace(tzinfo=None)
        start = end - timedelta(days=modified_since_days)
        queries = []
        while start < end:
            window_end = min(start + timedelta(days=MAX_WINDOW_DAYS), end)
            queries.append({
                "lastModStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
                "lastModEndDate": window_end.strftime("%Y-%m-%dT%H:%M:%S.000"),
            })
            start = window_end
        return queries
    # hasKev takes no value. httpx sends it as "hasKev=", which NVD accepts.
    return [{"hasKev": ""}]


# --- ingestion (I/O) ---------------------------------------------------------
def ingest_nvd(session: Session, client: JsonClient, queries: list[dict[str, Any]]) -> NvdResult:
    """Fetch every page of every query and upsert it.

    Commits after each page. A crash 40 minutes into a long run then keeps the
    first 40 minutes of work, and because upserts are idempotent, re-running
    just redoes the rest.
    """
    result = NvdResult(requests=0, upserted=0, skipped=0)
    for base in queries:
        start = 0
        while True:
            doc = client.get_json(
                NVD_URL, params={**base, "resultsPerPage": PAGE_SIZE, "startIndex": start}
            )
            result.requests += 1
            items = doc.get("vulnerabilities") or []
            rows = [row for row in (parse_nvd_cve(item["cve"]) for item in items) if row]
            result.skipped += len(items) - len(rows)
            result.upserted += upsert_nvd(session, rows)
            session.commit()

            total = doc.get("totalResults", 0)
            start += len(items)
            log.info("NVD %s: %d/%d", base or "query", start, total)
            if not items or start >= total:
                break
    return result
