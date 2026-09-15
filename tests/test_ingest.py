"""Ingestion: parsing against RECORDED real API responses (tests/fixtures), plus
idempotency and column-ownership checks against a real Postgres.

No test here touches the network. The fixtures are trimmed copies of actual
CISA KEV and NVD responses, so the parsers are tested against the true shape
of the data, not a guess at it.
"""
import copy
from datetime import date

import pytest
from sqlalchemy import func, select

from app.ingest.kev import ingest_kev, parse_kev_feed
from app.ingest.nvd import MAX_WINDOW_DAYS, build_queries, ingest_nvd, parse_nvd_cve
from app.models import Vulnerability
from tests.conftest import load_fixture


class FakeClient:
    """Stands in for RateLimitedClient: returns queued documents in order."""

    def __init__(self, *docs):
        self.docs = list(docs)
        self.calls = []

    def get_json(self, url, params=None):
        self.calls.append((url, params))
        return self.docs.pop(0)


# --- KEV parsing ------------------------------------------------------------
def test_parse_kev_feed():
    rows = {r["cve_id"]: r for r in parse_kev_feed(load_fixture("kev_sample.json"))}
    assert len(rows) == 3
    log4j = rows["CVE-2021-44228"]
    assert log4j["kev_flag"] is True
    assert log4j["known_ransomware_use"] is True
    assert log4j["vendor_project"] == "Apache"
    assert isinstance(log4j["kev_date_added"], date)
    assert log4j["cwe_ids"]
    assert rows["CVE-2020-29583"]["known_ransomware_use"] is False  # feed says "Unknown"
    # Uniform keys are required for a multi-row INSERT.
    assert len({tuple(sorted(r)) for r in rows.values()}) == 1


def test_parse_kev_feed_rejects_truncated_download():
    doc = load_fixture("kev_sample.json")
    doc["count"] = 1709
    with pytest.raises(ValueError, match="count"):
        parse_kev_feed(doc)


# --- NVD parsing ------------------------------------------------------------
def test_parse_nvd_real_log4j_record():
    cve = load_fixture("nvd_log4j_page.json")["vulnerabilities"][0]["cve"]
    row = parse_nvd_cve(cve)
    assert row["cve_id"] == "CVE-2021-44228"
    assert row["cvss_version"] == "3.1"  # preferred over the v2 metric also present
    assert row["cvss_score"] == 10.0
    assert row["cvss_vector"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
    assert row["cvss_severity"] == "CRITICAL"
    assert row["published_date"] == date(2021, 12, 10)
    assert row["cwe_ids"][0] == "CWE-917"  # NVD's own assignment ordered first
    assert "apache:log4j" in row["affected_products"]


def test_parse_nvd_falls_back_to_v2():
    cve = {
        "id": "CVE-2008-0001",
        "published": "2008-01-02T00:00:00.000",
        "lastModified": "2020-01-01T00:00:00.000",
        "metrics": {"cvssMetricV2": [{
            "type": "Primary", "baseSeverity": "HIGH",
            "cvssData": {"version": "2.0", "vectorString": "AV:N/AC:L/Au:N/C:C/I:C/A:C", "baseScore": 10.0},
        }]},
        "weaknesses": [{"source": "nvd@nist.gov", "description": [{"value": "NVD-CWE-Other"}]}],
    }
    row = parse_nvd_cve(cve)
    assert row["cvss_version"] == "2.0"
    assert row["cvss_severity"] == "HIGH"  # v2 keeps severity outside cvssData
    assert row["cwe_ids"] is None          # placeholder CWE dropped


def test_parse_nvd_skips_rejected_and_tolerates_unscored():
    assert parse_nvd_cve({"id": "CVE-2099-0001", "vulnStatus": "Rejected"}) is None
    row = parse_nvd_cve({"id": "CVE-2099-0002", "vulnStatus": "Awaiting Analysis", "metrics": {}})
    assert row["cvss_vector"] is None and row["affected_products"] is None


def test_build_queries_modes():
    assert build_queries() == [{"hasKev": ""}]
    assert build_queries(cve_ids=["cve-2021-44228"]) == [{"cveId": "CVE-2021-44228"}]
    windows = build_queries(modified_since_days=250)
    assert len(windows) == 3  # 120 + 120 + 10 days
    for q in windows:
        start = date.fromisoformat(q["lastModStartDate"][:10])
        end = date.fromisoformat(q["lastModEndDate"][:10])
        assert (end - start).days <= MAX_WINDOW_DAYS
    for prev, nxt in zip(windows, windows[1:], strict=False):
        assert prev["lastModEndDate"] == nxt["lastModStartDate"]  # contiguous, no gaps


# --- Database behaviour -----------------------------------------------------
def count_vulns(db):
    return db.scalar(select(func.count()).select_from(Vulnerability))


def test_kev_ingest_is_idempotent(db):
    feed = load_fixture("kev_sample.json")
    ingest_kev(db, FakeClient(feed))
    db.commit()
    ingest_kev(db, FakeClient(feed))
    db.commit()
    assert count_vulns(db) == 3


def test_rerunning_kev_does_not_erase_nvd_columns(db):
    """The silent-data-loss bug column ownership exists to prevent."""
    ingest_kev(db, FakeClient(load_fixture("kev_sample.json")))
    ingest_nvd(db, FakeClient(load_fixture("nvd_log4j_page.json")), [{"cveId": "CVE-2021-44228"}])
    ingest_kev(db, FakeClient(load_fixture("kev_sample.json")))
    db.commit()

    log4j = db.get(Vulnerability, "CVE-2021-44228")
    db.refresh(log4j)
    assert log4j.cvss_score == 10.0                # NVD column survived the KEV re-run
    assert "apache:log4j" in log4j.affected_products
    assert log4j.kev_flag is True                  # KEV column intact
    assert log4j.required_action
    assert log4j.cwe_ids[0] == "CWE-917"           # NVD's CWEs win over KEV's


def test_cve_removed_from_kev_is_unflagged(db):
    feed = load_fixture("kev_sample.json")
    ingest_kev(db, FakeClient(feed))

    shrunk = copy.deepcopy(feed)
    shrunk["vulnerabilities"] = [v for v in shrunk["vulnerabilities"] if v["cveID"] != "CVE-2014-0160"]
    shrunk["count"] = len(shrunk["vulnerabilities"])
    result = ingest_kev(db, FakeClient(shrunk))
    db.commit()

    assert result.flags_cleared == 1
    heartbleed = db.get(Vulnerability, "CVE-2014-0160")
    db.refresh(heartbleed)
    assert heartbleed.kev_flag is False
    assert heartbleed.vulnerability_name  # history kept, only the flag flipped


def test_nvd_ingest_follows_pagination(db):
    page1 = load_fixture("nvd_log4j_page.json")
    page2 = copy.deepcopy(page1)
    page2["vulnerabilities"][0]["cve"]["id"] = "CVE-2021-45046"
    for page, start in ((page1, 0), (page2, 1)):
        page.update(totalResults=2, resultsPerPage=1, startIndex=start)

    client = FakeClient(page1, page2)
    result = ingest_nvd(db, client, [{"hasKev": ""}])

    assert result.requests == 2 and result.upserted == 2
    assert [params["startIndex"] for _, params in client.calls] == [0, 1]
    assert count_vulns(db) == 2
