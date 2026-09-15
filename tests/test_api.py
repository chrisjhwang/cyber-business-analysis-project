"""API tests through FastAPI's TestClient, against the test database."""
import pytest

from app.scoring.engine import rescore
from tests.factories import HEARTBLEED_VECTOR, add_asset, add_vuln


@pytest.fixture
def seeded(db):
    payment = add_asset(db, "payment API", technologies=["apache:log4j"])
    warehouse = add_asset(db, "analytics warehouse", type="database", sensitivity_tier=2,
                          technologies=["openssl:openssl"])
    add_asset(db, "marketing site", type="web_app", sensitivity_tier=1, technologies=["drupal:drupal"])
    add_vuln(db, "CVE-2021-44228", name="Apache Log4j2 Remote Code Execution")
    add_vuln(db, "CVE-2014-0160", vector=HEARTBLEED_VECTOR, score=7.5, severity="HIGH",
             kev=False, ransomware=False, affected=["openssl:openssl"], cwe_ids=["CWE-125"])
    rescore(db)
    db.commit()
    return {"payment": payment, "warehouse": warehouse}


def test_health(client):
    assert client.get("/health").json() == {"status": "ok"}


def test_list_vulnerabilities_filters(client, seeded):
    response = client.get("/vulnerabilities", params={"kev_flag": True})
    assert response.status_code == 200
    assert [v["cve_id"] for v in response.json()] == ["CVE-2021-44228"]
    assert response.headers["X-Total-Count"] == "1"

    by_score = client.get("/vulnerabilities", params={"min_cvss": 8}).json()
    assert [v["cve_id"] for v in by_score] == ["CVE-2021-44228"]

    assert client.get("/vulnerabilities", params={"search": "log4j"}).json()[0]["cve_id"] == "CVE-2021-44228"


def test_list_vulnerabilities_validates_query_params(client):
    assert client.get("/vulnerabilities", params={"min_cvss": 11}).status_code == 422
    assert client.get("/vulnerabilities", params={"limit": 0}).status_code == 422


def test_get_vulnerability(client, seeded):
    assert client.get("/vulnerabilities/cve-2021-44228").json()["cvss_score"] == 10.0
    assert client.get("/vulnerabilities/CVE-1999-9999").status_code == 404


def test_asset_risk(client, seeded):
    body = client.get(f"/assets/{seeded['payment'].id}/risk").json()
    assert body["asset"]["name"] == "payment API"
    assert body["summary"]["scenario_count"] == 1
    assert body["summary"]["kev_count"] == 1
    scenario = body["scenarios"][0]
    assert scenario["cve_id"] == "CVE-2021-44228"
    assert scenario["ale"] == pytest.approx(2_635_200)
    assert scenario["lef"] * scenario["lm"] == pytest.approx(scenario["ale"])
    assert client.get("/assets/9999/risk").status_code == 404


def test_top_assets_ranked_by_ale(client, seeded):
    ranked = client.get("/risk/top", params={"n": 3}).json()
    assert [r["asset"]["name"] for r in ranked] == ["payment API", "analytics warehouse", "marketing site"]
    assert ranked[2]["summary"]["total_ale"] == 0  # no applicable CVEs is still listed


def test_top_scenarios(client, seeded):
    scenarios = client.get("/risk/scenarios", params={"n": 10}).json()
    assert len(scenarios) == 2
    assert scenarios[0]["ale"] >= scenarios[1]["ale"]


def test_rescore_endpoint(client, seeded):
    body = client.post("/rescore").json()
    assert body["scores_written"] == 2
    assert body["stale_removed"] == 0


def test_report_renders(client, seeded):
    html = client.get("/report")
    assert html.status_code == 200
    assert "payment API" in html.text and "CVE-2021-44228" in html.text

    md = client.get("/report.md")
    assert md.headers["content-type"].startswith("text/markdown")
    assert md.text.startswith("# Cyber Risk Quantification Report")
    assert "## 3. Remediation priorities" in md.text


def test_report_renders_on_empty_database(client):
    assert "No vulnerability-to-asset scenarios" in client.get("/report.md").text


def test_remediation_reduction_is_small_when_other_doors_remain(db):
    """Patching one of many exploitable CVEs barely moves asset ALE."""
    from app.queries import remediation_priorities

    add_asset(db, "auth", technologies=["apache:log4j"])
    for i in range(20):
        add_vuln(db, f"CVE-2021-{40000 + i}")
    rescore(db)
    db.commit()

    top = remediation_priorities(db, 1)[0]
    assert top["standalone_ale"] == pytest.approx(2_635_200)
    assert top["reduction"] < 0.01 * top["standalone_ale"]
