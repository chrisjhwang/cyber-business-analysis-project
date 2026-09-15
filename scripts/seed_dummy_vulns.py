"""Fabricated stand-in for the real ingestion pipeline.

Why this exists: it lets you build and test everything downstream -- the schema,
the upsert behaviour, the scoring engine, the API -- without waiting on NVD rate
limits or debugging someone else's JSON.

What makes it useful rather than throwaway: it writes through the SAME
app.ingest.upsert functions the real KEV and NVD ingesters will use. The only
thing the real ingesters add is the part that fetches JSON over HTTP and maps
feed field names onto these column names. So testing against this data is
genuinely testing the production write path.

The two lists below deliberately do not fully overlap, which reproduces the real
situation:
  - CVEs in KEV but not yet enriched by NVD  -> CVSS columns stay NULL
  - CVEs with CVSS but not in KEV            -> kev_flag stays false
  - CVEs in both                             -> one merged row, written twice

CVE IDs are real; the values attached to them are approximate and hand-entered.
When you switch on live ingestion these rows get corrected in place -- which is
itself a demonstration that the upsert works.

    python -m scripts.seed_dummy_vulns
"""
from datetime import date, datetime

from app.db import session_scope
from app.ingest.upsert import upsert_kev, upsert_nvd

# --- Shaped like what app/ingest/kev.py will produce ----------------------
KEV_ROWS = [
    {
        "cve_id": "CVE-2021-44228",
        "kev_flag": True,
        "kev_date_added": date(2021, 12, 10),
        "kev_due_date": date(2021, 12, 24),
        "known_ransomware_use": True,
        "vendor_project": "Apache",
        "product": "Log4j2",
        "vulnerability_name": "Apache Log4j2 Remote Code Execution Vulnerability",
        "short_description": "Apache Log4j2 contains a JNDI injection vulnerability allowing remote code execution.",
        "cwe_ids": ["CWE-917"],
    },
    {
        "cve_id": "CVE-2017-0144",
        "kev_flag": True,
        "kev_date_added": date(2022, 3, 25),
        "kev_due_date": date(2022, 4, 15),
        "known_ransomware_use": True,
        "vendor_project": "Microsoft",
        "product": "SMBv1",
        "vulnerability_name": "Microsoft SMBv1 Remote Code Execution Vulnerability",
        "short_description": "Microsoft SMBv1 server contains a vulnerability allowing remote code execution (EternalBlue).",
        "cwe_ids": ["CWE-20"],
    },
    {
        "cve_id": "CVE-2019-0708",
        "kev_flag": True,
        "kev_date_added": date(2021, 11, 3),
        "kev_due_date": date(2022, 5, 3),
        "known_ransomware_use": True,
        "vendor_project": "Microsoft",
        "product": "Remote Desktop Services",
        "vulnerability_name": "Microsoft Remote Desktop Services Remote Code Execution Vulnerability",
        "short_description": "Microsoft RDP contains a use-after-free allowing pre-auth remote code execution (BlueKeep).",
        "cwe_ids": ["CWE-416"],
    },
    {
        "cve_id": "CVE-2023-34362",
        "kev_flag": True,
        "kev_date_added": date(2023, 6, 2),
        "kev_due_date": date(2023, 6, 23),
        "known_ransomware_use": True,
        "vendor_project": "Progress",
        "product": "MOVEit Transfer",
        "vulnerability_name": "Progress MOVEit Transfer SQL Injection Vulnerability",
        "short_description": "Progress MOVEit Transfer contains a SQL injection vulnerability leading to escalated privileges.",
        "cwe_ids": ["CWE-89"],
    },
    {
        "cve_id": "CVE-2014-0160",
        "kev_flag": True,
        "kev_date_added": date(2022, 5, 4),
        "kev_due_date": date(2022, 5, 25),
        "known_ransomware_use": False,
        "vendor_project": "OpenSSL",
        "product": "OpenSSL",
        "vulnerability_name": "OpenSSL Information Disclosure Vulnerability",
        "short_description": "OpenSSL contains an out-of-bounds read in the TLS heartbeat extension (Heartbleed).",
        "cwe_ids": ["CWE-125"],
    },
    {
        "cve_id": "CVE-2022-22965",
        "kev_flag": True,
        "kev_date_added": date(2022, 4, 4),
        "kev_due_date": date(2022, 4, 25),
        "known_ransomware_use": True,
        "vendor_project": "VMware",
        "product": "Spring Framework",
        "vulnerability_name": "Spring Framework Remote Code Execution Vulnerability",
        "short_description": "Spring Framework contains a class-loader manipulation flaw allowing remote code execution (Spring4Shell).",
        "cwe_ids": ["CWE-94"],
    },
    {
        "cve_id": "CVE-2021-34527",
        "kev_flag": True,
        "kev_date_added": date(2021, 11, 3),
        "kev_due_date": date(2022, 5, 3),
        "known_ransomware_use": True,
        "vendor_project": "Microsoft",
        "product": "Windows Print Spooler",
        "vulnerability_name": "Microsoft Windows Print Spooler Remote Code Execution Vulnerability",
        "short_description": "Windows Print Spooler contains a vulnerability allowing remote code execution (PrintNightmare).",
        "cwe_ids": ["CWE-269"],
    },
    # --- these three have no NVD row below: CVSS columns stay NULL --------
    {
        "cve_id": "CVE-2020-1472",
        "kev_flag": True,
        "kev_date_added": date(2021, 11, 3),
        "kev_due_date": date(2022, 5, 3),
        "known_ransomware_use": True,
        "vendor_project": "Microsoft",
        "product": "Netlogon",
        "vulnerability_name": "Microsoft Netlogon Privilege Escalation Vulnerability",
        "short_description": "Netlogon contains a cryptographic flaw allowing domain controller takeover (Zerologon).",
        "cwe_ids": ["CWE-330"],
    },
    {
        "cve_id": "CVE-2018-13379",
        "kev_flag": True,
        "kev_date_added": date(2021, 11, 3),
        "kev_due_date": date(2022, 5, 3),
        "known_ransomware_use": True,
        "vendor_project": "Fortinet",
        "product": "FortiOS",
        "vulnerability_name": "Fortinet FortiOS Path Traversal Vulnerability",
        "short_description": "FortiOS SSL VPN contains a path traversal allowing unauthenticated credential disclosure.",
        "cwe_ids": ["CWE-22"],
    },
    {
        "cve_id": "CVE-2023-4966",
        "kev_flag": True,
        "kev_date_added": date(2023, 10, 18),
        "kev_due_date": date(2023, 11, 8),
        "known_ransomware_use": True,
        "vendor_project": "Citrix",
        "product": "NetScaler ADC",
        "vulnerability_name": "Citrix NetScaler Buffer Overflow Vulnerability",
        "short_description": "Citrix NetScaler contains a buffer overflow allowing session token disclosure (CitrixBleed).",
        "cwe_ids": ["CWE-119"],
    },
]

# --- Shaped like what app/ingest/nvd.py will produce ----------------------
# Note CVE-2016-5195 is NOT in KEV_ROWS: it lands with CVSS but kev_flag=false.
NVD_ROWS = [
    {
        "cve_id": "CVE-2021-44228",
        "cvss_score": 10.0,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "cvss_severity": "CRITICAL",
        "published_date": date(2021, 12, 10),
        "nvd_last_modified": datetime(2025, 4, 3, 1, 3, 51),
        "cwe_ids": ["CWE-917", "CWE-20", "CWE-400", "CWE-502"],
    },
    {
        "cve_id": "CVE-2017-0144",
        "cvss_score": 8.1,
        "cvss_vector": "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cvss_severity": "HIGH",
        "published_date": date(2017, 3, 17),
        "nvd_last_modified": datetime(2025, 1, 2, 17, 15, 12),
        "cwe_ids": ["CWE-20"],
    },
    {
        "cve_id": "CVE-2019-0708",
        "cvss_score": 9.8,
        "cvss_vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cvss_severity": "CRITICAL",
        "published_date": date(2019, 5, 16),
        "nvd_last_modified": datetime(2024, 11, 21, 4, 17, 5),
        "cwe_ids": ["CWE-416"],
    },
    {
        "cve_id": "CVE-2023-34362",
        "cvss_score": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cvss_severity": "CRITICAL",
        "published_date": date(2023, 6, 2),
        "nvd_last_modified": datetime(2025, 2, 13, 17, 16, 55),
        "cwe_ids": ["CWE-89"],
    },
    {
        "cve_id": "CVE-2014-0160",
        "cvss_score": 7.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "cvss_severity": "HIGH",
        "published_date": date(2014, 4, 7),
        "nvd_last_modified": datetime(2025, 2, 13, 17, 15, 20),
        "cwe_ids": ["CWE-125"],
    },
    {
        "cve_id": "CVE-2022-22965",
        "cvss_score": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cvss_severity": "CRITICAL",
        "published_date": date(2022, 4, 1),
        "nvd_last_modified": datetime(2024, 11, 21, 6, 47, 32),
        "cwe_ids": ["CWE-94"],
    },
    {
        "cve_id": "CVE-2021-34527",
        "cvss_score": 8.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",
        "cvss_severity": "HIGH",
        "published_date": date(2021, 7, 2),
        "nvd_last_modified": datetime(2024, 11, 21, 6, 10, 33),
        "cwe_ids": ["CWE-269"],
    },
    {
        "cve_id": "CVE-2016-5195",
        "cvss_score": 7.8,
        "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        "cvss_severity": "HIGH",
        "published_date": date(2016, 11, 10),
        "nvd_last_modified": datetime(2025, 4, 12, 10, 46, 40),
        "cwe_ids": ["CWE-362"],
    },
]


def seed_dummy_vulns() -> tuple[int, int]:
    """Run both fake 'ingestions' the way the real ones will run: separately."""
    with session_scope() as session:
        kev_count = upsert_kev(session, KEV_ROWS)
        nvd_count = upsert_nvd(session, NVD_ROWS)
    return kev_count, nvd_count


if __name__ == "__main__":
    kev, nvd = seed_dummy_vulns()
    print(f"upserted {kev} KEV rows, {nvd} NVD rows")
