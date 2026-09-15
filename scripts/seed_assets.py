"""Populate the curated asset list.

Assets are inputs to the risk model, not observed data -- they are hand-written
here rather than ingested from anywhere. Deliberately small (Section 4 of
PLAN.md): the point is to demonstrate the FAIR translation layer, not to build
an asset-management system.

Re-runnable: upserts on `name`, so running it twice updates the same eight rows
instead of creating sixteen.

    python -m scripts.seed_assets
"""
from sqlalchemy.dialects.postgresql import insert

from app.db import session_scope
from app.models import Asset

# technologies: the software each asset runs, in NVD CPE "vendor:product" naming.
# A CVE is only scored against an asset whose stack it affects. These stacks are
# illustrative -- a fictional mid-size fintech -- chosen so the platform has real
# KEV entries to find. Edit them to model a different organization, then rescore.
#
# sensitivity_tier: 1 low / 2 moderate / 3 high. Drives the secondary-loss
# multiplier in FAIR-lite -- how badly a breach here hurts beyond direct costs
# (regulatory fines, customer churn, reputational damage).
ASSETS = [
    {
        "name": "customer database",
        "type": "database",
        "sensitivity_tier": 3,
        "description": "Primary customer PII store. Breach triggers regulatory notification.",
        "technologies": ["oracle:database_server", "microsoft:sql_server", "postgresql:postgresql", "vmware:esxi", "linux:linux_kernel"],
    },
    {
        "name": "payment API",
        "type": "api",
        "sensitivity_tier": 3,
        "description": "Card processing path. In PCI-DSS scope.",
        "technologies": ["apache:log4j", "vmware:spring_framework", "apache:struts", "f5:big-ip", "apache:tomcat"],
    },
    {
        "name": "authentication service",
        "type": "api",
        "sensitivity_tier": 3,
        "description": "Issues session tokens. Compromise implies lateral access everywhere.",
        "technologies": ["microsoft:windows_server", "citrix:netscaler", "ivanti:connect_secure", "pulsesecure:pulse_connect_secure", "fortinet:fortios"],
    },
    {
        "name": "employee HR portal",
        "type": "internal_tool",
        "sensitivity_tier": 2,
        "description": "Salary and personnel records. Internal-only, staff-wide access.",
        "technologies": ["microsoft:sharepoint_server", "sap:netweaver", "oracle:e-business_suite", "microsoft:exchange_server"],
    },
    {
        "name": "internal admin panel",
        "type": "internal_tool",
        "sensitivity_tier": 2,
        "description": "Privileged operational tooling, VPN-gated.",
        "technologies": ["atlassian:confluence", "atlassian:jira", "zohocorp:manageengine", "vmware:vcenter_server"],
    },
    {
        "name": "analytics warehouse",
        "type": "database",
        "sensitivity_tier": 2,
        "description": "Aggregated behavioural data, largely de-identified.",
        "technologies": ["apache:activemq", "apache:spark", "elastic:elasticsearch", "apache:hadoop", "linux:linux_kernel"],
    },
    {
        "name": "public marketing site",
        "type": "web_app",
        "sensitivity_tier": 1,
        "description": "Static content. Defacement is reputational, not a data loss.",
        "technologies": ["wordpress:wordpress", "drupal:drupal", "apache:http_server", "php:php"],
    },
    {
        "name": "developer CI runners",
        "type": "infrastructure",
        "sensitivity_tier": 2,
        "description": "Build fleet holding deploy credentials. Supply-chain relevant.",
        "technologies": ["jenkins:jenkins", "gitlab:gitlab", "jetbrains:teamcity", "docker:docker", "linux:linux_kernel"],
    },
]


def seed_assets() -> int:
    with session_scope() as session:
        stmt = insert(Asset).values(ASSETS)
        stmt = stmt.on_conflict_do_update(
            index_elements=["name"],
            set_={
                "type": stmt.excluded.type,
                "sensitivity_tier": stmt.excluded.sensitivity_tier,
                "description": stmt.excluded.description,
                "technologies": stmt.excluded.technologies,
            },
        )
        session.execute(stmt)
    return len(ASSETS)


if __name__ == "__main__":
    print(f"seeded {seed_assets()} assets")
