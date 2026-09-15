"""Does this CVE affect this asset?

Without this step every CVE gets scored against every asset, so a Windows SMB
bug adds dollars to a Linux marketing site and the totals mean nothing. Each
asset instead declares the software it runs as "vendor:product" tokens, using
the same vendor/product names NVD uses in CPE identifiers
(cpe:2.3:a:<vendor>:<product>:...). A CVE applies to an asset when any
declared technology matches any product the CVE affects.

Matching is a PREFIX match on the product, so "microsoft:windows_server"
matches NVD's "microsoft:windows_server_2019". "vendor:*" matches every product
from that vendor. Pure functions only, like fair_lite.py.
"""
from collections.abc import Iterable

Technology = tuple[str, str]  # (vendor, product-prefix or "*")


def normalize(token: str) -> str:
    """CPE names are lowercase with underscores; KEV uses display names
    ("Pulse Secure", "Log4j2"). Normalize both sides the same way."""
    return token.strip().lower().replace(" ", "_")


def parse_technology(token: str) -> Technology:
    vendor, sep, product = token.partition(":")
    if not sep or not vendor.strip():
        raise ValueError(f"technology must look like 'vendor:product', got {token!r}")
    return normalize(vendor), normalize(product) or "*"


def parse_technologies(tokens: Iterable[str]) -> list[Technology]:
    return [parse_technology(t) for t in tokens]


def product_candidates(
    vendor_project: str | None,
    product: str | None,
    affected_products: Iterable[str] | None,
) -> set[tuple[str, str]]:
    """Every (vendor, product) the CVE is known to affect.

    NVD's CPE list is the precise source. KEV's single vendor/product pair is a
    fallback for CVEs NVD has not finished analysing yet.
    """
    candidates: set[tuple[str, str]] = set()
    for item in affected_products or ():
        vendor, sep, prod = item.partition(":")
        if sep:
            candidates.add((normalize(vendor), normalize(prod)))
    if vendor_project and product:
        candidates.add((normalize(vendor_project), normalize(product)))
    return candidates


def match_technology(
    technologies: Iterable[Technology], candidates: set[tuple[str, str]]
) -> str | None:
    """Return the first declared technology that matches, as "vendor:product",
    or None. Returning WHICH one matched lets the report explain itself."""
    for tech_vendor, tech_product in technologies:
        for vendor, product in candidates:
            if vendor == tech_vendor and (tech_product == "*" or product.startswith(tech_product)):
                return f"{tech_vendor}:{tech_product}"
    return None
