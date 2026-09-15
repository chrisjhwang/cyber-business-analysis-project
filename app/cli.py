"""Command-line entrypoint for the batch jobs.

    python -m app.cli pipeline            everything below, in order
    python -m app.cli seed-assets
    python -m app.cli ingest-kev
    python -m app.cli ingest-nvd [--cve CVE-2021-44228 ...] [--modified-since-days N]
    python -m app.cli rescore
    python -m app.cli report [--out-dir reports]

Each step opens its own transaction (session_scope), so a failure in a later
step never rolls back data an earlier step already committed.
"""
import argparse
import logging
from datetime import UTC, datetime
from pathlib import Path

from app.config import get_settings
from app.db import session_scope
from app.ingest.http import RateLimitedClient
from app.ingest.kev import ingest_kev
from app.ingest.nvd import build_queries, ingest_nvd, make_nvd_client
from app.reporting.report import build_report, render_html, render_markdown
from app.scoring.engine import rescore
from scripts.seed_assets import seed_assets

log = logging.getLogger("app.cli")


def cmd_seed_assets(_: argparse.Namespace) -> None:
    print(f"seeded {seed_assets()} assets")


def cmd_ingest_kev(_: argparse.Namespace) -> None:
    with RateLimitedClient() as client, session_scope() as session:
        result = ingest_kev(session, client)
    print(f"KEV {result.catalog_version}: {result.upserted} upserted, "
          f"{result.flags_cleared} stale flags cleared")


def cmd_ingest_nvd(args: argparse.Namespace) -> None:
    api_key = get_settings().nvd_api_key
    if not api_key:
        log.warning("NVD_API_KEY not set: limited to 5 requests/30s")
    queries = build_queries(cve_ids=args.cve, modified_since_days=args.modified_since_days)
    with make_nvd_client(api_key) as client, session_scope() as session:
        result = ingest_nvd(session, client, queries)
    print(f"NVD: {result.upserted} upserted, {result.skipped} rejected/skipped, "
          f"{result.requests} requests")


def cmd_rescore(_: argparse.Namespace) -> None:
    with session_scope() as session:
        r = rescore(session)
    print(f"rescored {r.scores_written} scenarios across {r.assets} assets "
          f"({r.vulnerabilities_considered} CVEs considered, {r.unscorable} without CVSS, "
          f"{r.stale_removed} stale rows removed)")


def cmd_report(args: argparse.Namespace) -> None:
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(UTC).strftime("%Y-%m-%d")
    with session_scope() as session:
        report = build_report(session)
        md, html = render_markdown(report), render_html(report)
    for suffix, content in (("md", md), ("html", html)):
        path = out_dir / f"risk_report_{stamp}.{suffix}"
        path.write_text(content, encoding="utf-8")
        print(f"wrote {path}")


def cmd_pipeline(args: argparse.Namespace) -> None:
    cmd_seed_assets(args)
    cmd_ingest_kev(args)
    cmd_ingest_nvd(args)
    cmd_rescore(args)
    cmd_report(args)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="python -m app.cli", description=__doc__.split("\n")[0])
    parser.add_argument("-v", "--verbose", action="store_true")
    sub = parser.add_subparsers(dest="command", required=True)

    def add_nvd_options(p: argparse.ArgumentParser) -> None:
        group = p.add_mutually_exclusive_group()
        group.add_argument("--cve", nargs="+", metavar="CVE_ID", help="only these CVEs")
        group.add_argument("--modified-since-days", type=int, metavar="N",
                           help="every CVE NVD modified in the last N days (not just KEV)")

    def add_report_options(p: argparse.ArgumentParser) -> None:
        p.add_argument("--out-dir", default="reports")

    sub.add_parser("seed-assets").set_defaults(func=cmd_seed_assets)
    sub.add_parser("ingest-kev").set_defaults(func=cmd_ingest_kev)
    p = sub.add_parser("ingest-nvd")
    add_nvd_options(p)
    p.set_defaults(func=cmd_ingest_nvd)
    sub.add_parser("rescore").set_defaults(func=cmd_rescore)
    p = sub.add_parser("report")
    add_report_options(p)
    p.set_defaults(func=cmd_report)
    p = sub.add_parser("pipeline")
    add_nvd_options(p)
    add_report_options(p)
    p.set_defaults(func=cmd_pipeline)

    args = parser.parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
    )
    args.func(args)


if __name__ == "__main__":
    main()
