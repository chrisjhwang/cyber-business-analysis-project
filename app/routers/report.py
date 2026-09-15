from fastapi import APIRouter
from fastapi.responses import HTMLResponse, PlainTextResponse

from app.deps import DbSession
from app.reporting.report import build_report, render_html, render_markdown

router = APIRouter(tags=["report"])


@router.get("/report", response_class=HTMLResponse)
def report_html(db: DbSession):
    """The executive risk report, rendered live from the current database."""
    return render_html(build_report(db))


@router.get("/report.md", response_class=PlainTextResponse)
def report_markdown(db: DbSession):
    """Same report as Markdown, to paste into a document and edit."""
    return PlainTextResponse(render_markdown(build_report(db)), media_type="text/markdown")
