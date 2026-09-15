"""FastAPI entrypoint.

    uvicorn app.main:app --reload       then open http://localhost:8000
"""
from fastapi import FastAPI
from fastapi.responses import RedirectResponse
from sqlalchemy import text

from app.deps import DbSession
from app.routers import assets, report, risk, vulnerabilities

app = FastAPI(
    title="Cyber Risk Quantification Platform",
    version="0.1.0",
    description=(
        "Live CISA KEV + NVD vulnerability data, translated into expected annual "
        "financial loss with FAIR-lite (ALE = LEF x LM). Human-readable report at /report."
    ),
)

app.include_router(vulnerabilities.router)
app.include_router(assets.router)
app.include_router(risk.router)
app.include_router(report.router)


@app.get("/", include_in_schema=False)
def root():
    return RedirectResponse("/report")


@app.get("/health", tags=["meta"])
def health(db: DbSession):
    """Liveness plus a real DB round-trip, so a healthy API with a dead
    database does not report healthy."""
    db.execute(text("SELECT 1"))
    return {"status": "ok"}
