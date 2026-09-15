# Convenience wrappers. Everything here is a shortcut for a command you can
# also type by hand -- run `make -n <target>` to see exactly what it does.
-include .env
export

PY := .venv/bin/python
PSQL := docker exec -it cyber_risk_db psql -U $(POSTGRES_USER) -d $(POSTGRES_DB)

.PHONY: help up down logs db tables shell api migrate revision seed seed-dummy ingest rescore report pipeline test lint reset

help:  ## show this list
	@grep -hE '^[a-z-]+:.*##' $(firstword $(MAKEFILE_LIST)) | sed 's/:.*##/\t/' | expand -t14

# --- Docker ----------------------------------------------------------------
up:  ## build + start Postgres, migrations and the API (http://localhost:8000)
	docker compose up -d --build

down:  ## stop containers (data is kept; `docker compose down -v` wipes it)
	docker compose down

logs:  ## follow API logs
	docker compose logs -f api

# --- Database --------------------------------------------------------------
db:  ## open an interactive psql prompt
	$(PSQL)

tables:  ## list tables and row counts
	@docker exec -i cyber_risk_db psql -U $(POSTGRES_USER) -d $(POSTGRES_DB) -c "\
	  select 'vulnerabilities' t, count(*) from vulnerabilities \
	  union all select 'assets', count(*) from assets \
	  union all select 'risk_scores', count(*) from risk_scores;"

shell:  ## python REPL with the session and models already imported
	@$(PY) -i -c "\
from sqlalchemy import select, func; \
from app.db import SessionLocal, engine; \
from app.models import Vulnerability, Asset, RiskScore; \
s = SessionLocal(); \
print('ready: s (session), select, func, Vulnerability, Asset, RiskScore')"

migrate:  ## apply all pending migrations
	.venv/bin/alembic upgrade head

revision:  ## autogenerate a migration: make revision M="add foo column"
	.venv/bin/alembic revision --autogenerate -m "$(M)"

# --- Data pipeline (runs on your machine against the Docker Postgres) ------
seed:  ## load/update the curated asset list
	$(PY) -m app.cli seed-assets

seed-dummy:  ## fabricated CVE rows for offline work (real ingestion corrects them)
	$(PY) -m scripts.seed_dummy_vulns

ingest:  ## pull live CISA KEV + NVD data
	$(PY) -m app.cli ingest-kev
	$(PY) -m app.cli ingest-nvd

rescore:  ## recompute every FAIR-lite risk score
	$(PY) -m app.cli rescore

report:  ## write reports/risk_report_<date>.md and .html
	$(PY) -m app.cli report

pipeline:  ## seed + ingest + rescore + report, end to end
	$(PY) -m app.cli pipeline

api:  ## run the API locally with auto-reload (needs `docker compose up -d db`)
	.venv/bin/uvicorn app.main:app --reload

# --- Quality ---------------------------------------------------------------
test:  ## run the test suite (DB tests skip if Postgres is down)
	.venv/bin/pytest

lint:  ## ruff static checks
	.venv/bin/ruff check .

reset:  ## drop everything, rebuild schema, rerun the pipeline
	.venv/bin/alembic downgrade base
	.venv/bin/alembic upgrade head
	$(MAKE) pipeline
