# Cyber Risk Quantification Platform — Build Plan

## 0. Purpose & framing

This project exists to do two things at once:

1. **Close specific gaps** left by coursework (Operating Systems, Principles of Programming Languages, Data Structures & Algorithms, Computer Organization, Mobile Application Security, Penetration Testing) — namely: a real backend web framework, multi-service container orchestration, an actual CI/CD pipeline, real cloud deployment, and Monte Carlo simulation.
2. **Produce one artifact** that reads coherently on resumes for four different tracks — financial/business analyst, risk analyst, cybersecurity, and SWE — without being watered down for any of them.

Core concept: ingest real vulnerability data (CVE / CISA KEV) → score technical severity → translate that into expected financial loss using **FAIR** (Factor Analysis of Information Risk) methodology, not an improvised formula. Serve it through a real backend/API/CI-CD/cloud stack, not a one-off script.

**Prior work this deliberately does NOT reuse:** an existing Android APK static-analysis project (Python, Androguard, LLM-assisted triage, CWE/OWASP MASVS mapping, a hand-designed relational DB, Docker) already proves cyber technical depth. This project stays CVE/KEV-based and does not fold in that dataset, so it reads as a distinct artifact to an interviewer and forces building a real ingestion pipeline instead of reusing static data.

**Prime directive for every session working on this:** ship the MVP checkpoint (end of Stage 7) before touching anything in the stretch stages. Don't let scope creep from later stages bleed into earlier ones.

**Structure:** the build is organized into **stages**, not a weekend timeline. Each stage is scoped to either one layer of the stack (e.g. "the data layer," "the scoring engine") or an integration point where two previously-built layers get wired together (e.g. "API + DB," "container + CI"). A stage isn't done until its writeup is done — see Section 5.

---

## 1. Confirmed stack decisions

| Layer | Choice | Why |
|---|---|---|
| Backend | FastAPI (Python) | Velocity — time budget goes to risk modeling and CI/CD, not learning a new language |
| DB | PostgreSQL + SQLAlchemy + Alembic | Real migrations, not `create_all()` — a hiring signal in itself |
| Cloud target | AWS (ECS Fargate + RDS) | Matches the stack run by target employers (JPMorgan, Goldman Sachs, Deloitte, Capital One, Mastercard) — chosen over a PaaS like Fly.io/Render on purpose |
| IaC | Terraform (stretch) | Only after MVP ships |
| Data sources | CISA KEV feed (static JSON, no auth) + NVD CVE API 2.0 (needs free API key) | Live, real-world feeds — forces a genuine ingestion pipeline |

### Open implementation decisions (defaults chosen below — flag if you want to change any)

- **NVD API key:** Request one now at https://nvd.nist.gov/developers/request-an-api-key if not already done — approval isn't instant, so this should happen in parallel with everything else, not block it. Ingestion code will be written to work either way: unauthenticated (5 requests/30s) or authenticated via an `NVD_API_KEY` env var (50 requests/30s). Until the key arrives, ingestion just runs slower.
- **Dependency management:** `venv` + `requirements.txt`. Simplest, zero extra tooling to learn on top of everything else that's new here (Poetry adds real value later but isn't worth the detour now).
- **Local Postgres:** run via `docker-compose` from day one, even in Weekend 1, rather than installing Postgres natively via Homebrew. This avoids local version drift and gets you comfortable with the Docker workflow a week early, ahead of when Weekend 2 formally introduces containerization.

---

## 2. Repository layout (target, built incrementally)

```
cyber-risk-platform/
├── app/
│   ├── __init__.py
│   ├── main.py                # FastAPI app entrypoint
│   ├── config.py               # env var loading (DB url, NVD key, etc.)
│   ├── models.py               # SQLAlchemy ORM models
│   ├── schemas.py              # Pydantic request/response schemas
│   ├── db.py                   # engine/session setup
│   ├── routers/
│   │   ├── vulnerabilities.py
│   │   ├── assets.py
│   │   └── risk_scores.py
│   ├── ingest/
│   │   ├── kev.py               # CISA KEV feed ingestion
│   │   └── nvd.py               # NVD CVE API 2.0 ingestion
│   └── scoring/
│       └── fair_lite.py         # LEF / LM / ALE point-estimate scoring
├── alembic/
│   ├── env.py
│   └── versions/
├── tests/
│   ├── test_scoring.py
│   ├── test_ingest.py
│   └── test_api.py
├── docs/
│   ├── architecture.md          # diagram + component descriptions
│   ├── assumptions.md           # every FAIR-lite banding/scaling constant, justified
│   └── writeups/                # one notes-style writeup per stage, in build order
│       ├── 01-repo-and-environment.md
│       ├── 02-data-layer.md
│       ├── 03-ingestion-pipeline.md
│       ├── 04-scoring-engine.md
│       ├── 05-api-layer.md
│       ├── 06-testing.md
│       └── 07-containerization-and-ci.md
├── scripts/
│   └── seed_assets.py           # loads the small representative asset set
├── docker-compose.yml
├── Dockerfile
├── requirements.txt
├── alembic.ini
├── .env.example
├── .github/workflows/ci.yml
├── PLAN.md                      # this file
└── README.md
```

---

## 3. Data model

```
vulnerabilities
  cve_id            PK, text
  cvss_score        float
  cvss_vector       text
  cwe_id            text, nullable
  published_date    date
  kev_flag          boolean, default false
  last_updated      timestamp

assets
  id                PK, serial
  name              text            -- e.g. "customer database", "payment API", "internal admin panel"
  type              text            -- e.g. "database", "api", "internal_tool"
  sensitivity_tier  int             -- 1 (low) .. 3 (high), drives secondary loss multiplier

risk_scores
  id                PK, serial
  asset_id          FK -> assets.id
  cve_id            FK -> vulnerabilities.cve_id
  lef               float
  lm                float
  ale               float
  computed_at       timestamp
```

Keep the asset set small and curated (5–10 rows) rather than trying to model a real enterprise inventory — the point is to demonstrate the FAIR translation layer, not build an asset-management system.

---

## 4. FAIR-lite scoring methodology (MVP — point estimate)

FAIR terminology, deliberately not an invented formula. Every constant below gets written into `docs/assumptions.md` with its justification the moment it's chosen — that documentation trail *is* the rigor an interviewer will probe on.

**Loss Event Frequency (LEF):**
```
LEF = threat_event_frequency_assumption × exploit_probability
```
- `threat_event_frequency_assumption`: a fixed baseline (e.g. attacks-per-year an asset of this type is realistically probed), documented per asset type.
- `exploit_probability`: derived from the CVSS exploitability subscore (attack vector, complexity, privileges required, user interaction), normalized to [0,1], then boosted by a fixed multiplier when `kev_flag` is true (KEV = known to be actively exploited in the wild — this is exactly the kind of real-world signal FAIR calls out as distinct from raw CVSS).

**Loss Magnitude (LM):**
```
LM = primary_loss_band(CVSS impact subscores: C/I/A) + secondary_loss(breach_cost_benchmark × asset.sensitivity_tier)
```
- `primary_loss_band`: maps the CIA impact subscores to a dollar band (low/medium/high loss tiers), grounded in a cited industry breach-cost benchmark (e.g. IBM Cost of a Data Breach report figures), not a made-up number.
- `secondary_loss`: scales that benchmark by the asset's sensitivity tier (reputational/regulatory/downstream cost that isn't captured by the primary technical loss).

**Annualized Loss Expectancy (ALE):**
```
ALE = LEF × LM
```

This point-estimate version is what ships in the MVP. It is explicitly a placeholder for the stretch-phase Monte Carlo version (Section 7), which replaces each point estimate with a sampled distribution.

---

## 5. Writeup convention

After **every** stage below, before starting the next one, write a notes-style writeup — not polished marketing copy, closer to a lab notebook entry. This is the artifact that proves understanding, not just working code.

- **Location:** `docs/writeups/NN-stage-name.md` (e.g. `docs/writeups/01-data-layer.md`), one file per stage.
- **Root `README.md`** stays a normal project README (what it is, setup, run instructions, architecture) and links out to the writeups in build order, so a reader can follow the project's evolution stage by stage.
- **Each writeup should cover, in your own words:**
  - What this stage built, and where it sits in the overall architecture.
  - The key concept(s) this stage forced you to actually understand (e.g. "what a connection pool is and why SQLAlchemy needs one," "what idempotency means for a re-runnable ingestion job," "why Alembic migrations exist instead of just calling `create_all()`").
  - Any non-obvious decision made and why (mirrors the "document the assumption" rule from Section 4, but for engineering decisions, not just risk constants).
  - What broke / what was confusing, and how it got resolved — this is often the most valuable part for an interviewer to read, and the most honest signal of real understanding.
  - A short "if I did this again" note, if applicable.
- **Do not** treat the writeup as optional or defer it — a stage isn't complete until its writeup exists. This is what keeps the "showcase understanding" goal from being an afterthought bolted on at the end.

---

## 6. Stages

Each stage is scoped to one stack layer or one integration point. Work through them in order; don't start a stage until the previous one's writeup (Section 5) is done.

### Stage 1 — Repo & environment scaffold
Set up the repo layout (Section 2), `venv`, `requirements.txt` (fastapi, sqlalchemy, alembic, psycopg2-binary, requests, pydantic, python-dotenv, pytest), `.env.example`, and `docker-compose.yml` with a single Postgres service for local dev.
**Exit:** `docker-compose up` gives you a running, empty Postgres instance you can connect to.
**Writeup focus:** why each dependency is there; what `docker-compose` is actually doing versus running Postgres natively.

### Stage 2 — Data layer
SQLAlchemy models for `vulnerabilities`, `assets`, `risk_scores` (Section 3); Alembic initial migration; `scripts/seed_assets.py` inserting the small curated asset list.
**Exit:** migrations apply cleanly to a fresh DB; seed script populates the asset table; you can query it directly with `psql`.
**Writeup focus:** why migrations instead of `create_all()`; how the schema maps to the FAIR concepts it will eventually hold.

### Stage 3 — Ingestion pipeline (integration: external APIs + data layer)
`app/ingest/kev.py` — pulls the CISA KEV JSON feed, upserts into `vulnerabilities` (`kev_flag=true`), idempotent on `cve_id`. `app/ingest/nvd.py` — pulls CVSS score/vector/CWE from NVD CVE API 2.0 per CVE, respecting rate limits (with or without an API key), upserts remaining columns. Both scripts must be safely re-runnable (cron-able later).
**Exit:** running both scripts against live data populates real rows in `vulnerabilities` with no duplicates on a second run.
**Writeup focus:** what idempotency means here concretely and how it was enforced (upsert key, conflict handling); rate-limit handling; what a live feed made you deal with that a static dataset wouldn't have.

### Stage 4 — Risk scoring engine
`app/scoring/fair_lite.py` implementing the LEF/LM/ALE formulas (Section 4) as pure, unit-testable functions; writes rows into `risk_scores` for every (asset, vulnerability) pair; `docs/assumptions.md` written *during* this stage, not after, capturing every constant as it's chosen.
**Exit:** scoring script produces ALE numbers you can pull straight from the table and sanity-check by hand for a few rows.
**Writeup focus:** the FAIR concepts themselves (LEF vs LM vs ALE, why they're multiplied, not added); why each banding/scaling constant was chosen the way it was.

### Stage 5 — API layer (integration: FastAPI + data + scoring)
`app/main.py` plus routers exposing:
- `GET /vulnerabilities` — list, filterable by `kev_flag`/min CVSS
- `GET /assets/{id}/risk` — an asset's current risk score(s)
- `GET /risk/top?n=` — top-N riskiest assets by ALE
- `POST /rescore` — re-runs FAIR-lite scoring against current DB state

Pydantic schemas for request/response shapes.
**Exit:** every endpoint works against real ingested/scored data via `uvicorn` locally, verified with `curl` or the FastAPI docs UI.
**Writeup focus:** how FastAPI's request/response cycle and dependency injection (DB session per request) actually works; REST design choices made for these endpoints.

### Stage 6 — Testing
`pytest` coverage: known CVSS/kev_flag/sensitivity inputs → known LEF/LM/ALE outputs (Stage 4 formulas); ingestion tests using recorded/fixture API responses (no live API calls in tests); API tests via `TestClient`.
**Exit:** `pytest` passes locally and covers scoring, ingestion, and API layers.
**Writeup focus:** what made scoring logic easy to test versus what made ingestion harder to test (network boundary, fixtures/mocking); what "known inputs → known outputs" testing buys you here.

### Stage 7 — Containerization + CI/CD (integration: full stack + automation)
`Dockerfile` for the FastAPI app; extend `docker-compose.yml` to run API + Postgres together with a health-check dependency. `.github/workflows/ci.yml`: lint + pytest on every PR; build and push the image to GitHub Container Registry on merge to `main`. Root `README.md` finished with an architecture diagram (Mermaid) and setup/run instructions, linking all writeups so far.
**Exit — this is the MVP checkpoint:** `docker-compose up` gives a working API backed by real ingested data, from a clean clone with no manual steps beyond following the README; CI is green on PRs and publishes an image on merge.
**Writeup focus:** what Docker networking between API and DB containers actually involves; what the CI pipeline catches that local testing doesn't; what "the MVP checkpoint" means and why stopping here is deliberate, not incomplete.

**Do not start Stage 8 until Stage 7's writeup is done and the MVP checkpoint is genuinely true.**

---

## 7. Stretch stages (only after the MVP checkpoint is genuinely done)

Same rules apply: each is a stage, each ends with a writeup. Ordered roughly by resume value per unit effort.

### Stage 8 — Monte Carlo ALE
Replace the point estimate with sampling: LEF from a Poisson-ish distribution, LM from a lognormal, run thousands of trials, produce a loss-exceedance curve. Highest-value stretch stage for quant/financial-consulting interviews (Cornerstone Research, BRG, Analysis Group style) since it's the piece the point-estimate MVP explicitly deferred.
**Writeup focus:** what a loss-exceedance curve communicates that a point estimate can't; why these specific distributions were chosen for LEF/LM.

### Stage 9 — Scheduled worker
APScheduler in its own container, daily re-ingestion of new CVE/KEV entries and auto-rescoring.
**Writeup focus:** what changes about a pipeline when it has to run unattended on a schedule versus being manually triggered.

### Stage 10 — AWS deployment (integration: containers + cloud infra)
RDS for Postgres, ECS Fargate for API + worker, ALB if needed.
**Writeup focus:** how the local docker-compose topology maps (or doesn't) onto ECS Fargate services; what changed about config/secrets management moving off `.env`.

### Stage 11 — Terraform
Define the Stage 10 AWS deployment as IaC.
**Writeup focus:** what manually clicking through the AWS console (Stage 10) taught you that made the Terraform version easier to write.

### Stage 12 — Dashboard
Server-rendered + Chart.js (or React) showing the loss-exceedance curve, a top-risky-assets table, and a CVSS→dollar mapping — the actual screen to share in an interview.
**Writeup focus:** design choices made translating risk_scores/ALE data into something a non-technical stakeholder (the "executive-facing" framing) can read at a glance.

### Stage 13 — Optional hardening
API key auth on endpoints; CloudWatch or structured logging/observability.
**Writeup focus:** what threat this specifically defends against, and what's still out of scope even after adding it.

---

## 8. Guardrails (do not violate)

- Don't reuse or fold in the existing APK static-analysis dataset.
- Don't skip past the MVP checkpoint (end of Stage 7) straight into Stage 8+ — even partially.
- Don't invent risk-scoring constants without grounding them in FAIR terminology and logging the assumption in `docs/assumptions.md` at the moment it's chosen.
- Don't start a new stage before the previous stage's writeup (Section 5) is written.
- Don't add stretch-stage complexity before `docker-compose up` reliably gives a working, real-data-backed API (Stage 7 exit criteria).

## 9. Naming

Undecided: RiskLedger, LossLens, CVE2Dollar. Decide once something is running and the tool's personality is clearer — not before.

## 10. Resume framing (the target, not the plan — build the thing, then the sentence is true)

- **Cyber:** "Built an automated pipeline ingesting live CVE/CISA KEV data, mapping CVSS/CWE to exploitability and computing per-asset risk scores."
- **Financial/business analyst:** "Applied FAIR-based quantitative risk modeling and Monte Carlo simulation to translate technical vulnerability data into expected annual loss estimates, producing an executive-facing risk register."
- **SWE:** "Designed and deployed a containerized REST API (FastAPI/PostgreSQL) with a CI/CD pipeline (GitHub Actions) to AWS, including scheduled background jobs for live data ingestion."
