# Cyber Risk Quantification Platform — Learning & Build Plan

## 0. What this actually is

This project has two goals, in this priority order:

1. **Teach you software development from the ground up**, using a real project instead of tutorials.
   You currently know cybersecurity/analysis concepts but not how to build backend software. This
   plan exists to close that gap by making you build every layer of a real system yourself.
2. **Produce one artifact** that reads coherently on resumes for four tracks — financial/business
   analyst, risk analyst, cybersecurity, and SWE.

Goal 1 comes first. A finished project with concepts you can't explain is worth less than a slower
project you actually understand. **Do not let "get it done" override "understand it."**

Core concept, so you always know what you're building toward: ingest real vulnerability data (CVE /
CISA KEV) → score technical severity → translate that into expected financial loss using **FAIR**
(Factor Analysis of Information Risk) methodology → serve it through a real backend/API/CI-CD stack.

**Prime directive for every session:** ship the MVP checkpoint (end of Stage 7) before touching
anything in the stretch stages. Don't let scope creep from later stages bleed into earlier ones.

---

## 1. How to work with Claude on this project

This is the most important section in this document. Read it before Stage 1.

**The rule: Claude writes code with you, not concepts for you.**

| Ask Claude for... | Figure out yourself first (then ask Claude if still stuck) |
|---|---|
| "This line throws `TypeError: ...` — what's wrong?" | "What is a TypeError?" |
| "Write the SQLAlchemy `Column` line for a nullable float" | "What is an ORM?" |
| "Why does this migration fail with `relation already exists`?" | "What is a database migration?" |
| Code review of something you wrote | "Is my approach to Stage 3 correct?" — try it, see what breaks |
| "What's the Python syntax for a dict comprehension?" | "Why does Python need virtual environments?" |
| Debugging a stack trace line by line | Reading the **Concepts** section of the current stage |

**Concretely, the workflow per stage is:**

1. Read that stage's section below in full, including the **Concepts you need first** list.
2. For any term you don't understand, look it up yourself — official docs, MDN, a blog post, whatever.
   This plan tells you *what to learn*, not the full explanation. Spending 20 minutes reading Postgres
   docs before touching SQLAlchemy is not wasted time — it's the actual point of this project.
3. Attempt the implementation yourself, even badly.
4. When you hit a wall — an error you don't understand, a "how do I even write this in Python" moment,
   a design choice where you want a second opinion on tradeoffs you've already thought through — bring
   that specific, concrete question to Claude.
5. After Claude helps you fix or write something, **make sure you can explain what it did** before
   moving on. If you can't, ask "explain what this code does line by line" — that's a legitimate ask,
   different from "explain the concept," because you're grounding it in code you're looking at.
6. Write the stage's writeup (Section 6) in your own words. If you can't write it without Claude's
   help, that's a signal you moved on before actually understanding the stage — go back.

**Why this matters:** the resume value of this whole project depends on you being able to talk about
it fluently in an interview. An interviewer asking "walk me through how your ingestion pipeline avoids
duplicate rows" will find out in about ten seconds whether you understood it or whether Claude did.

---

## 2. Concept primer — the stack, and why each piece exists

Read this once now, and re-read the relevant row when you reach the stage that uses it. This is meant
to give you *just enough* orientation to know what to go read more about — not a full explanation.

| Layer | Choice | What it is, at a level a newbie can start from |
|---|---|---|
| Language | Python | You'll interact with it via `venv` (isolated per-project dependency environments — look up "why virtual environments" if that phrase means nothing to you) |
| Backend framework | FastAPI | A framework is code that handles the boring, repeated parts of "receive an HTTP request → run your function → send back a response" so you only write the part specific to your app. FastAPI is built on **ASGI** (an async server interface — look up sync vs. async in Python) and uses Pydantic to validate incoming/outgoing data automatically. |
| Web server | Uvicorn | FastAPI is a set of Python objects, not something that can listen on a network port by itself. Uvicorn is the actual program that binds to a port, receives raw HTTP bytes, and hands them to your FastAPI app. This is the same relationship as "a car engine" (FastAPI) vs. "the car" (Uvicorn) that actually drives on the road. |
| Database | PostgreSQL | A **relational database**: data lives in tables (rows/columns), tables can reference each other (**foreign keys**), and you query with **SQL**. Look up: what a relational database is, what a primary key and foreign key are, what a JOIN does. |
| ORM | SQLAlchemy | An **Object-Relational Mapper**. Instead of writing raw SQL strings in Python, you define Python classes, and SQLAlchemy translates operations on those classes into SQL. It also manages a **connection pool** (a set of reusable open connections to the database, because opening a new one per request is slow) — look this term up specifically. |
| Migrations | Alembic | Your database schema (table/column definitions) needs to change over time as you build. A migration is a small, version-controlled script describing one schema change, that can be applied (`upgrade`) or undone (`downgrade`). Look up why this is different from just calling `create_all()` once — this is a concept interviewers specifically probe. |
| DB driver | psycopg2 | SQLAlchemy doesn't speak Postgres's network protocol itself — it delegates to a driver library. Worth knowing this layering exists even if you never touch psycopg2 directly. |
| Validation layer | Pydantic | Defines the *shape* of data — what fields exist, their types, what's required — and validates it automatically. Used both for reading config (env vars) and for API request/response schemas. Different from a SQLAlchemy model: a Pydantic model describes data shape, a SQLAlchemy model describes a database table. They often look similar but serve different jobs. |
| Containers | Docker / docker-compose | Look up: the difference between a container and a virtual machine, and the difference between an **image** (a frozen template) and a **container** (a running instance of that template). `docker-compose` runs multiple containers together (e.g. your API + your database) on a shared private network. |
| CI/CD | GitHub Actions | **CI (continuous integration)**: automatically run tests/checks on every code push, so broken code is caught before it's merged. **CD (continuous deployment)**: automatically build and publish a deployable artifact (here, a Docker image) when code lands on `main`. Look up the difference — they're often said together but are two separate concerns. |
| Cloud target | AWS (ECS Fargate + RDS) | Stretch phase. ECS Fargate runs containers without you managing the underlying servers. RDS is a managed Postgres instance AWS operates for you. Chosen because it matches the stack used by large financial-sector employers. |
| IaC | Terraform | Stretch phase. Instead of clicking through the AWS console to create resources, you write config files describing the desired infrastructure, and Terraform creates/updates/destroys real cloud resources to match. Look up "declarative vs. imperative infrastructure" once you get here. |
| Risk framework | FAIR | Not a technology — a risk-quantification methodology from the cybersecurity industry. Covered in depth in Section 5. |

**Data sources:**
- **CISA KEV feed** — a static JSON list of CVEs known to be actively exploited in the wild. No auth needed.
- **NVD CVE API 2.0** — the National Vulnerability Database's API, giving you CVSS scores/vectors/CWE
  IDs per CVE. Works without a key (5 requests/30s) or with a free key (50 requests/30s) — request one
  early at https://nvd.nist.gov/developers/request-an-api-key since approval isn't instant.

**Dependency management:** `venv` + `requirements.txt`. This is the simplest option, deliberately —
you have enough new concepts already without adding Poetry on top.

---

## 3. Repository layout (target — you build this incrementally, not all at once)

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
├── scripts/
│   └── seed_assets.py           # loads the small representative asset set
├── docker-compose.yml
├── Dockerfile
├── requirements.txt
├── alembic.ini
├── .env.example
├── .github/workflows/ci.yml
├── PLAN.md
└── README.md
```

You don't need to understand every line of this yet — it will make more sense as each stage adds
its piece. Nothing exists yet; Stage 1 creates the first slice of it.

---

## 4. Data model

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

**PK** = primary key (uniquely identifies a row). **FK** = foreign key (a column that references a
primary key in another table — this is what makes it "relational"). If those two terms aren't already
familiar, that's a five-minute detour worth taking before Stage 2.

Keep the asset set small and curated (5–10 rows) rather than trying to model a real enterprise
inventory — the point is to demonstrate the FAIR translation layer, not build an asset-management
system.

---

## 5. FAIR-lite scoring methodology (MVP — point estimate)

FAIR (Factor Analysis of Information Risk) is a real, published risk-quantification standard — not an
improvised formula. Every constant chosen below gets written into `docs/assumptions.md` with its
justification the moment it's chosen, in Stage 4. That documentation trail *is* the rigor an
interviewer will probe on, so don't defer it.

**Loss Event Frequency (LEF)** — how often, per year, is this asset realistically going to experience
a loss event from this vulnerability?
```
LEF = threat_event_frequency_assumption × exploit_probability
```
- `threat_event_frequency_assumption`: a fixed baseline (e.g. attacks-per-year an asset of this type
  is realistically probed), documented per asset type.
- `exploit_probability`: derived from the CVSS exploitability subscore (attack vector, complexity,
  privileges required, user interaction), normalized to [0,1], then boosted by a fixed multiplier when
  `kev_flag` is true (KEV = known to be actively exploited in the wild — a real-world signal FAIR calls
  out as distinct from raw CVSS, which only measures theoretical severity).

**Loss Magnitude (LM)** — if the loss event happens, how much does it cost?
```
LM = primary_loss_band(CVSS impact subscores: C/I/A) + secondary_loss(breach_cost_benchmark × asset.sensitivity_tier)
```
- `primary_loss_band`: maps the CIA (Confidentiality/Integrity/Availability) impact subscores to a
  dollar band (low/medium/high), grounded in a cited industry breach-cost benchmark (e.g. IBM Cost of
  a Data Breach report figures) — not a made-up number.
- `secondary_loss`: scales that benchmark by the asset's sensitivity tier (reputational/regulatory/
  downstream cost the primary technical loss doesn't capture).

**Annualized Loss Expectancy (ALE)** — the headline number:
```
ALE = LEF × LM
```

Multiplication, not addition — because LEF is a *rate* (events/year) and LM is a *cost per event*;
multiplying them gives you an expected cost *per year*, which is the whole point. Be able to explain
that in an interview without looking it up.

This point-estimate version ships in the MVP. Stage 8 replaces each point estimate with a sampled
distribution (Monte Carlo).

---

## 6. Writeup convention

After **every** stage below, before starting the next one, write a notes-style writeup — not
polished marketing copy, closer to a lab notebook entry. Given the learning-first framing of this
project (Section 0), the writeup is not a formality — it's your own proof (to yourself and to an
interviewer) that you actually understood the stage rather than pattern-matched your way through it.

- **Location:** `docs/writeups/NN-stage-name.md`, one file per stage.
- **Root `README.md`** stays a normal project README and links out to the writeups in build order.
- **Each writeup should cover, in your own words, with no Claude drafting the explanation for you:**
  - What this stage built, and where it sits in the overall architecture.
  - The key concept(s) this stage forced you to actually understand — pull from the "Concepts you
    need first" list for that stage, but explain it in your own words, not a copy of this document.
  - Any non-obvious decision made and why.
  - What broke / what was confusing, and how it got resolved — often the most valuable and most
    honest section.
  - A short "if I did this again" note, if applicable.
- **If you find yourself unable to write a section without asking Claude to explain the concept to
  you first, go back and actually learn it before finishing the writeup.** The writeup is the
  checkpoint that catches "I got the code working but don't understand why" before it compounds into
  later stages.

---

## 7. Stages

Work through them in order. Don't start a stage until the previous stage's writeup is done. Each
stage below has four parts: **Concepts you need first**, **What you're building**, **Components
explained**, and **Exit criterion**.

### Stage 1 — Repo & environment scaffold

**Concepts you need first:**
- What a Python virtual environment (`venv`) is and why it exists (isolating one project's
  dependencies from another, and from your system Python).
- What `pip` and `requirements.txt` do together.
- What a `.gitignore` is for, and specifically why secrets/`.env` files belong in it.
- What a container image is (revisit the Docker row in Section 2).
- What a healthcheck is, in the context of "a container has started" vs. "the service inside it is
  ready to accept connections" — these are not the same moment, and this distinction causes real bugs.

**What you're building:** the repo layout (Section 3, the parts that exist this early), a `venv`, a
`requirements.txt` naming the tools from Section 2, `.env.example`, and a `docker-compose.yml` running
a single Postgres service for local dev.

**Components explained:**
- `app/config.py` will hold one typed settings object (Pydantic `Settings`) that reads environment
  variables once and fails loudly at startup if something required is missing — instead of scattering
  `os.getenv()` calls through the codebase, each of which silently returns `None` on a typo.
- `docker-compose.yml`'s job: pull the Postgres image, create a named **volume** (persistent storage
  outside the container's ephemeral filesystem — without it, `docker compose down` deletes your data),
  create a private network for future services to join, and publish a host port so tools on your
  machine (psql, Alembic, your app) can reach the database.
- Why Docker for Postgres instead of installing it natively: version reproducibility (the version is a
  line in a file, not a property of your laptop), and disposability (`docker compose down -v` gives you
  a truly clean slate, which matters a lot in Stage 2).

**Exit criterion:** `docker-compose up` gives you a running, empty Postgres instance you can connect
to with `psql`.

**Writeup focus:** why each dependency in `requirements.txt` is there (in your own words, not copied
from Section 2); what `docker-compose` is actually doing versus running Postgres natively.

---

### Stage 2 — Data layer

**Concepts you need first:**
- ORM basics (revisit Section 2) — specifically, how a Python class becomes a SQL `CREATE TABLE`.
- What a migration is and why `create_all()` doesn't give you the same thing (it has no history, no
  rollback path, and no way to describe *changing* an existing table).
- Primary keys, foreign keys, nullable vs. not-null columns.

**What you're building:** SQLAlchemy models for `vulnerabilities`, `assets`, `risk_scores` (Section
4), the first Alembic migration, and `scripts/seed_assets.py` inserting the small curated asset list.

**Components explained:**
- Each SQLAlchemy model is a Python class where each class attribute maps to a table column, with a
  type (`String`, `Float`, `Boolean`, etc.) and constraints (nullable, unique, foreign key).
- Alembic tracks which migrations have already been applied to a given database (in its own metadata
  table), so running it twice doesn't re-apply the same change — this is what "migrations are
  idempotent at the schema level" means in practice.
- `scripts/seed_assets.py` is a plain script, not part of the app — it runs once (or is re-run
  deliberately) to populate a fixed, hand-written list of example assets, not to be confused with the
  ingestion pipeline in Stage 3, which pulls from a live external feed.

**Exit criterion:** migrations apply cleanly to a fresh DB; the seed script populates the asset table;
you can query it directly with `psql`.

**Writeup focus:** why migrations instead of `create_all()`, in your own words; how the schema maps to
the FAIR concepts it will eventually hold.

---

### Stage 3 — Ingestion pipeline (integration: external APIs + data layer)

**Concepts you need first:**
- What **idempotency** means concretely for a script that talks to a database (running it twice
  produces the same end state, not duplicate rows).
- What an **upsert** is (insert-or-update based on a conflict key) and how it enforces idempotency here.
- What API rate limiting is, and the difference between handling it gracefully (backing off, retrying)
  versus just crashing when you hit it.
- The general shape of calling an HTTP API from Python and parsing a JSON response.

**What you're building:** `app/ingest/kev.py` (pulls the CISA KEV JSON feed, upserts into
`vulnerabilities` with `kev_flag=true`) and `app/ingest/nvd.py` (pulls CVSS score/vector/CWE from NVD
CVE API 2.0 per CVE, respecting rate limits with or without an API key, upserting the remaining
columns). Both must be safely re-runnable.

**Components explained:**
- The **upsert key** here is `cve_id` — if a row with that ID already exists, update it; otherwise
  insert a new one. This is the concrete mechanism that makes "re-runnable" true.
- KEV and NVD are ingested separately because they're different data sources answering different
  questions (KEV: "is this actively exploited?"; NVD: "how severe is this technically?") — the same
  row in `vulnerabilities` gets touched by both scripts, at different times, which is exactly why the
  upsert pattern matters instead of a plain insert.
- Rate-limit handling for NVD: branch on whether `NVD_API_KEY` is set (5 req/30s unauthenticated vs.
  50 with a key), and sleep/retry rather than hammering the API and getting blocked.

**Exit criterion:** running both scripts against live data populates real rows in `vulnerabilities`
with no duplicates on a second run.

**Writeup focus:** what idempotency meant here concretely and how you enforced it; rate-limit handling;
what dealing with a *live* feed forced you to handle that a static dataset wouldn't have.

---

### Stage 4 — Risk scoring engine

**Concepts you need first:**
- Re-read Section 5 closely — LEF, LM, ALE, and *why* they're multiplied rather than added.
- What a **pure function** is (same input always gives same output, no side effects) and why that
  makes scoring logic easy to unit test — this sets up Stage 6.

**What you're building:** `app/scoring/fair_lite.py` implementing the LEF/LM/ALE formulas as pure,
unit-testable functions, writing rows into `risk_scores` for every (asset, vulnerability) pair.
`docs/assumptions.md` gets written *during* this stage, capturing every constant as it's chosen — not
after the fact.

**Components explained:**
- "Pure" here specifically means: the scoring functions take CVSS values, `kev_flag`, and
  `sensitivity_tier` as plain arguments and return a number — they don't query the database themselves.
  A separate, thin layer loops over (asset, vulnerability) pairs, calls the pure functions, and writes
  results. This separation is what makes Stage 6's testing straightforward.
- `docs/assumptions.md` is not optional documentation — every banding constant (e.g. "CVSS impact
  score 7-10 maps to the 'high' loss band, cited from X") needs a one-line justification the moment
  you pick it, or you'll forget why by the time someone asks.

**Exit criterion:** the scoring script produces ALE numbers you can pull straight from the table and
sanity-check by hand for a few rows.

**Writeup focus:** the FAIR concepts themselves, in your own words; why each banding/scaling constant
was chosen the way it was.

---

### Stage 5 — API layer (integration: FastAPI + data + scoring)

**Concepts you need first:**
- REST basics: what a resource is, what GET/POST mean, what a URL path parameter vs. query parameter
  is, common status codes (200, 404, 422).
- What **dependency injection** means in FastAPI specifically — a function parameter that FastAPI
  fills in automatically (e.g. a fresh DB session per request) rather than you constructing it by hand
  in every route.
- The difference between a SQLAlchemy model (Stage 2, describes a DB table) and a Pydantic schema
  (describes the shape of an API request/response) — they will look similar but are not the same thing
  and serve different layers.

**What you're building:** `app/main.py` plus routers exposing:
- `GET /vulnerabilities` — list, filterable by `kev_flag`/min CVSS
- `GET /assets/{id}/risk` — an asset's current risk score(s)
- `GET /risk/top?n=` — top-N riskiest assets by ALE
- `POST /rescore` — re-runs FAIR-lite scoring against current DB state

Pydantic schemas define the request/response shapes for each.

**Components explained:**
- Each router file groups related endpoints (e.g. everything about vulnerabilities in one file) — this
  is an organizational convention, not a technical requirement, but it's the standard FastAPI pattern.
- A DB session per request (via dependency injection) exists so that each request gets its own
  connection from the pool, used for the duration of that request and then released — not one shared
  global connection, which would break under concurrent requests.
- `POST /rescore` is a mutation triggered by a request rather than a schedule — this is deliberate for
  the MVP; Stage 9 (stretch) is what makes it run on a schedule instead of requiring a manual call.

**Exit criterion:** every endpoint works against real ingested/scored data via `uvicorn` locally,
verified with `curl` or the FastAPI docs UI (`/docs`, auto-generated — go look at it, it's one of
FastAPI's actual selling points).

**Writeup focus:** how FastAPI's request/response cycle and dependency injection actually work, in
your own words; REST design choices made for these specific endpoints.

---

### Stage 6 — Testing

**Concepts you need first:**
- What a **unit test** is vs. an **integration test**, and why Stage 4's pure functions are easy to
  unit test while Stage 3's ingestion (which hits a real network) is not, without help.
- What a **fixture** or **mock** is, in the context of testing code that would otherwise make a real
  network call — recording a real API response once and replaying it in tests, instead of calling the
  live API every time you run the test suite.
- What `pytest` conventions are (test discovery, `assert`, fixtures via `conftest.py`).

**What you're building:** `pytest` coverage — known CVSS/kev_flag/sensitivity inputs mapped to known
LEF/LM/ALE outputs (Stage 4); ingestion tests using recorded/fixture API responses (no live API calls
in tests); API tests via FastAPI's `TestClient`.

**Components explained:**
- "Known inputs → known outputs" testing means: you pick specific values (e.g. CVSS 9.8, `kev_flag`
  true, sensitivity tier 3), compute what the correct LEF/LM/ALE *should* be by hand using the Stage 4
  formulas, and assert the code produces that exact number. This catches formula bugs, not just
  crashes.
- `TestClient` lets you call your FastAPI endpoints in-process, without actually starting `uvicorn` or
  binding a real network port — fast and isolated.

**Exit criterion:** `pytest` passes locally and covers scoring, ingestion, and API layers.

**Writeup focus:** what made scoring logic easy to test versus what made ingestion harder (the network
boundary, and why fixtures/mocking solve it); what "known inputs → known outputs" buys you here.

---

### Stage 7 — Containerization + CI/CD (integration: full stack + automation)

**Concepts you need first:**
- The difference between building an image (`Dockerfile`) and running it (`docker-compose`).
- Docker networking basics: containers on the same compose network reach each other by *service name*
  (e.g. `db`), not `localhost` — `localhost` from inside a container means that container itself.
- What `depends_on: condition: service_healthy` solves (a container being *started* is not the same as
  the service inside it being *ready* — the API racing ahead of the DB is a classic bug this prevents).
- What CI actually catches that running things locally doesn't (a clean environment with no leftover
  local state, dependency versions, forgotten `.env` values).

**What you're building:** a `Dockerfile` for the FastAPI app; `docker-compose.yml` extended to run API
+ Postgres together with the healthcheck dependency wired up; `.github/workflows/ci.yml` running
lint + pytest on every PR, and building/pushing the image to GitHub Container Registry on merge to
`main`. Root `README.md` finished with an architecture diagram and setup/run instructions, linking all
writeups so far.

**Components explained:**
- Inside the compose network, `DATABASE_URL` needs to point at `db` (the service name), not
  `localhost` as it did when you ran the app directly on your host in Stages 1-6 — same database,
  different path to it depending on where the caller is running.
- The GitHub Actions workflow is triggered by GitHub itself on push/PR events — it runs on GitHub's
  infrastructure, not your machine, which is exactly why a green CI run means something a passing local
  test run doesn't (no "works on my machine" leftover state).

**Exit criterion — this is the MVP checkpoint:** `docker-compose up` gives a working API backed by
real ingested data, from a clean clone with no manual steps beyond following the README; CI is green
on PRs and publishes an image on merge.

**Writeup focus:** what Docker networking between API and DB containers actually involves; what the CI
pipeline catches that local testing doesn't; what "the MVP checkpoint" means and why stopping here is
deliberate, not incomplete.

**Do not start Stage 8 until Stage 7's writeup is done and the MVP checkpoint is genuinely true.**

---

## 8. Stretch stages (only after the MVP checkpoint is genuinely done)

Same rules: each is a stage, each gets a Concepts list, each ends with a writeup. Ordered roughly by
resume value per unit effort.

### Stage 8 — Monte Carlo ALE
**Concepts first:** what Monte Carlo simulation is (running a model thousands of times with randomly
sampled inputs instead of one fixed input, to see a *distribution* of outcomes instead of a single
number); what a Poisson distribution and a lognormal distribution model, intuitively (event counts vs.
skewed positive magnitudes); what a loss-exceedance curve communicates that a single ALE number can't.
**What you're building:** replace the point estimate with sampling — LEF from a Poisson-ish
distribution, LM from a lognormal, run thousands of trials, produce a loss-exceedance curve.
**Writeup focus:** why these specific distributions were chosen for LEF/LM.

### Stage 9 — Scheduled worker
**Concepts first:** what a job scheduler is and how "runs unattended on a timer" differs from "runs
when someone calls an endpoint" — failure handling, logging, and idempotency all matter more once
nobody's watching it run.
**What you're building:** APScheduler in its own container, daily re-ingestion of new CVE/KEV entries
and auto-rescoring.
**Writeup focus:** what changes about a pipeline when it has to run unattended on a schedule.

### Stage 10 — AWS deployment (integration: containers + cloud infra)
**Concepts first:** what "serverless containers" (Fargate) means versus managing your own EC2
instances; what a managed database service (RDS) takes off your plate versus self-hosting Postgres;
secrets management in the cloud versus a local `.env` file.
**What you're building:** RDS for Postgres, ECS Fargate for API + worker, ALB if needed.
**Writeup focus:** how the local docker-compose topology maps (or doesn't) onto ECS Fargate services.

### Stage 11 — Terraform
**Concepts first:** Infrastructure as Code, declarative vs. imperative infra management, Terraform
state.
**What you're building:** the Stage 10 AWS deployment, defined as code instead of console clicks.
**Writeup focus:** what manually clicking through the AWS console (Stage 10) taught you that made the
Terraform version easier to write.

### Stage 12 — Dashboard
**Concepts first:** basics of a frontend charting library; how to design a view for a non-technical
("executive-facing") audience versus a technical one.
**What you're building:** server-rendered + Chart.js (or React) view showing the loss-exceedance
curve, a top-risky-assets table, and a CVSS→dollar mapping.
**Writeup focus:** design choices translating risk_scores/ALE data into something a non-technical
stakeholder can read at a glance.

### Stage 13 — Optional hardening
**Concepts first:** what an API key/auth scheme actually protects against; what structured logging is
and why it's more useful than print statements once something's running unattended in the cloud.
**What you're building:** API key auth on endpoints; CloudWatch or structured logging/observability.
**Writeup focus:** what threat this specifically defends against, and what's still out of scope even
after adding it.

---

## 9. Guardrails (do not violate)

- Don't reuse or fold in any existing static-analysis dataset from prior projects — this project
  stays CVE/KEV-based and builds its own ingestion pipeline from scratch.
- Don't skip past the MVP checkpoint (end of Stage 7) straight into Stage 8+, even partially.
- Don't invent risk-scoring constants without grounding them in FAIR terminology and logging the
  assumption in `docs/assumptions.md` at the moment it's chosen.
- Don't start a new stage before the previous stage's writeup (Section 6) is written.
- Don't let Claude explain a concept you haven't tried to learn yourself first (Section 1) — that's
  the guardrail that protects the actual point of this project.

## 10. Naming

Undecided: RiskLedger, LossLens, CVE2Dollar. Decide once something is running and the tool's
personality is clearer — not before.

## 11. Resume framing (the target, not the plan — build the thing, then the sentence is true)

- **Cyber:** "Built an automated pipeline ingesting live CVE/CISA KEV data, mapping CVSS/CWE to
  exploitability and computing per-asset risk scores."
- **Financial/business analyst:** "Applied FAIR-based quantitative risk modeling and Monte Carlo
  simulation to translate technical vulnerability data into expected annual loss estimates, producing
  an executive-facing risk register."
- **SWE:** "Designed and deployed a containerized REST API (FastAPI/PostgreSQL) with a CI/CD pipeline
  (GitHub Actions) to AWS, including scheduled background jobs for live data ingestion."
