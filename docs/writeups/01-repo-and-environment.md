# Stage 1 — Repo & environment scaffold

## What this stage built

The skeleton everything else hangs off of, and nothing more:

- Package layout under `app/` (`routers/`, `ingest/`, `scoring/`), each with an `__init__.py` so
  Python treats them as packages and `from app.scoring.fair_lite import ...` resolves later.
- `venv` + pinned `requirements.txt`.
- `app/config.py` — a single typed settings object.
- `.env.example` (committed) / `.env` (gitignored).
- `docker-compose.yml` running one service: Postgres 16.

Architecturally this stage sits *under* every other stage. There is no application logic here at
all — no models, no endpoints. The only thing that "works" at the end of it is a database with
nothing in it, which is exactly the Stage 1 exit criterion.

## Why each dependency is in requirements.txt

Grouped the file by role rather than alphabetically, because the grouping is the explanation:

| Dependency | Why it's here |
|---|---|
| `fastapi` | The web framework (Stage 5). Chosen over Flask/Django mainly for Pydantic-native request/response validation and free OpenAPI docs. |
| `uvicorn[standard]` | FastAPI is an ASGI *application*, not a server — it needs something to actually listen on a socket. The `[standard]` extra pulls in `uvloop`/`httptools` (faster event loop and HTTP parser) and `watchfiles` (`--reload` in dev). |
| `SQLAlchemy` | ORM + connection pooling (Stage 2). |
| `alembic` | Schema migrations. Separate package from SQLAlchemy on purpose — see below. |
| `psycopg2-binary` | The actual Postgres driver. SQLAlchemy is a layer over a DBAPI driver; it doesn't speak the Postgres wire protocol itself. `-binary` ships precompiled wheels so there's no local libpq/compiler dependency. |
| `pydantic` | Validation, and the schema layer for the API. |
| `pydantic-settings` | Split out of Pydantic in v2. This is what makes `Settings` read from the environment. |
| `python-dotenv` | Loads `.env` into the environment; pydantic-settings uses it for `env_file`. |
| `requests` | The ingestion HTTP client (Stage 3) — plain sync scripts, so no need for async here. |
| `pytest` | Stage 6. |
| `httpx` | FastAPI's `TestClient` is built on httpx, so it's a test dependency even though no test code imports it directly. |

Everything is pinned to an exact version (`==`, not `>=`). The point of pinning here is that CI in
Stage 7 should install the *same* dependency set that works locally, so a green build means
something.

## What docker-compose is actually doing (vs. installing Postgres natively)

`brew install postgresql` would have been fewer moving parts on day one. The reason not to:

- **A native install is one global Postgres for the whole machine.** Version drift between it and
  whatever RDS runs in Stage 10 is invisible until it isn't. The compose file pins
  `postgres:16-alpine`, so the version is a line of code in the repo, not a property of my laptop.
- **Reproducibility.** `docker compose up` from a clean clone gives a byte-identical database. That
  is literally the Stage 7 exit criterion, so starting there means not migrating to it later.
- **Disposability.** `docker compose down -v` wipes the volume and I get a virgin DB. That matters a
  lot in Stage 2, where the whole point is proving migrations apply cleanly to a *fresh* database.

Concretely, what compose does when it reads this file:

1. Pulls the `postgres:16-alpine` image if it isn't cached.
2. Creates a named volume `pgdata` and mounts it at `/var/lib/postgresql/data` — the container's
   filesystem is ephemeral, so without this, all data vanishes on `down`. The volume is what makes
   the DB survive a container restart.
3. Creates a private network for the project and attaches the container to it. Nothing else is on
   that network yet; in Stage 7 the API container joins it and will reach the DB at the hostname
   `db` (the *service* name) rather than `localhost`.
4. Publishes `5432:5432`, which is a separate mechanism from that network — it forwards a host port
   into the container so tools running on the host (psql, Alembic, the app under `uvicorn`) can
   connect. This is why `DATABASE_URL` says `localhost` in Stage 1 and will need to say `db` for the
   containerized app in Stage 7. Same database, two different paths to it.
5. Passes `POSTGRES_USER`/`PASSWORD`/`DB` as env vars. The official image's entrypoint reads these on
   *first* boot to `initdb` and create the role and database. Worth knowing: they're only read when
   the data directory is empty. Changing the password in `.env` later does nothing to an existing
   volume, which is a genuinely confusing failure mode to hit later.

## Non-obvious decisions

**Config as one typed object instead of scattered `os.getenv()` calls.** `app/config.py` defines a
Pydantic `Settings` class wrapped in `@lru_cache`. Two reasons: (a) `os.getenv` returns `str | None`
and every call site has to re-handle a missing value, whereas this fails once, loudly, at startup
with a useful message; (b) `lru_cache` means the `.env` file is parsed once per process, and every
module — app, ingestion scripts, Alembic's `env.py` — gets the same instance instead of each
inventing its own convention.

**`nvd_api_key: str | None = None`.** Deliberately optional. The NVD key has a real approval delay,
and the plan says ingestion should work either way (5 req/30s unauthenticated, 50 with a key). Typing
it as optional at the config layer is what makes that possible without a code change later — Stage 3
branches on whether it's set.

**`database_url` has a default that matches the compose credentials.** Slightly redundant with
`.env.example`, but it means a fresh clone runs against the compose DB with zero config. The
committed default is only ever localhost dev credentials, so nothing sensitive lives in the repo.

**Compose has a healthcheck already, even though nothing depends on it yet.** `pg_isready` on a 5s
interval. It's inert in Stage 1. It's here because Stage 7 needs `depends_on: condition:
service_healthy` — a container being *started* is not the same as Postgres being *ready to accept
connections*, and the API container racing ahead of the DB is the classic compose bug. Writing the
check now means Stage 7 is a two-line change.

**`.env` gitignored, `.env.example` committed.** Standard, but the reason to bother in a project
where the only "secret" is `postgres/postgres`: the NVD API key lands in this file in Stage 3, and
the habit needs to already exist by then.

## What was confusing / what to watch for

- The `${POSTGRES_USER:-postgres}` syntax in the compose file is *compose's* variable substitution
  reading the `.env` file in the project root — it's not the same mechanism as the container's own
  environment. The `:-` provides a default so the file works even with no `.env` present.
- Two ports that look like one: the `5432:5432` mapping means "host 5432 → container 5432." Only the
  left side is negotiable, which is why it's parameterized as `POSTGRES_PORT` — if something else on
  the machine already holds 5432, that's the knob to turn, and `DATABASE_URL` has to move with it.

<!-- TODO(Christine): add anything that actually broke while bringing this up — port conflicts,
     image pull issues, .env not being picked up — the plan calls this the most valuable section
     and it should be first-hand. -->

## If I did this again

Probably nothing structural. The one thing I'd flag is that pinning exact versions across the board
is the right call for CI reproducibility but means dependency updates are a manual chore; a real
long-lived project would want Dependabot or `pip-compile` with a separate `.in` file. Not worth the
tooling detour here.

## Exit criterion

`docker compose up -d` → a running, empty Postgres reachable from the host:

```
$ docker compose up -d
$ docker compose ps          # db healthy
$ psql "postgresql://postgres:postgres@localhost:5432/cyber_risk" -c '\dt'
Did not find any relations.
```

Empty is correct — tables arrive in Stage 2.
