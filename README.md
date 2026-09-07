# Threat Intelligence Aggregator

A threat intelligence aggregation and SOC operations platform built on FastAPI and MongoDB. It collects IOCs from OSINT sources, runs them through a normalization/enrichment/correlation/MITRE-mapping/risk-scoring pipeline, ingests raw auth/nginx/DNS logs for detection, manages incidents, and exposes a D3.js dashboard for visualizing the results.

[![Python](https://img.shields.io/badge/Python-3.11-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.109-green.svg)](https://fastapi.tiangolo.com/)
[![MongoDB](https://img.shields.io/badge/MongoDB-7.0-brightgreen.svg)](https://www.mongodb.com/)

## What this is

A two-stage system:

1. **Threat intelligence pipeline** — pulls indicators from AlienVault OTX, Abuse.ch, and OpenPhish, then runs them through nine stages: collect → normalize → enrich → correlate → MITRE ATT&CK map → risk score → generate alerts → summarize → persist to MongoDB.
2. **SOC operations layer** — parses raw auth/nginx/DNS log lines, matches them against the collected IOCs and a small set of stateful behavioral rules (SSH brute force, web scanning, DNS DGA-style query bursts), and produces detections that can be tied to incidents.

A FastAPI app (`main.py`) exposes both stages as a REST API plus an HTML dashboard.

## Architecture

```
OSINT sources (AlienVault, Abuse.ch, OpenPhish)
        │
        ▼
Collect → Normalize → Enrich → Correlate → MITRE Map → Risk Score → Alert → Summary
        │                                                                      │
        └──────────────────────────► MongoDB ◄────────────────────────────────┘
                                   (events, alerts, detections, incidents)
                                        ▲
        ┌───────────────────────────────┴────────────────────────────┐
        │                                                             │
Log ingestion (auth/nginx/dns)  ──►  DetectionEngine  ──►  IncidentManager
                                                                       │
                                                              Dashboard (/dashboard)
```

## Project structure

```
SOC/
├── main.py                    # FastAPI app: routes, lifespan, exception handling
├── collectors/                 # OSINT collectors
│   ├── base.py                 # BaseCollector (shared httpx client lifecycle)
│   ├── alienvault.py           # AlienVault OTX pulses
│   ├── abusedb.py               # Abuse.ch
│   └── openphish.py            # OpenPhish feed
├── core/                       # Intelligence pipeline
│   ├── normalizer.py            # Raw source data -> NormalizedEvent
│   ├── enrichment.py            # GeoIP / ASN / WHOIS enrichment
│   ├── correlation.py           # Time-window based event correlation
│   ├── mitre_mapper.py          # MITRE ATT&CK technique/tactic mapping
│   ├── risk_scoring.py          # Weighted 0-10 risk score + severity
│   ├── alert_generator.py       # Turns scored events into Alert objects
│   ├── analyst_summary.py       # Human-readable summary generation
│   └── incident_manager.py      # Incident create/update/notes lifecycle
├── ingestion/                  # Log parsing and validation
│   ├── log_parser.py            # Regex parsers for auth/nginx/dns log lines
│   └── event_ingestor.py        # Parses + validates into Pydantic log models
├── detection/
│   └── detection_engine.py      # IOC matching + stateful behavioral heuristics
├── storage/                    # MongoDB access (Motor, async)
│   ├── database.py               # Connection singleton, health check
│   ├── models.py                 # Document models (Event/Alert/Detection/Incident)
│   └── repositories.py           # Repository pattern per collection
├── security/                   # Input validation, sanitization, rate limiting
│   ├── validation.py             # Pydantic schemas (extra="forbid")
│   ├── sanitizer.py               # SQL/command-injection pattern defusing
│   └── rate_limiter.py            # slowapi IP-based rate limiter
├── visualization/               # Dashboard (read-only)
│   ├── dashboard.py               # /dashboard routes
│   ├── graph_view.py               # Force-directed graph data
│   ├── timeline_view.py            # Timeline events
│   ├── pipeline_status.py          # Status/health summary
│   ├── cluster_details_panel.py    # Per-cluster detail lookup
│   └── templates/dashboard.html
├── utils/
│   ├── config.py                  # Pydantic BaseSettings (reads .env)
│   └── logger.py                  # structlog setup
├── demo.py                     # Stage 1 script: run the intel pipeline standalone
├── demo_soc.py                  # Stage 2 script: ingest logs, detect, create incident
├── requirements.txt
├── Dockerfile
└── docker-compose.yml           # mongodb + web services
```

## Detection engine, specifically

`detection/detection_engine.py` does two things per ingested log line:

- **Static IOC matching**: extracts IPs/domains/URLs from the log and checks them against an in-memory cache built from the `events` collection.
- **Stateful behavioral heuristics**, tracked in module-level in-process dictionaries (not persisted, reset on restart):
  - **SSH brute force (T1110)** — 3+ failed auth attempts from one source IP within 60s.
  - **Active scanning (T1595)** — 5+ suspicious/403/404 nginx requests from one client IP within 60s.
  - **DGA/tunneling (T1568)** — 5+ unique domains queried by one client IP within 10s.

Because the counters are in-process, they do not survive a process restart and will not work correctly if you run more than one API worker/replica without moving that state into a shared store.

## Engineering notes

Points worth knowing about how this is actually built, not just what it does:

- **Repository pattern is enforced, not just documented.** Every MongoDB access goes through `storage/repositories.py` — no route or pipeline stage touches `db[collection]` directly. Each repository also owns its own `create_indexes()`, called once at startup via the FastAPI `lifespan` handler in `main.py`, so indexes exist before the first request is served.
- **Correlation uses stable, content-derived IDs, not database-generated ones.** `CorrelationEngine._generate_event_id` hashes `value:source:type` (MD5, truncated) so the same IOC always maps to the same graph node across separate collection runs, and `_generate_correlation_id` hashes the sorted set of related IDs (SHA-1) so a cluster's ID doesn't depend on iteration order. This is what lets the D3 dashboard draw a consistent graph across repeated `/api/v1/collect` calls instead of duplicating nodes every run.
- **Correlation strength is a bounded weighted score, not a boolean match.** Four signals (same IOC type, same source feed, same ASN, same country) each contribute a fixed weight, normalized against the maximum possible weight to produce a 0–1 strength — with explicit guards against matching on placeholder data (`AS00000`, `"Unknown"`, `"Private Network"`) so junk enrichment doesn't create false correlations.
- **Defense in depth on untrusted input, at two separate layers.** Pydantic models with `extra="forbid"` reject any unexpected field outright (`security/validation.py`, `ingestion/event_ingestor.py`), and `Sanitizer` separately defuses SQL/command-injection substrings and strips HTML/null bytes on every string field before it's persisted (`security/sanitizer.py`, applied again at the repository layer in `insert_one`/`insert_many`). Log ingestion also explicitly strips parser-internal keys (`raw`, `log_line`, `_parser_meta`) before strict validation, closing a specific key-injection path rather than relying on `extra="forbid"` alone.
- **Behavioral detection windows are self-pruning, not just self-expiring.** Each rule in `detection_engine.py` (brute force, scanning, DNS burst) prunes its own timestamp list on every event (`if now - t <= window`) rather than relying on a background sweep or TTL, so memory use is bounded by recent activity, not total historical events.
- **The IOC cache is loaded once and explicitly invalidated**, not re-queried per log line — `DetectionEngine._load_ioc_cache` builds the lookup map on first use and `clear_cache()` is the only way to force a reload, which keeps repeated `/api/v1/ingest/*` calls cheap after a `/api/v1/collect` run.
- **MongoDB connection is a single managed singleton** (`storage/database.py`) with pool bounds (`maxPoolSize=10`), a bounded server-selection timeout, and an explicit `ping` on connect, so a bad `MONGODB_URI` fails fast at startup instead of surfacing as a mysterious timeout on the first request.
- **Global exception handler is the only place stack traces could leak, and it doesn't leak them** — every route already catches its own exceptions and logs the real error server-side via `structlog`, while returning a generic message to the client either way.
- **Docker image drops root before running the app** (`Dockerfile`: `useradd -u 10001` + `USER appuser`), and `.dockerignore`/`.gitignore` keep `.venv`, `venv`, `__pycache__`, and `.env` out of both the image and the repo.

## API endpoints

All endpoints are rate-limited (default 60 req/min/IP, configurable via `RATE_LIMIT_DEFAULT`).

**Threat intelligence**
- `POST /api/v1/collect` — run the 9-stage collection pipeline
- `GET /api/v1/alerts` — list alerts (filter: `severity`, `min_risk_score`)
- `GET /api/v1/alerts/{id}`
- `GET /api/v1/events` — list normalized/correlated threat events

**Log ingestion & detection**
- `POST /api/v1/ingest/auth` / `/ingest/nginx` / `/ingest/dns` — ingest one raw log line, run detection
- `GET /api/v1/detections` — list detections (filter: `log_type`)
- `GET /api/v1/detections/{id}`

**Incidents**
- `POST /api/v1/incidents`
- `GET /api/v1/incidents` — filter: `status`, `severity`
- `GET /api/v1/incidents/{id}`
- `PUT /api/v1/incidents/{id}/status`
- `POST /api/v1/incidents/{id}/notes`

**Dashboard** (read-only, prefix `/dashboard`)
- `GET /dashboard` — HTML page
- `GET /dashboard/api/graph-data` — D3 nodes/edges
- `GET /dashboard/api/timeline`
- `GET /dashboard/api/status`
- `GET /dashboard/api/cluster/{cluster_id}`
- `GET /dashboard/api/incident-stats` — incident/detection/event counts, per-analyst and per-tactic breakdowns

**Other**
- `GET /health` — DB connectivity check

Full interactive docs at `/docs` once the server is running.

## Security controls actually implemented

- Rate limiting per IP via `slowapi` (`security/rate_limiter.py`).
- Strict Pydantic schemas with `extra="forbid"` reject unexpected fields (`security/validation.py`).
- `Sanitizer` (`security/sanitizer.py`) regex-defuses common SQL/command-injection substrings and strips HTML tags/null bytes from string input — this is pattern-based defusing, not a substitute for parameterized queries (MongoDB access here goes through Motor with typed documents, not raw string queries).
- Global exception handler in `main.py` returns a generic 500 body instead of leaking stack traces.
- Repository pattern (`storage/repositories.py`) — routes never touch the MongoDB collections directly.
- Structured JSON logging via `structlog`.
- Dashboard routes are read-only; they never write to the database.
- Docker image runs as a non-root user (`appuser`, uid 10001).

## Requirements

- Python 3.11 (matches the Dockerfile; `requirements.txt` doesn't pin a minimum, but this is what's tested)
- MongoDB 7.0 (local or Atlas)
- Docker + Docker Compose, if you want the containerized path

## Setup

```bash
git clone <this-repo>
cd SOC

python -m venv venv
venv\Scripts\activate        # Windows
source venv/bin/activate     # Linux/Mac

pip install -r requirements.txt
```

Create a `.env` file (see `.env.example`):

```env
MONGODB_URI=mongodb://localhost:27017
MONGODB_DB_NAME=threat_intel
ALIENVAULT_API_KEY=
ABUSEDB_API_KEY=
RATE_LIMIT_DEFAULT=60
LOG_LEVEL=INFO
ENVIRONMENT=development
```

`ALIENVAULT_API_KEY` and `ABUSEDB_API_KEY` are optional — the collectors run without them, just with more limited results. OpenPhish needs no key.

> **Note:** `.env` is git-ignored and was never committed, which is correct. If the credentials currently in your local `.env` (e.g. a MongoDB Atlas connection string) have ever been shared outside this machine, rotate them — a connection string with an embedded username/password is a live secret.

## Running it

**Locally:**
```bash
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

**Docker Compose** (starts MongoDB + the API):
```bash
docker-compose up -d
```
The compose file maps MongoDB's port to the host too, so local demo scripts can still connect to it directly.

**Demo scripts**, for exercising each stage without going through the API:
```bash
python demo.py       # collects from OSINT sources, runs the 9-stage pipeline, prints a summary
python demo_soc.py   # ingests sample logs, runs detection, creates and updates a test incident
```

Once running (via Docker):
- Dashboard: http://localhost:8005/dashboard
- API docs: http://localhost:8005/docs
- Health check: http://localhost:8005/health

## Environment variables

| Variable | Default | Required | Notes |
|---|---|---|---|
| `MONGODB_URI` | `mongodb://localhost:27017` | Yes | |
| `MONGODB_DB_NAME` | `threat_intel` | No | |
| `ALIENVAULT_API_KEY` | none | No | AlienVault OTX works unauthenticated at reduced scope |
| `ABUSEDB_API_KEY` | none | No | |
| `RATE_LIMIT_DEFAULT` | `60` | No | Requests/minute/IP |
| `LOG_LEVEL` | `INFO` | No | |
| `ENVIRONMENT` | `development` | No | Not currently branched on in code |

## Known limitations

- Behavioral detection state (`_FAILED_LOGINS`, `_SCANNING_REQUESTS`, `_DNS_QUERIES` in `detection_engine.py`) lives in process memory. It resets on restart and won't be shared across multiple workers/replicas.
- No automated test suite — `demo.py` / `demo_soc.py` are manual smoke-test scripts, not `pytest` tests.
- No `LICENSE` file is present in the repo despite this being a personal project; add one if you intend others to reuse the code under specific terms.
- The rate limiter's storage is in-memory (`storage_uri="memory://"`), so limits are also per-process, not shared across replicas.

## Testing

There's no automated test suite. To smoke-test manually:

```bash
python demo.py
python demo_soc.py
curl http://localhost:8000/health
```
