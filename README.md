# AI-SOC — AI-Powered Security Operations Center

> **Phase 1 Complete** — Real-time anomaly detection · Compliance mapping · Live SOC dashboard

[![Build & Publish Docker Images](https://github.com/Seenu7x/AI-SOC/actions/workflows/docker-publish.yml/badge.svg)](https://github.com/Seenu7x/AI-SOC/actions/workflows/docker-publish.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

---

## 🚀 Quick Start — Run Anywhere

> **Requirements:** Docker + Docker Compose (no Python, no pip, nothing else needed)

```bash
# 1. Clone the repo
git clone https://github.com/Seenu7x/AI-SOC.git
cd AI-SOC

# 2. Create your .env file from the template (REQUIRED — never committed to git)
cp .env.example .env
```

Open `.env` and set at minimum:
```env
DB_PASSWORD=aisoc_password
DATABASE_URL=postgresql://aisoc:aisoc_password@db:5432/aisoc_db
SECRET_KEY=change-this-to-any-random-string
API_KEY=change-this-to-any-random-key
ADMIN_PASSWORD=aisoc-admin-2024
ANALYST_PASSWORD=aisoc-analyst-2024
```

```bash
# 3. Start all services (fresh volume — avoids password mismatch)
docker compose down -v
docker compose up -d

# 4. Open the dashboard
# → http://localhost:3000
```

> ⚠️ **Always run `docker compose down -v` before the first `up`** on a fresh clone. This ensures the PostgreSQL volume is initialized with the password in your `.env` file.

---

## 📐 Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  DATA SOURCES                                               │
│  auth.log  syslog  ufw.log  nginx  Docker container logs   │
└──────────────────────┬──────────────────────────────────────┘
                       │ tail -F  (per-file threads)
┌──────────────────────▼──────────────────────────────────────┐
│  AI-SOC Log Agent                                           │
│  EventEnricher · BruteForceDetector · DockerWatcher         │
│                    POST /api/v1/events/bulk                  │
└──────────────────────┬──────────────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────────────┐
│  FastAPI Backend  (port 8000)                               │
│  Events · Alerts · ML Models · Compliance APIs             │
│                                                             │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  Dual Isolation Forest                               │  │
│  │  Auth Model (login)  +  Net Model (network/system)  │  │
│  │  10 features · 4-level severity · auto-alerts        │  │
│  └──────────────────────────────────────────────────────┘  │
└──────────────────────┬──────────────────────────────────────┘
          ┌────────────┼────────────┐
          ▼            ▼            ▼
      PostgreSQL     Redis      model .joblib
      (events,       (future    files
       alerts,       queue)
       compliance)
                       │
┌──────────────────────▼──────────────────────────────────────┐
│  Nginx Dashboard  (port 3000)                               │
│  Real-time SOC UI · Charts · Alerts · Compliance coverage   │
└─────────────────────────────────────────────────────────────┘
```

---

## 🐳 Docker Images

Pre-built images are automatically published to GitHub Container Registry on every push to `main`:

| Image | Description |
|-------|-------------|
| `ghcr.io/Seenu7x/ai-soc-app:latest` | FastAPI backend + ML engine |
| `ghcr.io/Seenu7x/ai-soc-log-agent:latest` | Real-time log ingestion agent |

---

## 📦 Running with Pre-Built Images (Recommended)

```bash
git clone https://github.com/Seenu7x/AI-SOC.git
cd AI-SOC

# Copy env template and set your passwords
cp .env.example .env
nano .env   # set ADMIN_PASSWORD, ANALYST_PASSWORD, or just use ai-soc.sh below

# Pull and run (uses docker-compose.prod.yml — no build needed)
bash ai-soc.sh
```

### Manual pull-and-run (no deploy script):
```bash
cp .env.example .env
# Edit .env with your passwords ...

docker compose -f docker-compose.prod.yml pull
docker compose -f docker-compose.prod.yml up -d
```

---

## 🔧 Development Setup (Build Locally)

```bash
git clone https://github.com/Seenu7x/AI-SOC.git
cd AI-SOC

cp .env.example .env
# Edit .env ...

# Build and run from source
docker compose up -d --build

# Or run without Docker (Python 3.11+)
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python main.py
```

---

## 🔐 Authentication

All write operations are protected. Get a token first:

```bash
# Login → get JWT
curl -X POST http://localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "YOUR_ADMIN_PASSWORD"}'

# Use the token
curl -X POST http://localhost:8000/api/v1/models/train \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"contamination_rate": 0.01}'
```

| Account | Default password (set in `.env`) | Access |
|---------|----------------------------------|--------|
| `admin` | `ADMIN_PASSWORD` env var | Train models, manage all alerts |
| `analyst` | `ANALYST_PASSWORD` env var | Update alert status, view everything |

> Dashboard GET endpoints are **open** — no login needed for the SOC UI.

---

## 🌐 Service Endpoints

| Service | URL | Description |
|---------|-----|-------------|
| Dashboard | http://localhost:3000 | Real-time SOC UI |
| Backend API | http://localhost:8000 | FastAPI REST API |
| Swagger Docs | http://localhost:8000/docs | Interactive API docs |
| Health Check | http://localhost:8000/health | System status |
| Login | POST http://localhost:8000/auth/login | Get JWT token |

---

## 📋 API Quick Reference

```bash
BASE=http://localhost:8000/api/v1
TOKEN="Bearer <your-jwt>"

# Events
GET    $BASE/events?limit=100&anomalies_only=true
POST   $BASE/events          # requires auth
POST   $BASE/events/bulk     # requires auth (or API key)
GET    $BASE/events/statistics/summary?hours=24

# Alerts
GET    $BASE/alerts?severity=high&status_filter=open
PATCH  $BASE/alerts/{id}     # requires JWT

# ML Models
POST   $BASE/models/train    # requires JWT
GET    $BASE/models/info
GET    $BASE/models/versions
POST   $BASE/models/re-score # requires JWT

# Compliance
GET    $BASE/compliance/status
GET    $BASE/compliance/frameworks
POST   $BASE/compliance/reports/generate
```

---

## 🧪 Testing

```bash
# Train the model (after some events exist)
curl -X POST http://localhost:8000/api/v1/models/train \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"contamination_rate": 0.01, "n_estimators": 100}'

# Check health
curl http://localhost:8000/health

# View API docs
# → http://localhost:8000/docs
```

---

## ⚙️ Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SECRET_KEY` | *(auto-generated by ai-soc.sh)* | JWT signing key |
| `ADMIN_PASSWORD` | `aisoc-admin-2024` | Admin account password |
| `ANALYST_PASSWORD` | `aisoc-analyst-2024` | Analyst account password |
| `API_KEY` | *(auto-generated)* | Internal key for log agent |
| `DB_PASSWORD` | *(auto-generated)* | PostgreSQL password |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | `480` | JWT expiry (8 hours) |
| `MIN_TRAINING_SAMPLES` | `100` | Min events before training |
| `CONTAMINATION_RATE` | `0.01` | Isolation Forest contamination |

---

## 🗂️ Project Structure

```
AI-SOC/
├── .github/workflows/
│   └── docker-publish.yml   # Auto-build & push to GHCR
├── app/
│   ├── api/                 # FastAPI route handlers
│   ├── core/                # Config, auth, rate limiting
│   ├── db/                  # Database session
│   ├── models/              # SQLAlchemy ORM models
│   ├── schemas/             # Pydantic validation schemas
│   └── services/            # ML engine + compliance service
├── dashboard/
│   └── index.html           # Real-time SOC dashboard
├── Dockerfile               # App container
├── Dockerfile.agent         # Log agent container
├── docker-compose.yml       # Dev (build from source)
├── docker-compose.prod.yml  # Prod (pull from GHCR)
├── nginx.conf               # Production Nginx config
├── log_agent.py             # Real-time log ingestion agent
├── main.py                  # FastAPI application entry point
├── ai-soc.sh                # One-command deploy script
└── requirements.txt
```

---

## 📊 Compliance Frameworks

The system automatically maps every security event to relevant controls across:

| Framework | Controls |
|-----------|----------|
| NIST Cybersecurity Framework 1.1 | 11 controls |
| ISO/IEC 27001:2022 | 8 controls |
| SOC 2 Type II | 8 controls |
| GDPR | 5 controls |

---

## 🛑 Stopping & Cleanup

```bash
# Stop all containers (data preserved)
docker compose down

# Stop and wipe all data (fresh start)
docker compose down -v
docker compose up -d

# View logs
docker compose logs -f app
docker compose logs -f db
```

---

## 🔧 Troubleshooting

### ❌ `password authentication failed for user "aisoc"`

This means the PostgreSQL Docker volume was initialized with a different password than what your `.env` has.

**Fix:**
```bash
# Wipe the old volume and restart fresh
docker compose down -v
docker compose up -d
```

> `down -v` deletes the postgres volume. Docker re-creates it with the correct password from your `.env` on next startup.

### ❌ No `.env` file / app won't start

```bash
cp .env.example .env
# Edit .env and set DB_PASSWORD and DATABASE_URL
docker compose down -v && docker compose up -d
```

### ❌ Container name conflict on startup

```bash
docker rm -f aisoc-db aisoc-redis aisoc-app aisoc-dashboard
docker compose up -d
```

---

## 🏫 Academic Project

This is a Final Year B.E. project — AI-SOC: AI-Powered Security Operations Center.

**Tech stack:** FastAPI · scikit-learn · SQLAlchemy · PostgreSQL · Redis · Docker · Nginx · Chart.js
