# AI-SOC Production Change Notice
**Date:** 2026-05-16 | **Environment:** Docker Compose Stack

---

## Summary
Four bugs were fixed to make `normal_data_generator.py`, `anomaly_simulator.py`, and `brute_force_demo.py` work correctly against the running backend.

---

## Change 1 — Critical: Fix Login Crash (bcrypt Incompatibility)

**File:** `app/core/auth.py`  
**Impact:** 🔴 HIGH — `/auth/login` was crashing for ALL users, making model training impossible.

**Root Cause:** `passlib 1.7.4` is incompatible with `bcrypt 5.0.0` (installed by pip). Passlib's internal wrap-bug detection sends a 73-byte secret to bcrypt, which now rejects it.

**Fix:** Replaced `passlib.CryptContext` with direct `bcrypt` library calls.

```diff
- from passlib.context import CryptContext
- pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

+ import bcrypt as _bcrypt
+ def hash_password(plain: str) -> str:
+     return _bcrypt.hashpw(plain.encode(), _bcrypt.gensalt()).decode()
+ def verify_password(plain: str, hashed: str) -> bool:
+     return _bcrypt.checkpw(plain.encode(), hashed.encode())
```

> [!IMPORTANT]
> **Production action required:** Copy the updated `app/core/auth.py` into the container and restart, OR rebuild the Docker image with `bcrypt==4.0.1` pinned in `requirements.txt`. The current image must have the file copied in manually until next rebuild.
>
> ```bash
> docker cp app/core/auth.py aisoc-app:/app/app/core/auth.py
> docker exec aisoc-app find /app -name "*.pyc" -delete
> docker compose restart app
> ```

---

## Change 2 — High: Add API Key Header to Scripts

**Files:** `normal_data_generator.py`, `anomaly_simulator.py`  
**Impact:** 🟠 HIGH — All event ingestion and alert fetching calls were returning 401 Unauthorized.

**Root Cause:** The `/api/v1/events`, `/api/v1/events/bulk`, and `/api/v1/alerts` endpoints require `require_auth` (Bearer token OR `X-API-Key`). The scripts were sending requests with no auth header.

**Fix:** Added `HEADERS = {"X-API-Key": "aisoc-internal-api-key-123"}` and passed it to every `requests.post/get` call.

```diff
+ API_KEY = "aisoc-internal-api-key-123"   # matches .env API_KEY
+ HEADERS = {"X-API-Key": API_KEY, "Content-Type": "application/json"}

- requests.post(f"{BASE_URL}/events/bulk", json={"events": events}, timeout=30)
+ requests.post(f"{API_V1}/events/bulk", json={"events": events}, headers=HEADERS, timeout=30)
```

> [!NOTE]
> No server-side changes needed. Script files only. Ensure `API_KEY` in the scripts matches the `API_KEY` value in `.env`.

---

## Change 3 — High: JWT Token for Model Training

**File:** `normal_data_generator.py`  
**Impact:** 🟠 HIGH — `POST /api/v1/models/train` uses `require_jwt` (Bearer token only, not API key), so training always failed with 401.

**Fix:** Added a `get_jwt_token()` helper that logs in as admin before calling `/models/train`, then passes the Bearer token.

```diff
+ def get_jwt_token():
+     r = requests.post(f"{BASE_URL}/auth/login",
+                       json={"username": "admin", "password": "aisoc-admin-2024"})
+     return r.json().get("access_token")

  def train_model():
+     token = get_jwt_token()
+     auth_headers = {"Authorization": f"Bearer {token}"}
-     r = requests.post(f"{BASE_URL}/models/train", headers=HEADERS, ...)
+     r = requests.post(f"{API_V1}/models/train", headers=auth_headers, ...)
```

> [!NOTE]
> No server-side changes needed. Script file only. If `ADMIN_PASSWORD` is changed in `.env`, update `ADMIN_PASS` constant in `normal_data_generator.py` to match.

---

## Change 4 — Medium: Enable Redis Password for Brute-Force Demo

**Files:** `docker-compose.yml`, `.env`  
**Impact:** 🟡 MEDIUM — `brute_force_demo.py` was getting `ERR AUTH` (no password configured) instead of `WRONGPASS` responses. The demo was non-functional.

**Fix:** Added `requirepass` to the Redis service so it enforces authentication and returns proper `WRONGPASS` on bad credentials.

```diff
# docker-compose.yml
  redis:
    image: redis:7-alpine
+   command: redis-server --requirepass ${REDIS_PASSWORD:-aisoc-redis-pass}
    healthcheck:
-     test: ["CMD", "redis-cli", "ping"]
+     test: ["CMD", "redis-cli", "-a", "${REDIS_PASSWORD:-aisoc-redis-pass}", "ping"]

  app:
    environment:
-     - REDIS_URL=redis://redis:6379/0
+     - REDIS_URL=redis://:${REDIS_PASSWORD:-aisoc-redis-pass}@redis:6379/0
```

```diff
# .env
- REDIS_URL=redis://redis:6379/0
+ REDIS_PASSWORD=aisoc-redis-pass
+ REDIS_URL=redis://:aisoc-redis-pass@redis:6379/0
```

> [!IMPORTANT]
> **Production action required:** Recreate the Redis container and restart the app:
> ```bash
> docker compose up -d --force-recreate redis
> docker compose restart app
> ```

---

## Production Deployment Checklist

```
[ ] 1. Copy patched auth.py into container:
        docker cp app/core/auth.py aisoc-app:/app/app/core/auth.py
        docker exec aisoc-app find /app -name "*.pyc" -delete

[ ] 2. Recreate Redis with password:
        docker compose up -d --force-recreate redis

[ ] 3. Restart the app container:
        docker compose restart app

[ ] 4. Verify health:
        curl http://localhost:8000/health

[ ] 5. Verify login works:
        curl -X POST http://localhost:8000/auth/login \
             -H "Content-Type: application/json" \
             -d '{"username":"admin","password":"aisoc-admin-2024"}'

[ ] 6. Run verification sequence:
        python3 normal_data_generator.py --count 500
        python3 anomaly_simulator.py --step 6 --pause 2
        python3 brute_force_demo.py
```

> [!TIP]
> For a permanent fix on next rebuild, pin `bcrypt==4.0.1` in `requirements.txt` instead of relying on `passlib[bcrypt]` pulling the latest bcrypt.
