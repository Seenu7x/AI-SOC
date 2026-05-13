#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# AI-SOC Deploy Script
# Usage:  bash ai-soc.sh [--reset-db]
#
# What it does:
#   1. Creates .env from .env.example if it doesn't exist
#   2. Auto-generates SECRET_KEY and API_KEY if they are placeholder values
#   3. Builds and starts all 5 Docker containers
#   4. Waits for the app to become healthy
#   5. Prints service URLs and credentials summary
#
# Flags:
#   --reset-db   Wipe the PostgreSQL volume and start fresh (USE WITH CAUTION)
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

RESET_DB=false
for arg in "$@"; do
  [[ "$arg" == "--reset-db" ]] && RESET_DB=true
done

CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log()  { echo -e "${CYAN}[AI-SOC]${NC} $*"; }
ok()   { echo -e "${GREEN}[✓]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[✗]${NC} $*"; exit 1; }

# ── 1. Ensure .env exists ────────────────────────────────────────────────────
if [[ ! -f .env ]]; then
    log "No .env found — creating from .env.example …"
    cp .env.example .env
    warn ".env created. Review and update passwords before going to production."
fi

# ── 2. Auto-generate secrets if still placeholder values ─────────────────────
gen_secret() { openssl rand -hex 32 2>/dev/null || python3 -c "import secrets; print(secrets.token_hex(32))"; }

if grep -q "CHANGE_ME_generate_with_openssl_rand_hex_32" .env 2>/dev/null; then
    NEW_KEY=$(gen_secret)
    sed -i "s|CHANGE_ME_generate_with_openssl_rand_hex_32|${NEW_KEY}|g" .env
    ok "SECRET_KEY auto-generated"
fi

if grep -q "CHANGE_ME_generate_with_openssl_rand_hex_24" .env 2>/dev/null; then
    NEW_API=$(gen_secret)
    sed -i "s|CHANGE_ME_generate_with_openssl_rand_hex_24|${NEW_API}|g" .env
    ok "API_KEY auto-generated"
fi

if grep -q "CHANGE_DB_PASSWORD" .env 2>/dev/null; then
    NEW_DB=$(gen_secret | cut -c1-20)
    sed -i "s|CHANGE_DB_PASSWORD|${NEW_DB}|g" .env
    ok "DB_PASSWORD auto-generated"
fi

# ── 3. Warn about default user passwords ────────────────────────────────────
if grep -q "CHANGE_ME_strong_admin_password" .env 2>/dev/null; then
    warn "ADMIN_PASSWORD is still a placeholder — update .env before production!"
fi

# ── 4. Optional DB reset ─────────────────────────────────────────────────────
if [[ "$RESET_DB" == true ]]; then
    warn "Removing PostgreSQL volume (all data will be lost) …"
    docker compose down -v 2>/dev/null || true
    ok "Volume wiped"
fi

# ── 5. Build & start ─────────────────────────────────────────────────────────
log "Building and starting AI-SOC containers …"
docker compose up -d --build

# ── 6. Wait for health ───────────────────────────────────────────────────────
log "Waiting for backend to become healthy …"
MAX_WAIT=120
ELAPSED=0
until curl -sf http://localhost:8000/health > /dev/null 2>&1; do
    if (( ELAPSED >= MAX_WAIT )); then
        err "Backend did not become healthy within ${MAX_WAIT}s. Check: docker compose logs app"
    fi
    sleep 3
    ELAPSED=$((ELAPSED + 3))
    echo -n "."
done
echo ""

ok "Backend is healthy (${ELAPSED}s)"

# ── 7. Quick smoke test ───────────────────────────────────────────────────────
HEALTH=$(curl -sf http://localhost:8000/health | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('status','?'))" 2>/dev/null \
         || curl -sf http://localhost:8000/health | python -c "import sys,json; d=json.load(sys.stdin); print(d.get('status','?'))" 2>/dev/null \
         || echo "unknown")
log "Health status: ${HEALTH}"

# ── 8. Print summary ─────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  AI-SOC is running!${NC}"
echo -e "${GREEN}════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  🖥️  Dashboard      →  ${CYAN}http://localhost:3000${NC}"
echo -e "  🔌  Backend API    →  ${CYAN}http://localhost:8000${NC}"
echo -e "  📚  Swagger Docs   →  ${CYAN}http://localhost:8000/docs${NC}"
echo -e "  ❤️  Health Check   →  ${CYAN}http://localhost:8000/health${NC}"
echo ""
echo -e "  🔑  Login endpoint →  POST ${CYAN}http://localhost:8000/auth/login${NC}"
echo -e "      Body: {\"username\": \"admin\", \"password\": \"<ADMIN_PASSWORD from .env>\"}"
echo ""
echo -e "  🐳  Container status:"
docker compose ps --format "table {{.Name}}\t{{.Status}}\t{{.Ports}}"
echo ""
warn "Check .env for your ADMIN_PASSWORD and ANALYST_PASSWORD"
warn "To view logs:  docker compose logs -f app"
warn "To stop:       docker compose down"
echo ""
