#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# AI-SOC Git Setup Script
# Run this ONCE to initialise the repo and push to GitHub
#
# Usage:
#   bash git-setup.sh <your-github-username> <your-repo-name>
#
# Example:
#   bash git-setup.sh sivaseenu AI-SOC
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

GITHUB_USER="${1:-}"
REPO_NAME="${2:-AI-SOC}"

CYAN='\033[0;36m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
log()  { echo -e "${CYAN}[setup]${NC} $*"; }
ok()   { echo -e "${GREEN}[✓]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[✗]${NC} $*"; exit 1; }

[[ -z "$GITHUB_USER" ]] && err "Usage: bash git-setup.sh <github-username> [repo-name]  (default repo-name: AI-SOC)"

# ── Substitute your GitHub username into template files ──────────────────────
log "Setting GitHub username to: ${GITHUB_USER}"

# README
sed -i "s|GITHUB_USERNAME|${GITHUB_USER}|g" README.md

# docker-compose.prod.yml
sed -i "s|GITHUB_USERNAME|${GITHUB_USER}|g" docker-compose.prod.yml

# GitHub Actions workflow
sed -i "s|GITHUB_USERNAME|${GITHUB_USER}|g" .github/workflows/docker-publish.yml

ok "Username substituted in all template files"

# ── Initialise git repo ──────────────────────────────────────────────────────
if [[ ! -d .git ]]; then
    log "Initialising git repository …"
    git init
    git branch -M main
    ok "Git repository initialised"
else
    warn ".git already exists — skipping init"
fi

# ── Stage all files ──────────────────────────────────────────────────────────
log "Staging files …"
git add .
git status --short | head -30
ok "Files staged"

# ── First commit ─────────────────────────────────────────────────────────────
log "Creating initial commit …"
git commit -m "🚀 Initial commit — AI-SOC Phase 1 complete

Features:
- Dual Isolation Forest anomaly detection (auth + network models)
- Real-time log agent (system logs + Docker container monitoring)
- Compliance mapping: NIST CSF, ISO 27001, SOC 2, GDPR
- JWT + API key authentication with rate limiting
- Real-time SOC dashboard (dark theme, Chart.js)
- Docker Compose full stack (app, db, redis, agent, nginx)
- GitHub Actions CI/CD → GHCR auto-publish on push to main
- One-command deploy: bash ai-soc.sh"
ok "Initial commit created"

# ── Add remote and push ──────────────────────────────────────────────────────
REMOTE_URL="https://github.com/${GITHUB_USER}/${REPO_NAME}.git"
log "Adding remote: ${REMOTE_URL}"

if git remote get-url origin &>/dev/null; then
    warn "Remote 'origin' already exists — updating URL"
    git remote set-url origin "${REMOTE_URL}"
else
    git remote add origin "${REMOTE_URL}"
fi

echo ""
warn "About to push to: ${REMOTE_URL}"
warn "Make sure you have created the repo on GitHub first!"
warn "Go to: https://github.com/new"
warn "  • Repository name: ${REPO_NAME}"
warn "  • Visibility: Public (required for free GHCR pulls)"
warn "  • Do NOT initialise with README (we're pushing our own)"
echo ""
read -rp "Press ENTER when the GitHub repo is ready, or Ctrl+C to cancel … "

log "Pushing to GitHub …"
git push -u origin main
ok "Code pushed to GitHub!"

# ── Done ─────────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  ✅ Repository is live!${NC}"
echo -e "${GREEN}════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  📁 GitHub Repo    → https://github.com/${GITHUB_USER}/${REPO_NAME}"
echo -e "  🔄 Actions        → https://github.com/${GITHUB_USER}/${REPO_NAME}/actions"
echo -e "  📦 Packages       → https://github.com/${GITHUB_USER}?tab=packages"
echo ""
echo -e "  ⏳ GitHub Actions is now building Docker images …"
echo -e "     (takes ~3-5 minutes on first build)"
echo ""
echo -e "  Once images are published, anyone can run:"
echo -e "    git clone https://github.com/${GITHUB_USER}/${REPO_NAME}.git"
echo -e "    cd ${REPO_NAME} && bash ai-soc.sh"
echo ""
warn "IMPORTANT: Make the packages public after first build:"
warn "  https://github.com/${GITHUB_USER}?tab=packages"
warn "  → Click each package → Package settings → Change visibility → Public"
