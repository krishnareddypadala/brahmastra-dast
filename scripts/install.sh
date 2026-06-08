#!/usr/bin/env bash
# BRAHMASTRA DAST - Path A installer (Cloud AI, no GPU required)
#
# Installs the scanner core (Python + Postgres + code) and leaves you with a
# running dashboard at http://localhost:8888. You then provide a cloud-AI key
# (Gemini / Claude / OpenAI) per scan from the dashboard.
#
# Time to first scan: ~10 to 15 minutes.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/krishnareddypadala/brahmastra-dast/main/scripts/install.sh | bash
#   # or
#   ./scripts/install.sh
#
# Safe to re-run: skips steps that are already done.

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration (override via env var before running)
# ---------------------------------------------------------------------------
REPO_URL="${REPO_URL:-https://github.com/krishnareddypadala/brahmastra-dast.git}"
INSTALL_DIR="${INSTALL_DIR:-$HOME/brahmastra-dast}"
VENV_DIR="${VENV_DIR:-$HOME/brahmastra-env}"
DB_USER="${DB_USER:-brahmastra}"
DB_PASS="${DB_PASS:-brahmastra}"
DB_NAME="${DB_NAME:-brahmastra}"
SCANNER_PORT="${SCANNER_PORT:-8888}"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
green() { printf "\033[32m%s\033[0m\n" "$*"; }
yellow() { printf "\033[33m%s\033[0m\n" "$*"; }
red() { printf "\033[31m%s\033[0m\n" "$*"; }
step() { printf "\n\033[1;34m==> %s\033[0m\n" "$*"; }

require_linux() {
    if [[ "$(uname)" != "Linux" ]]; then
        red "This installer targets Linux (Ubuntu / Debian / WSL2). Detected: $(uname)"
        red "For macOS / Windows, see SETUP.md for manual steps."
        exit 1
    fi
}

require_sudo() {
    if ! sudo -n true 2>/dev/null; then
        yellow "sudo is required. You may be prompted for your password."
    fi
}

apt_pkg_installed() { dpkg -s "$1" >/dev/null 2>&1; }

# ---------------------------------------------------------------------------
# 1. Pre-flight
# ---------------------------------------------------------------------------
step "Pre-flight checks"
require_linux
require_sudo

# ---------------------------------------------------------------------------
# 2. System dependencies
# ---------------------------------------------------------------------------
step "Installing system dependencies (python3, postgresql, git, curl)"
NEEDS=()
for p in python3 python3-pip python3-venv postgresql postgresql-contrib git curl build-essential; do
    apt_pkg_installed "$p" || NEEDS+=("$p")
done
if [[ ${#NEEDS[@]} -gt 0 ]]; then
    sudo apt update -q
    sudo DEBIAN_FRONTEND=noninteractive apt install -y -q "${NEEDS[@]}"
    green "Installed: ${NEEDS[*]}"
else
    green "All system packages already present."
fi

# ---------------------------------------------------------------------------
# 3. Postgres
# ---------------------------------------------------------------------------
step "Ensuring PostgreSQL is running"
sudo systemctl enable --now postgresql
pg_isready -q || { red "Postgres did not start cleanly"; exit 1; }
green "Postgres is running."

step "Creating database role + database (idempotent)"
if ! sudo -u postgres psql -tAc "SELECT 1 FROM pg_user WHERE usename='${DB_USER}'" | grep -q 1; then
    sudo -u postgres createuser "${DB_USER}"
    green "Created role: ${DB_USER}"
else
    yellow "Role ${DB_USER} already exists. Skipping creation."
fi
sudo -u postgres psql -c "ALTER USER ${DB_USER} WITH PASSWORD '${DB_PASS}';" >/dev/null
if ! sudo -u postgres psql -tAc "SELECT 1 FROM pg_database WHERE datname='${DB_NAME}'" | grep -q 1; then
    sudo -u postgres createdb -O "${DB_USER}" "${DB_NAME}"
    green "Created database: ${DB_NAME}"
else
    yellow "Database ${DB_NAME} already exists. Skipping creation."
fi

# ---------------------------------------------------------------------------
# 4. Clone / update the repo
# ---------------------------------------------------------------------------
step "Cloning or updating BRAHMASTRA DAST"
if [[ -d "${INSTALL_DIR}/.git" ]]; then
    yellow "Existing repo at ${INSTALL_DIR}. Pulling latest..."
    git -C "${INSTALL_DIR}" pull --ff-only
else
    git clone "${REPO_URL}" "${INSTALL_DIR}"
fi
green "Code at: ${INSTALL_DIR}"

# ---------------------------------------------------------------------------
# 5. Python venv + dependencies
# ---------------------------------------------------------------------------
step "Creating Python virtual environment"
if [[ ! -d "${VENV_DIR}" ]]; then
    python3 -m venv "${VENV_DIR}"
    green "Created venv: ${VENV_DIR}"
else
    yellow "Venv already exists at ${VENV_DIR}. Reusing."
fi
# shellcheck disable=SC1091
source "${VENV_DIR}/bin/activate"

step "Installing Python dependencies"
pip install --upgrade pip --quiet
pip install -r "${INSTALL_DIR}/requirements.txt" --quiet
green "Dependencies installed."

# ---------------------------------------------------------------------------
# 6. Apply migrations
# ---------------------------------------------------------------------------
step "Applying database migrations"
for f in "${INSTALL_DIR}"/server/migrations/*.sql; do
    PGPASSWORD="${DB_PASS}" psql -h 127.0.0.1 -U "${DB_USER}" -d "${DB_NAME}" -f "$f" >/dev/null 2>&1 \
        || yellow "  (migration $(basename "$f") possibly already applied; continuing)"
done
TABLES=$(PGPASSWORD="${DB_PASS}" psql -h 127.0.0.1 -U "${DB_USER}" -d "${DB_NAME}" -tAc "SELECT count(*) FROM information_schema.tables WHERE table_schema='public'")
green "Database has ${TABLES} tables."

# ---------------------------------------------------------------------------
# 7. Start the DAST server
# ---------------------------------------------------------------------------
step "Starting the DAST server on port ${SCANNER_PORT}"
if ss -tln 2>/dev/null | awk '{print $4}' | grep -q ":${SCANNER_PORT}\$"; then
    yellow "Port ${SCANNER_PORT} already in use. Skipping launch."
    yellow "Stop the other process and re-run, or set SCANNER_PORT=<other>."
else
    cd "${INSTALL_DIR}"
    nohup "${VENV_DIR}/bin/python3" -m uvicorn server.api:app \
        --host 0.0.0.0 --port "${SCANNER_PORT}" \
        > "${HOME}/brahmastra-dast.log" 2>&1 < /dev/null &
    disown -a
    sleep 2
    if ss -tln 2>/dev/null | awk '{print $4}' | grep -q ":${SCANNER_PORT}\$"; then
        green "Scanner started. Log: ${HOME}/brahmastra-dast.log"
    else
        red "Scanner failed to bind to port ${SCANNER_PORT}. Check log:"
        tail -20 "${HOME}/brahmastra-dast.log"
        exit 1
    fi
fi

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------
green ""
green "================================================================"
green "  BRAHMASTRA DAST is up. Open the dashboard:"
green "    http://localhost:${SCANNER_PORT}"
green ""
green "  Next steps:"
green "    1. Open the dashboard in your browser."
green "    2. In the 'AI Mode' dropdown, select 'Gemini 2.5 Flash (Google)'."
green "    3. Get a free API key at https://aistudio.google.com/apikey"
green "    4. Paste the key in the field that appears."
green "    5. Enter a target URL (e.g. https://httpbin.org) and click Launch Scan."
green ""
green "  Privacy note: scan data is sent to the chosen cloud provider."
green "  For a fully on-prem setup with BRAHMASTRA 0.3 (no data leaves your"
green "  machine), run: ./scripts/install-local.sh"
green ""
green "  Stop the scanner with:  pkill -f 'uvicorn server.api:app'"
green "  Full docs:              ${INSTALL_DIR}/SETUP.md"
green "================================================================"
