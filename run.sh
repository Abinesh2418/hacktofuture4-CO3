#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────
#  HTF 4.0 ARENA — Red vs Blue Cyber Battleground
#  Unified launcher: Auth + Red + Blue + Arena Dashboard
# ─────────────────────────────────────────────────────────────────────
set -uo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT_DIR"

RED='\033[0;31m'; BLUE='\033[0;34m'; GREEN='\033[0;32m'
YELLOW='\033[1;33m'; CYAN='\033[0;36m'; PURPLE='\033[0;35m'
NC='\033[0m'; BOLD='\033[1m'

PIDS=()
CLEANED_UP=0

cleanup() {
    [ "$CLEANED_UP" = "1" ] && return; CLEANED_UP=1
    echo ""; echo -e "${YELLOW}Shutting down all services...${NC}"
    for pid in "${PIDS[@]+"${PIDS[@]}"}"; do kill -0 "$pid" 2>/dev/null && kill "$pid" 2>/dev/null || true; done
    sleep 1
    for pid in "${PIDS[@]+"${PIDS[@]}"}"; do kill -0 "$pid" 2>/dev/null && kill -9 "$pid" 2>/dev/null || true; done
    echo -e "${GREEN}All services stopped.${NC}"
}
trap cleanup SIGINT SIGTERM EXIT

banner() {
    echo ""
    echo -e "${PURPLE}${BOLD}════════════════════════════════════════════════════════════${NC}"
    echo -e "${PURPLE}${BOLD}  HTF 4.0 ARENA — Red vs Blue Cyber Battleground${NC}"
    echo -e "${PURPLE}${BOLD}════════════════════════════════════════════════════════════${NC}"
    echo ""
}

log_info()  { echo -e "${GREEN}[INFO]${NC}   $1"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}   $1"; }
log_error() { echo -e "${RED}[ERROR]${NC}  $1"; }

# ── Detect tools ─────────────────────────────────────────────────────

detect_python() {
    if command -v python3 &>/dev/null; then PYTHON=python3
    elif command -v python &>/dev/null; then PYTHON=python
    else log_error "Python 3 not found."; exit 1; fi
    log_info "Python: $($PYTHON --version 2>&1)"
}

HAS_NODE=0
detect_node() {
    if command -v node &>/dev/null && command -v npm &>/dev/null; then
        HAS_NODE=1; log_info "Node.js: $(node --version)"
    else
        log_warn "Node.js/npm not found — frontends will not start"
    fi
}

# ── Port management ──────────────────────────────────────────────────

free_port() {
    local pids; pids=$(lsof -ti :"$1" 2>/dev/null || true)
    [ -n "$pids" ] && { log_warn "Port $1 in use — freeing"; echo "$pids" | xargs kill -9 2>/dev/null || true; sleep 1; }
}

# ── Setup ────────────────────────────────────────────────────────────

setup_env() {
    if [ ! -f "$ROOT_DIR/.env" ]; then
        [ -f "$ROOT_DIR/.env.example" ] && cp "$ROOT_DIR/.env.example" "$ROOT_DIR/.env" || touch "$ROOT_DIR/.env"
        log_info "Created .env"
    fi
}

install_py_deps() {
    log_info "Installing Python dependencies..."
    $PYTHON -m pip install -r "$ROOT_DIR/requirements.txt" --quiet 2>&1 | tail -1 || true
}

install_fe_deps() {
    local dir="$1" name="$2"
    [ -d "$dir" ] && [ -f "$dir/package.json" ] && [ ! -d "$dir/node_modules" ] && {
        log_info "Installing $name frontend deps..."
        (cd "$dir" && npm install --silent 2>&1) || true
    }
}

# ── Service launchers ────────────────────────────────────────────────

start_svc() {
    local name="$1" module="$2" port="$3" color="$4" reload_dir="$5"
    echo -e "${color}[${name}]${NC} Starting on port ${port}..."
    PYTHONPATH="$ROOT_DIR" $PYTHON -m uvicorn "$module" \
        --host 0.0.0.0 --port "$port" --log-level info \
        --reload --reload-dir "$reload_dir" --reload-dir "$ROOT_DIR/core" &
    PIDS+=("$!")
    echo -e "${color}[${name}]${NC} PID: $!"
}

start_fe() {
    local dir="$1" name="$2" port="$3" color="$4"
    [ -d "$dir" ] && [ -f "$dir/package.json" ] || return 0
    echo -e "${color}[${name}]${NC} Starting frontend on port ${port}..."
    (cd "$dir" && npm run dev -- --port "$port" --strictPort) &
    PIDS+=("$!")
}

wait_port() {
    local port=$1 name=$2 i=0
    while ! (echo >/dev/tcp/localhost/$port) 2>/dev/null; do
        i=$((i+1)); [ $i -ge 30 ] && { log_warn "$name (port $port) timed out"; return 1; }; sleep 1
    done
    log_info "$name ready on port $port"
}

# ── Print URLs ───────────────────────────────────────────────────────

print_urls() {
    echo ""
    echo -e "${PURPLE}${BOLD}════════════════════════════════════════════════════════════${NC}"
    echo -e "${PURPLE}${BOLD}  All Services Running${NC}"
    echo -e "${PURPLE}${BOLD}════════════════════════════════════════════════════════════${NC}"
    echo ""
    [ "${S_ARENA:-0}" = "1" ] && {
        echo -e "  ${CYAN}${BOLD}ARENA DASHBOARD${NC}     ${BOLD}http://localhost:5173${NC}"
        echo -e "  ${CYAN}  Login -> Register -> MFA Setup -> Battle${NC}"
        echo ""
    }
    [ "${S_AUTH:-0}" = "1" ] && {
        echo -e "  ${PURPLE}${BOLD}AUTH SERVICE${NC}        http://localhost:8003"
        echo -e "    /auth/register   /auth/login   /scores"
    }
    [ "${S_RED:-0}" = "1" ] && {
        echo -e "  ${RED}${BOLD}RED AGENT${NC}           http://localhost:8001"
        echo -e "    /chat  /scan/recon  /exploit/auto  /report/download"
    }
    [ "${S_BLUE:-0}" = "1" ] && {
        echo -e "  ${BLUE}${BOLD}BLUE AGENT${NC}          http://localhost:8002"
        echo -e "    /remediate/pending  /remediate/approve-all  /scan/ssh"
    }
    [ "${S_RED_FE:-0}" = "1" ]  && echo -e "  ${RED}Red Dashboard${NC}      http://localhost:5175"
    [ "${S_BLUE_FE:-0}" = "1" ] && echo -e "  ${BLUE}Blue Dashboard${NC}     http://localhost:5174"
    echo ""
    echo -e "${PURPLE}${BOLD}════════════════════════════════════════════════════════════${NC}"
    echo -e "  Press ${BOLD}Ctrl+C${NC} to stop all services"
    echo -e "${PURPLE}${BOLD}════════════════════════════════════════════════════════════${NC}"
    echo ""
}

# ── Usage ────────────────────────────────────────────────────────────

usage() {
    cat <<EOF
Usage: $0 [mode]

Modes:
  all        Auth + Red + Blue backends + Arena dashboard (default)
  arena      Auth + backends + Arena dashboard only (no standalone FEs)
  backends   All 3 backends only (auth + red + blue)
  blue       Auth + Blue backend + Blue standalone frontend
  red        Auth + Red backend + Red standalone frontend
  auth       Auth service only
  docker     Docker Compose
  test       Run tests

Ports:
  8003  Auth Service     5173  Arena Dashboard
  8001  Red Agent        5175  Red standalone
  8002  Blue Agent       5174  Blue standalone
EOF
    exit 0
}

# ── Main ─────────────────────────────────────────────────────────────

MODE="${1:-all}"
case "$MODE" in -h|--help|help) usage;; test) detect_python; banner; PYTHONPATH="$ROOT_DIR" $PYTHON -m pytest tests/ -v 2>/dev/null || { for f in tests/test_blue/test_*.py; do [ -f "$f" ] && PYTHONPATH="$ROOT_DIR" $PYTHON "$f"; done; }; exit 0;; docker) detect_python; banner; setup_env; docker compose up --build 2>/dev/null || docker-compose up --build; exit 0;; esac

banner; detect_python; detect_node; echo ""
setup_env; install_py_deps

# Install frontend deps
[ "$HAS_NODE" = "1" ] && case "$MODE" in
    all)     install_fe_deps "$ROOT_DIR/dashboard" "Arena"; install_fe_deps "$ROOT_DIR/red_agent/frontend" "Red"; install_fe_deps "$ROOT_DIR/blue_agent/frontend" "Blue";;
    arena)   install_fe_deps "$ROOT_DIR/dashboard" "Arena";;
    blue)    install_fe_deps "$ROOT_DIR/blue_agent/frontend" "Blue";;
    red)     install_fe_deps "$ROOT_DIR/red_agent/frontend" "Red";;
esac

echo ""

# Load .env
[ -f "$ROOT_DIR/.env" ] && { set -a; source "$ROOT_DIR/.env"; set +a; log_info "Loaded .env"; }

# Flags
S_AUTH=0; S_RED=0; S_BLUE=0; S_ARENA=0; S_RED_FE=0; S_BLUE_FE=0

case "$MODE" in
    all)
        for p in 8001 8002 8003 5173 5174 5175; do free_port $p; done
        start_svc "AUTH" "auth_service.main:app" 8003 "$PURPLE" "$ROOT_DIR/auth_service"; S_AUTH=1
        start_svc "RED"  "red_agent.backend.main:app" 8001 "$RED" "$ROOT_DIR/red_agent"; S_RED=1
        start_svc "BLUE" "blue_agent.backend.main:app" 8002 "$BLUE" "$ROOT_DIR/blue_agent"; S_BLUE=1
        [ "$HAS_NODE" = "1" ] && { sleep 2
            start_fe "$ROOT_DIR/dashboard" "ARENA" 5173 "$CYAN"; S_ARENA=1
            start_fe "$ROOT_DIR/red_agent/frontend" "RED-FE" 5175 "$RED"; S_RED_FE=1
            start_fe "$ROOT_DIR/blue_agent/frontend" "BLUE-FE" 5174 "$BLUE"; S_BLUE_FE=1
        };;
    arena)
        for p in 8001 8002 8003 5173; do free_port $p; done
        start_svc "AUTH" "auth_service.main:app" 8003 "$PURPLE" "$ROOT_DIR/auth_service"; S_AUTH=1
        start_svc "RED"  "red_agent.backend.main:app" 8001 "$RED" "$ROOT_DIR/red_agent"; S_RED=1
        start_svc "BLUE" "blue_agent.backend.main:app" 8002 "$BLUE" "$ROOT_DIR/blue_agent"; S_BLUE=1
        [ "$HAS_NODE" = "1" ] && { sleep 2; start_fe "$ROOT_DIR/dashboard" "ARENA" 5173 "$CYAN"; S_ARENA=1; };;
    backends)
        for p in 8001 8002 8003; do free_port $p; done
        start_svc "AUTH" "auth_service.main:app" 8003 "$PURPLE" "$ROOT_DIR/auth_service"; S_AUTH=1
        start_svc "RED"  "red_agent.backend.main:app" 8001 "$RED" "$ROOT_DIR/red_agent"; S_RED=1
        start_svc "BLUE" "blue_agent.backend.main:app" 8002 "$BLUE" "$ROOT_DIR/blue_agent"; S_BLUE=1;;
    blue)
        for p in 8002 8003 5174; do free_port $p; done
        start_svc "AUTH" "auth_service.main:app" 8003 "$PURPLE" "$ROOT_DIR/auth_service"; S_AUTH=1
        start_svc "BLUE" "blue_agent.backend.main:app" 8002 "$BLUE" "$ROOT_DIR/blue_agent"; S_BLUE=1
        [ "$HAS_NODE" = "1" ] && { sleep 2; start_fe "$ROOT_DIR/blue_agent/frontend" "BLUE-FE" 5174 "$BLUE"; S_BLUE_FE=1; };;
    red)
        for p in 8001 8003 5175; do free_port $p; done
        start_svc "AUTH" "auth_service.main:app" 8003 "$PURPLE" "$ROOT_DIR/auth_service"; S_AUTH=1
        start_svc "RED"  "red_agent.backend.main:app" 8001 "$RED" "$ROOT_DIR/red_agent"; S_RED=1
        [ "$HAS_NODE" = "1" ] && { sleep 2; start_fe "$ROOT_DIR/red_agent/frontend" "RED-FE" 5175 "$RED"; S_RED_FE=1; };;
    auth)
        free_port 8003
        start_svc "AUTH" "auth_service.main:app" 8003 "$PURPLE" "$ROOT_DIR/auth_service"; S_AUTH=1;;
    *) log_error "Unknown mode: $MODE"; usage;;
esac

sleep 2
[ "$S_AUTH" = "1" ] && wait_port 8003 "Auth"
[ "$S_RED" = "1" ]  && wait_port 8001 "Red"
[ "$S_BLUE" = "1" ] && wait_port 8002 "Blue"

print_urls
wait
