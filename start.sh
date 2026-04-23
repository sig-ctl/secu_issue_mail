#!/bin/bash
# ============================================================
# Security Mail Analyzer - 통합 실행 스크립트
# NVIDIA GB10 + Gemma4 + PostgreSQL + Nginx:61001
# ============================================================
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; NC='\033[0m'

log_info()  { echo -e "${GREEN}[INFO]${NC}  $1"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_step()  { echo -e "${CYAN}[STEP]${NC}  $1"; }

echo ""
echo -e "${BLUE}╔════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║  🔐 Security Mail Analyzer                 ║${NC}"
echo -e "${BLUE}║  NVIDIA GB10 + Gemma4 + PostgreSQL         ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════╝${NC}"
echo ""

MODE="${1:-auto}"

# ── .env 파일 ──────────────────────────────────────────────
[ ! -f ".env" ] && cp .env.example .env && log_warn ".env 파일을 복사했습니다. 설정을 확인하세요."

# ── Docker 명령어 ────────────────────────────────────────
if docker info > /dev/null 2>&1; then
    DC="docker compose"
else
    DC="sudo docker compose"
fi

# ── GPU & NVIDIA Runtime 감지 ────────────────────────────
has_gpu() { nvidia-smi > /dev/null 2>&1; }

has_nvidia_runtime() {
    # CDI 방식 또는 runtime 방식 모두 확인
    $DC version > /dev/null 2>&1
    docker info 2>/dev/null | grep -qiE "nvidia|cdi" && return 0
    [ -f /etc/docker/daemon.json ] && grep -q "nvidia" /etc/docker/daemon.json 2>/dev/null && return 0
    # nvidia-ctk 결과로 runtime 설정 확인
    command -v nvidia-ctk > /dev/null 2>&1 && nvidia-ctk cdi list 2>/dev/null | grep -q "nvidia" && return 0
    return 1
}

# ── Compose 파일 선택 ────────────────────────────────────
pick_compose() {
    if has_gpu; then
        log_info "✅ GPU 감지: $(nvidia-smi --query-gpu=name --format=csv,noheader 2>/dev/null | head -1)"
        if has_nvidia_runtime; then
            log_info "✅ NVIDIA Container Runtime 확인됨"
            echo "docker-compose.yml"
        else
            log_warn "⚠️  NVIDIA Runtime 미설정 → CPU 모드 사용"
            log_warn "    GPU 활성화: sudo bash docker/setup-nvidia-runtime.sh"
            echo "docker-compose.no-gpu.yml"
        fi
    else
        log_warn "GPU 미감지 → CPU 모드"
        echo "docker-compose.no-gpu.yml"
    fi
}

run_docker() {
    local CF="$1"
    log_step "Compose 파일: ${CF}"

    # 기존 컨테이너 정리
    $DC -f "$CF" down --remove-orphans 2>/dev/null || true

    # 데이터 디렉터리 생성
    mkdir -p data/db data/logs data/knowledge logs

    log_step "빌드 및 시작..."
    $DC -f "$CF" up -d --build

    echo ""
    log_step "초기 상태 (10초 후):"
    sleep 10
    $DC -f "$CF" ps

    echo ""
    HOST_IP=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "localhost")
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    log_info "✅ 서비스 시작 완료!"
    echo ""
    log_info "📊 대시보드  : http://${HOST_IP}:61001"
    log_info "🔌 API       : http://${HOST_IP}:8000"
    log_info "📖 API 문서  : http://${HOST_IP}:8000/docs"
    log_info "🗄️  PostgreSQL: localhost:5432"
    log_info "🤖 Ollama    : http://localhost:11434"
    echo ""
    log_warn "Gemma4 모델 설치는 백그라운드 진행 (수 분 소요)"
    log_warn "확인: docker logs secmail_ollama_init -f"
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

# ── 모드별 실행 ──────────────────────────────────────────
case "$MODE" in
  auto|docker)
    CF=$(pick_compose)
    run_docker "$CF"
    ;;
  gpu)
    log_step "GPU 강제 모드 (docker-compose.yml)"
    run_docker "docker-compose.yml"
    ;;
  no-gpu)
    log_step "CPU 전용 모드 (docker-compose.no-gpu.yml)"
    run_docker "docker-compose.no-gpu.yml"
    ;;
  local)
    log_step "로컬 개발 모드 (SQLite, 포트 8000)"
    [ -d "venv" ] && source venv/bin/activate
    mkdir -p data/db data/logs data/knowledge logs
    set -a; source .env 2>/dev/null || true; DATABASE_URL=""; set +a
    pkill -f "uvicorn backend.main" 2>/dev/null || true
    sleep 1
    python3 -m uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload --log-level info &
    PID=$!
    sleep 3
    kill -0 $PID 2>/dev/null && log_info "✅ 로컬 서버 실행 (PID:$PID) → http://localhost:8000" || { log_error "시작 실패"; exit 1; }
    wait $PID
    ;;
  *)
    echo ""
    echo "사용법: $0 [auto|gpu|no-gpu|local]"
    echo "  auto   - GPU 자동 감지 (기본)"
    echo "  gpu    - GPU 강제 사용"
    echo "  no-gpu - CPU 전용"
    echo "  local  - Docker 없이 로컬 실행"
    ;;
esac
