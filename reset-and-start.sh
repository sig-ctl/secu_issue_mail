#!/bin/bash
# ============================================================
# Security Mail Analyzer - 완전 초기화 및 재시작 스크립트
# 이전 컨테이너(다른 프로젝트명 포함) 모두 정리 후 재시작
# ============================================================

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
echo -e "${BLUE}║  🔐 Security Mail Analyzer - 완전 초기화  ║${NC}"
echo -e "${BLUE}║  이전 컨테이너 모두 정리 후 재시작        ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════╝${NC}"
echo ""

# ── Docker 권한 확인 ─────────────────────────────────────
if docker info > /dev/null 2>&1; then
    DOCKER="docker"
    DC="docker compose"
else
    DOCKER="sudo docker"
    DC="sudo docker compose"
fi

# ── STEP 1: 이전 컨테이너 완전 정리 ────────────────────
log_step "STEP 1: 기존 컨테이너 완전 정리..."

# secmail 프로젝트 정리 (현재 compose 파일 기준)
$DC -f docker-compose.no-gpu.yml down --remove-orphans 2>/dev/null || true
$DC -f docker-compose.yml down --remove-orphans 2>/dev/null || true

# 이전 프로젝트명(webapp)으로 생성된 컨테이너도 강제 정리
CONTAINERS=("secmail_postgres" "secmail_ollama" "secmail_ollama_init" "secmail_backend" "secmail_nginx")
for c in "${CONTAINERS[@]}"; do
    if $DOCKER ps -a --format '{{.Names}}' | grep -q "^${c}$"; then
        log_warn "  컨테이너 강제 제거: $c"
        $DOCKER stop "$c" 2>/dev/null || true
        $DOCKER rm -f "$c" 2>/dev/null || true
    fi
done

# webapp 프로젝트 이름으로 생성된 컨테이너 정리 (이전 버전 잔재)
WEBAPP_CONTAINERS=$($DOCKER ps -a --format '{{.Names}}' | grep -E "^webapp-|^webapp_" 2>/dev/null || true)
if [ -n "$WEBAPP_CONTAINERS" ]; then
    log_warn "  webapp 프로젝트 컨테이너 정리: $WEBAPP_CONTAINERS"
    echo "$WEBAPP_CONTAINERS" | xargs $DOCKER stop 2>/dev/null || true
    echo "$WEBAPP_CONTAINERS" | xargs $DOCKER rm -f 2>/dev/null || true
fi

log_info "  컨테이너 정리 완료"
echo ""

# ── STEP 2: 데이터 디렉터리 생성 ───────────────────────
log_step "STEP 2: 데이터 디렉터리 생성..."
mkdir -p data/db data/logs data/knowledge logs
log_info "  디렉터리 준비 완료"
echo ""

# ── STEP 3: .env 파일 확인 ──────────────────────────────
log_step "STEP 3: 환경 설정 확인..."
if [ ! -f ".env" ]; then
    cp .env.example .env
    log_warn "  .env 파일을 생성했습니다. 설정을 확인/수정하세요: vi .env"
else
    log_info "  .env 파일 존재 확인됨"
fi
echo ""

# ── STEP 4: NVIDIA Runtime 확인 및 Compose 파일 선택 ───
log_step "STEP 4: GPU / NVIDIA Runtime 확인..."

has_gpu() {
    nvidia-smi > /dev/null 2>&1
}

has_nvidia_runtime() {
    # docker info에서 nvidia runtime 확인
    $DOCKER info 2>/dev/null | grep -qiE "nvidia|cdi" && return 0
    # daemon.json 확인
    [ -f /etc/docker/daemon.json ] && grep -qi "nvidia" /etc/docker/daemon.json 2>/dev/null && return 0
    # nvidia-ctk CDI 확인
    command -v nvidia-ctk > /dev/null 2>&1 && nvidia-ctk cdi list 2>/dev/null | grep -qi "nvidia" && return 0
    return 1
}

USE_GPU=false
COMPOSE_FILE="docker-compose.no-gpu.yml"

if has_gpu; then
    GPU_NAME=$(nvidia-smi --query-gpu=name --format=csv,noheader 2>/dev/null | head -1)
    log_info "  GPU 감지: ${GPU_NAME:-알 수 없음}"
    if has_nvidia_runtime; then
        log_info "  NVIDIA Container Runtime 설정됨 → GPU 모드"
        USE_GPU=true
        COMPOSE_FILE="docker-compose.yml"
    else
        log_warn "  GPU 있지만 NVIDIA Container Runtime 미설정 → CPU 모드"
        log_warn "  GPU 활성화: sudo bash docker/setup-nvidia-runtime.sh"
        COMPOSE_FILE="docker-compose.no-gpu.yml"
    fi
else
    log_warn "  GPU 미감지 → CPU 모드"
    COMPOSE_FILE="docker-compose.no-gpu.yml"
fi

# 강제 모드 옵션
if [ "$1" == "gpu" ]; then
    log_info "  [강제] GPU 모드 사용"
    COMPOSE_FILE="docker-compose.yml"
elif [ "$1" == "no-gpu" ]; then
    log_info "  [강제] CPU 전용 모드 사용"
    COMPOSE_FILE="docker-compose.no-gpu.yml"
fi

log_step "  사용할 Compose 파일: ${COMPOSE_FILE}"
echo ""

# ── STEP 5: 빌드 및 시작 ────────────────────────────────
log_step "STEP 5: 빌드 및 서비스 시작..."
echo ""

$DC -f "$COMPOSE_FILE" up -d --build

echo ""
log_step "STEP 6: 서비스 상태 확인 (15초 대기)..."
sleep 15

echo ""
$DC -f "$COMPOSE_FILE" ps
echo ""

# ── 접속 정보 출력 ──────────────────────────────────────
HOST_IP=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "localhost")
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
log_info "서비스 시작 완료!"
echo ""
log_info "📊 대시보드  : http://${HOST_IP}:61001"
log_info "🔌 API       : http://${HOST_IP}:8000"
log_info "📖 API 문서  : http://${HOST_IP}:8000/docs"
log_info "🗄️  PostgreSQL: localhost:5432"
log_info "🤖 Ollama    : http://localhost:11434"
echo ""
log_warn "Gemma3:4b 모델 설치는 백그라운드 진행 중 (수 분 소요)"
log_warn "Ollama 로그 확인: docker logs secmail_ollama -f"
log_warn "모델 설치 확인 : docker logs secmail_ollama_init -f"
echo ""
log_info "📋 유용한 명령어:"
echo "  docker ps                                    # 컨테이너 상태"
echo "  docker logs secmail_backend -f               # backend 로그"
echo "  docker logs secmail_ollama -f                # ollama 로그"
echo "  docker logs secmail_ollama_init -f           # 모델 설치 로그"
echo "  $DC -f $COMPOSE_FILE logs -f                 # 전체 로그"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
