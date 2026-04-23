#!/bin/bash
# ============================================================
# Security Mail Analyzer - 관리 스크립트
# ============================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; RED='\033[0;31m'; NC='\033[0m'
log_info() { echo -e "${GREEN}[INFO]${NC}  $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC}  $1"; }
log_cmd()  { echo -e "${CYAN}[CMD]${NC}   $1"; }
log_error(){ echo -e "${RED}[ERROR]${NC} $1"; }

# Docker 명령어 자동 선택
if docker info > /dev/null 2>&1; then
    DOCKER_CMD="docker"
else
    DOCKER_CMD="sudo docker"
fi

# Compose 파일 자동 선택 (실행 중인 컨테이너 기준)
if $DOCKER_CMD inspect secmail_ollama > /dev/null 2>&1; then
    # 실행 중인 컨테이너의 runtime 확인
    RUNTIME=$($DOCKER_CMD inspect secmail_ollama --format '{{.HostConfig.Runtime}}' 2>/dev/null)
    if [ "$RUNTIME" = "nvidia" ]; then
        COMPOSE_FILE="docker-compose.yml"
    else
        COMPOSE_FILE="docker-compose.no-gpu.yml"
    fi
else
    # 기본값: GPU 여부 자동 감지
    if nvidia-smi > /dev/null 2>&1 && $DOCKER_CMD info 2>/dev/null | grep -q "nvidia"; then
        COMPOSE_FILE="docker-compose.yml"
    else
        COMPOSE_FILE="docker-compose.no-gpu.yml"
    fi
fi

log_info "Compose 파일: ${COMPOSE_FILE}"
echo ""

case "${1:-help}" in

  # ── 상태 확인 ──────────────────────────────────────
  status)
    log_info "서비스 상태:"
    $DOCKER_CMD compose -f "$COMPOSE_FILE" ps
    ;;

  # ── 로그 ────────────────────────────────────────────
  logs)
    SERVICE="${2:-}"
    if [ -n "$SERVICE" ]; then
      $DOCKER_CMD logs -f "secmail_${SERVICE}" --tail=100
    else
      $DOCKER_CMD compose -f "$COMPOSE_FILE" logs -f --tail=100
    fi
    ;;

  # ── 재시작 ──────────────────────────────────────────
  restart)
    SERVICE="${2:-}"
    if [ -n "$SERVICE" ]; then
      log_info "${SERVICE} 재시작 중..."
      $DOCKER_CMD compose -f "$COMPOSE_FILE" restart "$SERVICE"
    else
      log_info "전체 재시작 중..."
      $DOCKER_CMD compose -f "$COMPOSE_FILE" restart
    fi
    ;;

  # ── 중지 ─────────────────────────────────────────────
  stop)
    log_info "서비스 중지 중..."
    $DOCKER_CMD compose -f "$COMPOSE_FILE" down
    ;;

  # ── 완전 초기화 ──────────────────────────────────────
  clean)
    log_warn "⚠️  모든 컨테이너와 볼륨을 삭제합니다!"
    read -p "계속하시겠습니까? (y/N): " confirm
    if [ "$confirm" = "y" ] || [ "$confirm" = "Y" ]; then
      $DOCKER_CMD compose -f "$COMPOSE_FILE" down -v
      log_info "정리 완료"
    fi
    ;;

  # ── Ollama 모델 목록 ─────────────────────────────────
  models)
    log_info "설치된 Ollama 모델:"
    curl -s http://localhost:11434/api/tags | python3 -c "
import json, sys
try:
    data = json.load(sys.stdin)
    models = data.get('models', [])
    if not models:
        print('  (설치된 모델 없음 - 설치 진행 중일 수 있음)')
    for m in models:
        size = m.get('size', 0) / 1024**3
        print(f\"  - {m['name']} ({size:.1f} GB)\")
except Exception as e:
    print(f'  오류: {e}')
" 2>/dev/null || log_warn "Ollama에 연결할 수 없습니다."
    ;;

  # ── Gemma4 수동 설치 ─────────────────────────────────
  pull-gemma)
    log_info "Gemma4 모델 설치 중... (시간이 걸릴 수 있습니다)"
    curl -X POST http://localhost:11434/api/pull \
      -H 'Content-Type: application/json' \
      -d '{"name":"gemma3:4b","stream":false}' \
      --max-time 1800 | python3 -c "
import json, sys
try:
    data = json.load(sys.stdin)
    print(data.get('status', data))
except:
    print(sys.stdin.read())
"
    ;;

  # ── Ollama 컨테이너 내부 pull ──────────────────────────
  pull-gemma-exec)
    log_info "컨테이너 내부에서 Gemma4 pull..."
    $DOCKER_CMD exec secmail_ollama ollama pull gemma3:4b
    ;;

  # ── Ollama 재시작 ──────────────────────────────────────
  restart-ollama)
    log_info "Ollama 컨테이너 재시작..."
    $DOCKER_CMD restart secmail_ollama
    log_info "30초 대기 후 상태 확인..."
    sleep 30
    curl -s http://localhost:11434/api/tags | python3 -m json.tool 2>/dev/null || log_warn "아직 시작 중..."
    ;;

  # ── DB 백업 ──────────────────────────────────────────
  db-backup)
    TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    BACKUP_FILE="data/backup_${TIMESTAMP}.sql"
    log_info "DB 백업: ${BACKUP_FILE}"
    $DOCKER_CMD exec secmail_postgres pg_dump -U secmail secmail > "$BACKUP_FILE"
    log_info "백업 완료: ${BACKUP_FILE} ($(du -sh $BACKUP_FILE | cut -f1))"
    ;;

  # ── DB 복원 ──────────────────────────────────────────
  db-restore)
    BACKUP_FILE="${2}"
    if [ -z "$BACKUP_FILE" ]; then
      log_warn "사용법: $0 db-restore <backup_file.sql>"
      ls data/backup_*.sql 2>/dev/null | head -10
      exit 1
    fi
    log_info "DB 복원 중: ${BACKUP_FILE}"
    $DOCKER_CMD exec -i secmail_postgres psql -U secmail secmail < "$BACKUP_FILE"
    log_info "복원 완료"
    ;;

  # ── 전체 헬스체크 ─────────────────────────────────────
  health)
    echo ""
    echo "═══ 서비스 헬스체크 ═══"
    
    echo ""
    echo "1️⃣  FastAPI API (8000):"
    curl -sf http://localhost:8000/health | python3 -m json.tool 2>/dev/null || echo "   ❌ 연결 불가"
    
    echo ""
    echo "2️⃣  Nginx UI (61001):"
    STATUS=$(curl -so /dev/null -w "%{http_code}" http://localhost:61001/health 2>/dev/null)
    [ "$STATUS" = "200" ] && echo "   ✅ 정상 (HTTP $STATUS)" || echo "   ❌ 오류 (HTTP $STATUS)"
    
    echo ""
    echo "3️⃣  Ollama (11434):"
    curl -sf http://localhost:11434/api/tags | python3 -c "
import json, sys
try:
    d = json.load(sys.stdin)
    models = d.get('models', [])
    print(f'   ✅ 연결됨 - 모델 {len(models)}개: {[m[\"name\"] for m in models]}')
except:
    print('   ❌ 응답 파싱 오류')
" 2>/dev/null || echo "   ❌ 연결 불가 (아직 시작 중일 수 있음)"
    
    echo ""
    echo "4️⃣  PostgreSQL (5432):"
    $DOCKER_CMD exec secmail_postgres pg_isready -U secmail 2>/dev/null \
      && echo "   ✅ 정상" || echo "   ❌ 연결 불가"
    
    echo ""
    echo "5️⃣  컨테이너 상태:"
    $DOCKER_CMD compose -f "$COMPOSE_FILE" ps --format "table {{.Name}}\t{{.Status}}" 2>/dev/null
    echo ""
    ;;

  # ── NVIDIA 런타임 확인 ────────────────────────────────
  check-gpu)
    echo ""
    echo "═══ GPU / NVIDIA Runtime 확인 ═══"
    echo ""
    echo "1. nvidia-smi:"
    nvidia-smi --query-gpu=name,driver_version,memory.total --format=csv 2>/dev/null || echo "   nvidia-smi 사용 불가"
    echo ""
    echo "2. Docker NVIDIA Runtime:"
    $DOCKER_CMD info 2>/dev/null | grep -i "nvidia\|runtime" | head -10 || echo "   Runtime 정보 없음"
    echo ""
    echo "3. /etc/docker/daemon.json:"
    cat /etc/docker/daemon.json 2>/dev/null || echo "   파일 없음"
    echo ""
    ;;

  # ── 도움말 ────────────────────────────────────────────
  *)
    echo ""
    echo -e "${CYAN}Security Mail Analyzer 관리 스크립트${NC}"
    echo ""
    echo "사용법: $0 <command> [options]"
    echo ""
    echo "명령어:"
    log_cmd "status              - 컨테이너 상태 확인"
    log_cmd "logs [service]      - 로그 (backend/nginx/postgres/ollama)"
    log_cmd "restart [service]   - 재시작"
    log_cmd "stop                - 모든 서비스 중지"
    log_cmd "clean               - 완전 초기화 (볼륨 포함)"
    echo ""
    log_cmd "models              - Ollama 모델 목록"
    log_cmd "pull-gemma          - Gemma4 REST API로 다운로드"
    log_cmd "pull-gemma-exec     - Gemma4 컨테이너 내부 exec로 다운로드"
    log_cmd "restart-ollama      - Ollama 재시작"
    echo ""
    log_cmd "db-backup           - DB 백업 (SQL)"
    log_cmd "db-restore <file>   - DB 복원"
    echo ""
    log_cmd "health              - 전체 헬스체크"
    log_cmd "check-gpu           - GPU / NVIDIA Runtime 확인"
    echo ""
    ;;
esac
