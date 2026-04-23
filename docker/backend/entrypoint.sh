#!/bin/bash
# ============================================================
# Backend 컨테이너 시작 스크립트
# PostgreSQL 연결 대기 후 uvicorn 실행
# ============================================================
set -e

echo "🔐 Security Mail Analyzer Backend 시작..."
echo "📅 시간: $(date)"
echo "🐍 Python: $(python3 --version)"

# ── DB 연결 대기 ──────────────────────────────────────────
if [ -n "$DATABASE_URL" ]; then
    # postgresql+asyncpg://user:pass@host:port/db 에서 host:port 추출
    DB_HOST=$(echo "$DATABASE_URL" | sed -E 's|.*@([^:/]+).*|\1|')
    DB_PORT=$(echo "$DATABASE_URL" | sed -E 's|.*:([0-9]+)/.*|\1|')
    DB_PORT=${DB_PORT:-5432}
    
    echo "🗄️  PostgreSQL 연결 대기 중... (${DB_HOST}:${DB_PORT})"
    
    MAX_WAIT=60
    WAITED=0
    until pg_isready -h "$DB_HOST" -p "$DB_PORT" -U "${POSTGRES_USER:-secmail}" > /dev/null 2>&1; do
        if [ $WAITED -ge $MAX_WAIT ]; then
            echo "⚠️  PostgreSQL 연결 타임아웃 (${MAX_WAIT}s) - 계속 진행..."
            break
        fi
        echo "   PostgreSQL 대기 중... (${WAITED}s)"
        sleep 3
        WAITED=$((WAITED + 3))
    done
    echo "✅ PostgreSQL 연결 확인됨"
else
    echo "ℹ️  DATABASE_URL 없음 - SQLite 모드로 실행"
fi

# ── uvicorn 실행 ──────────────────────────────────────────
echo "🚀 FastAPI 서버 시작 (port 8000)..."
exec python3 -m uvicorn backend.main:app \
    --host 0.0.0.0 \
    --port 8000 \
    --workers 2 \
    --log-level info \
    --no-access-log
