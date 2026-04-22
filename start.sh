#!/bin/bash
# Security Mail Analyzer - 시작 스크립트
# NVIDIA GB10 환경용

set -e

WEBAPP_DIR="/home/sigroup/webapp"
cd "$WEBAPP_DIR"

echo "=========================================="
echo " 🔐 Security Mail Analyzer"
echo " NVIDIA GB10 · Local LLM · Gmail"
echo "=========================================="

# 데이터 디렉토리 생성
mkdir -p data/db data/logs data/knowledge

# Python 환경 확인
python3 --version || { echo "❌ Python3 필요"; exit 1; }

# 의존성 설치 확인
echo "📦 의존성 확인 중..."
python3 -c "import fastapi, uvicorn, sqlalchemy" 2>/dev/null || {
    echo "📦 패키지 설치 중..."
    pip3 install -r requirements.txt --break-system-packages -q
}

# Ollama 상태 확인
echo "🤖 Ollama 상태 확인..."
if curl -s http://localhost:11434/api/tags > /dev/null 2>&1; then
    echo "✅ Ollama 실행 중"
    MODELS=$(curl -s http://localhost:11434/api/tags | python3 -c "import sys,json; data=json.load(sys.stdin); print([m['name'] for m in data.get('models',[])])" 2>/dev/null)
    echo "   모델: $MODELS"
else
    echo "⚠️  Ollama가 실행되지 않았습니다."
    echo "   Ollama 설치: curl -fsSL https://ollama.ai/install.sh | sh"
    echo "   모델 다운로드: ollama pull llama3.2:3b"
    echo "   서버 시작: ollama serve"
fi

# 환경변수 로드
if [ -f .env ]; then
    export $(grep -v '^#' .env | grep -v '^$' | sed 's/"//g' | xargs)
    echo "✅ 환경변수 로드됨"
fi

# 서버 시작
echo ""
echo "🚀 서버 시작 중... (포트: 8000)"
echo "📊 대시보드: http://localhost:8000"
echo "📚 API 문서: http://localhost:8000/docs"
echo ""

python3 -m uvicorn backend.main:app \
    --host 0.0.0.0 \
    --port 8000 \
    --reload \
    --log-level info \
    --access-log
