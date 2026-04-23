#!/bin/bash
# 진단 스크립트 - sudo bash docker/diag.sh
echo "=== Ollama 컨테이너 로그 (마지막 30줄) ==="
docker logs secmail_ollama 2>&1 | tail -30

echo ""
echo "=== Ollama 헬스체크 결과 (최근 5회) ==="
docker inspect secmail_ollama --format '{{json .State.Health}}' 2>&1 | python3 -c "
import json, sys
try:
    h = json.load(sys.stdin)
    print('Status:', h.get('Status'))
    for l in (h.get('Log') or [])[-5:]:
        print(f\"  Exit={l.get('ExitCode')} Output={repr(l.get('Output','')[:200])}\")
except Exception as e:
    print('파싱 오류:', e)
    print(sys.stdin.read()[:500])
"

echo ""
echo "=== Backend 로그 (마지막 30줄) ==="
docker logs secmail_backend 2>&1 | tail -30

echo ""
echo "=== Backend 헬스체크 결과 ==="
docker inspect secmail_backend --format '{{json .State.Health}}' 2>&1 | python3 -c "
import json, sys
try:
    h = json.load(sys.stdin)
    print('Status:', h.get('Status'))
    for l in (h.get('Log') or [])[-3:]:
        print(f\"  Exit={l.get('ExitCode')} Output={repr(l.get('Output','')[:200])}\")
except Exception as e:
    print('파싱 오류:', e)
"

echo ""
echo "=== 전체 컨테이너 상태 ==="
docker ps -a --format "table {{.Names}}\t{{.Status}}\t{{.Image}}"

echo ""
echo "=== Ollama API 연결 테스트 (localhost:11434) ==="
curl -sv http://localhost:11434/api/tags 2>&1 | head -20 || echo "연결 실패"

echo ""
echo "=== NVIDIA GPU 상태 ==="
nvidia-smi 2>&1 | head -15 || echo "nvidia-smi 없음"

echo ""
echo "=== Docker NVIDIA Runtime ==="
docker info 2>&1 | grep -iE "runtime|nvidia|cdi" | head -10
