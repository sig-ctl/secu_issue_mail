# 🚨 긴급 수정 가이드 - Ollama/Backend 컨테이너 오류 해결

## 현재 상황 분석
- `docker ps -a` 결과: 이전 컨테이너들이 다른 프로젝트명(`webapp`)으로 실행 중
- `runtime: nvidia` 설정으로 NVIDIA Container Runtime 없으면 Ollama Error
- backend가 Ollama를 기다리다가 재시작 반복

---

## ✅ 즉시 실행: 완전 초기화 후 재시작

### 방법 1: 스크립트로 자동 처리 (권장)

```bash
cd /home/sigroup/webapp

# 실행 권한 부여
chmod +x reset-and-start.sh

# CPU 전용 모드 (NVIDIA Container Toolkit 없을 때)
sudo bash reset-and-start.sh no-gpu

# GPU 모드 (NVIDIA Container Toolkit 설치됐을 때)
sudo bash reset-and-start.sh gpu

# 자동 감지
sudo bash reset-and-start.sh
```

---

### 방법 2: 수동 단계별 실행

#### STEP 1: 모든 기존 컨테이너 강제 정리
```bash
# 이전 컨테이너들 모두 정리 (어떤 이름이든)
sudo docker stop secmail_postgres secmail_ollama secmail_ollama_init secmail_backend secmail_nginx 2>/dev/null; true
sudo docker rm -f secmail_postgres secmail_ollama secmail_ollama_init secmail_backend secmail_nginx 2>/dev/null; true

# 이전 webapp 프로젝트 컨테이너 정리
sudo docker ps -a | grep -E "webapp" | awk '{print $1}' | xargs sudo docker rm -f 2>/dev/null; true

# 확인
sudo docker ps -a
```

#### STEP 2: NVIDIA Runtime 확인
```bash
# NVIDIA runtime 설치 여부 확인
sudo docker info | grep -i nvidia

# 만약 없으면 → no-gpu 버전 사용
# 만약 있으면 → gpu 버전 사용
```

#### STEP 3A: NVIDIA Runtime 없는 경우 (CPU 모드)
```bash
cd /home/sigroup/webapp
mkdir -p data/db data/logs data/knowledge logs

# CPU 전용 compose 파일 사용
sudo docker compose -f docker-compose.no-gpu.yml up -d --build
```

#### STEP 3B: NVIDIA Runtime 있는 경우 (GPU 모드)
```bash
cd /home/sigroup/webapp
mkdir -p data/db data/logs data/knowledge logs

# GPU compose 파일 사용
sudo docker compose -f docker-compose.yml up -d --build
```

#### STEP 4: 상태 확인
```bash
# 컨테이너 상태
sudo docker ps -a

# 로그 확인
sudo docker logs secmail_backend --tail=50
sudo docker logs secmail_ollama --tail=20
sudo docker logs secmail_postgres --tail=10
```

---

## 🔍 NVIDIA Container Toolkit 설치 방법 (선택사항)

NVIDIA GB10에서 GPU 가속 사용하려면:

```bash
# 자동 설치 스크립트
sudo bash /home/sigroup/webapp/docker/setup-nvidia-runtime.sh

# 설치 후 Docker 재시작
sudo systemctl restart docker

# GPU 모드로 재시작
sudo bash /home/sigroup/webapp/reset-and-start.sh gpu
```

---

## 서비스 포트

| 서비스 | 포트 | URL |
|--------|------|-----|
| 대시보드 (nginx) | 61001 | http://서버IP:61001 |
| API (FastAPI) | 8000 | http://서버IP:8000 |
| API 문서 | 8000 | http://서버IP:8000/docs |
| PostgreSQL | 5432 | localhost:5432 |
| Ollama | 11434 | localhost:11434 |
