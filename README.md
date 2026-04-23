# 🔐 Security Mail Analyzer

**NVIDIA GB10 + Gemma4 + PostgreSQL 기반 보안 알람 메일 분석 시스템**

Gmail로 수신된 보안 알람 메일을 로컬 LLM(Gemma4)으로 자동 분석하여, 중요도·반복성·오탐을 판단하고 대시보드형 요약 메일을 발송합니다.

---

## 🏗️ 아키텍처

```
Gmail ──► FastAPI Backend ──► PostgreSQL (Docker, host network)
                │
                ▼
          Ollama + Gemma4 (Docker, GPU)
                │
                ▼
       Nginx Frontend :61001
```

| 서비스 | 포트 | 역할 |
|---|---|---|
| **Nginx (Frontend)** | **61001** | 대시보드 SPA |
| **FastAPI (Backend)** | 8000 | REST API |
| **PostgreSQL** | 5432 | 분석 데이터 저장 |
| **Ollama (Gemma4)** | 11434 | 로컬 LLM 추론 |

---

## 🚀 빠른 시작 (Docker)

### 1. 사전 요구사항

- Docker 29+ / Docker Compose v5+
- NVIDIA Container Toolkit (GPU 가속)
- NVIDIA GB10 이상 GPU

### 2. 설치 및 실행

```bash
# 저장소 클론
git clone https://github.com/sig-ctl/secu_issue_mail.git
cd secu_issue_mail

# 환경 설정
cp .env.example .env
nano .env   # Gmail, SMTP, API 키 입력

# Docker로 전체 실행 (권장)
sudo ./start.sh sudo-docker

# 또는 직접 실행
sudo docker compose up -d --build
```

### 3. 접속

| URL | 설명 |
|---|---|
| http://서버IP:61001 | 🎯 메인 대시보드 |
| http://서버IP:8000/docs | 📖 API 문서 |

---

## ⚙️ 환경 설정 (.env)

```env
# PostgreSQL (Docker가 자동 생성)
POSTGRES_DB=secmail
POSTGRES_USER=secmail
POSTGRES_PASSWORD=secmail_pass_2024

# Gmail (앱 비밀번호 사용)
GMAIL_USER=your@gmail.com
GMAIL_APP_PASSWORD=xxxx_xxxx_xxxx_xxxx

# Ollama LLM (Docker 자동 설치)
OLLAMA_URL=http://localhost:11434
OLLAMA_MODEL=gemma3:4b

# 리포트 발송 SMTP
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your@gmail.com
SMTP_PASSWORD=your_app_password

# 리포트 수신자
REPORT_RECIPIENTS=["admin@company.com"]

# IP 조회 API (선택)
ABUSEIPDB_API_KEY=
IPINFO_TOKEN=
```

---

## 📦 Docker 구성

### 컨테이너 구조 (host network 모드)

```yaml
services:
  postgres:      # PostgreSQL 16 (port 5432)
  ollama:        # Ollama + GPU (port 11434)
  ollama-init:   # Gemma4 자동 설치 (1회성)
  backend:       # FastAPI (port 8000)
  nginx:         # Frontend (port 61001)
```

### 관리 명령어

```bash
# 상태 확인
sudo ./manage.sh status

# 로그 보기
sudo ./manage.sh logs backend
sudo ./manage.sh logs ollama

# 서비스 재시작
sudo ./manage.sh restart backend

# DB 백업
sudo ./manage.sh db-backup

# 헬스체크
sudo ./manage.sh health

# Gemma4 모델 수동 다운로드
sudo ./manage.sh pull-gemma
```

---

## 🖥️ 로컬 개발 모드 (Docker 없이)

```bash
# 의존성 설치
pip install -r requirements.txt --break-system-packages

# Ollama 설치 (별도)
curl -fsSL https://ollama.ai/install.sh | sh
ollama serve &
ollama pull gemma3:4b

# 실행 (SQLite 자동 사용)
./start.sh local
```

---

## 🔑 주요 기능

### 1. Gmail 연동
- **App Password** 방식 (간편)
- **OAuth2** 방식 (구글 API)
- 메일함 라벨 필터링
- 검색 쿼리 기반 수집

### 2. LLM 분석 (Gemma4)
- 심각도 평가 (Critical/High/Medium/Low/Info)
- 오탐 감지 및 이유 설명
- 반복 패턴 탐지
- 보안 권고사항 생성

### 3. IP 인텔리전스
- GeoIP (국가/도시/ISP/ASN)
- AbuseIPDB 위협 점수
- TOR/Proxy/VPN/데이터센터 감지
- Shodan, VirusTotal, Censys 링크
- 일괄 IP 조회

### 4. 대시보드형 리포트
- HTML 형식 요약 메일 자동 발송 (매일 09:30)
- 수동 발송 기능
- 심각도별 통계 차트

### 5. 지속 학습 (Knowledge Base)
- AI 채팅을 통한 보안 Q&A
- 피드백 기반 지식베이스 구축
- 세션 히스토리 관리

### 6. 히스토리 관리
- 90일 알람 이력 보기
- 날짜별 그룹화
- 알람 유형별 분류

---

## 🛠️ 기술 스택

| 분류 | 기술 |
|---|---|
| **Backend** | FastAPI, SQLAlchemy, APScheduler |
| **Database** | PostgreSQL 16 (Docker) |
| **LLM** | Ollama + Gemma4 (gemma3:4b) |
| **Frontend** | Vanilla JS SPA, Chart.js |
| **Nginx** | 리버스 프록시 + 포트 61001 |
| **GPU** | NVIDIA GB10, CUDA |
| **Container** | Docker, docker-compose (host network) |

---

## 📁 프로젝트 구조

```
webapp/
├── docker-compose.yml      # 전체 서비스 구성
├── docker/
│   ├── backend/Dockerfile
│   ├── nginx/nginx.conf    # 포트 61001
│   └── postgres/init.sql
├── backend/
│   ├── main.py             # FastAPI + 스케줄러
│   ├── models/database.py  # PostgreSQL + SQLite fallback
│   ├── routers/            # API 라우터
│   └── services/           # Gmail, LLM, IP, 리포트
├── frontend/
│   ├── index.html          # SPA
│   └── app.js              # ~1800줄 대시보드 앱
├── start.sh                # 통합 실행 스크립트
├── manage.sh               # 관리 유틸리티
├── .env                    # 환경변수 (git 제외)
└── .env.example            # 설정 예시
```

---

## ❓ FAQ

**Q: Gemma4 모델 다운로드가 오래 걸립니다**  
A: gemma3:4b 기준 약 3-5분 소요. `docker logs secmail_ollama_init -f`로 진행 확인.

**Q: Docker 권한 오류 발생 시**  
A: `sudo ./start.sh sudo-docker` 또는 `sudo usermod -aG docker $USER`

**Q: Gmail 인증 방법**  
A: Gmail 계정 → 2단계 인증 활성화 → [앱 비밀번호 생성](https://myaccount.google.com/apppasswords)

**Q: PostgreSQL 접속**  
A: `docker exec -it secmail_postgres psql -U secmail secmail`
