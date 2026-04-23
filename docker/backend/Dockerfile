FROM python:3.12-slim

LABEL maintainer="Security Mail Analyzer"
LABEL description="NVIDIA GB10 Security Mail Analyzer Backend"

# 시스템 패키지 (curl: healthcheck, gcc+libpq: asyncpg/psycopg2)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    gcc \
    libpq-dev \
    postgresql-client \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Python 의존성
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 애플리케이션 코드
COPY backend/ ./backend/
COPY frontend/ ./frontend/

# 시작 스크립트
COPY docker/backend/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# 데이터 디렉터리
RUN mkdir -p /app/data/db /app/data/logs /app/data/knowledge /app/logs

# 환경변수 기본값
ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1
ENV TZ=Asia/Seoul

EXPOSE 8000

# Dockerfile 레벨 헬스체크 (docker-compose healthcheck보다 낮은 우선순위)
HEALTHCHECK --interval=15s --timeout=10s --start-period=20s --retries=10 \
    CMD curl -sf http://localhost:8000/health || exit 1

ENTRYPOINT ["/entrypoint.sh"]
