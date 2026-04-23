-- Security Mail Analyzer - PostgreSQL 초기화 스크립트
-- 데이터베이스와 사용자는 docker-compose 환경변수로 생성됨

-- 확장 모듈
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";  -- 텍스트 검색 최적화

-- 타임존 설정
SET timezone = 'Asia/Seoul';
