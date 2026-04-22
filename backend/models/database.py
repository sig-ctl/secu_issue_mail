"""
Database models and setup for Security Mail Analyzer
"""
from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime, Float, Boolean, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker, relationship
from datetime import datetime
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DB_PATH = os.path.join(BASE_DIR, "data", "db", "security_mail.db")

DATABASE_URL = f"sqlite+aiosqlite:///{DB_PATH}"

engine = create_async_engine(DATABASE_URL, echo=False)
async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

Base = declarative_base()


class SecurityAlert(Base):
    """보안 알람 메일 모델"""
    __tablename__ = "security_alerts"

    id = Column(Integer, primary_key=True, index=True)
    gmail_id = Column(String(255), unique=True, index=True)
    subject = Column(String(1000))
    sender = Column(String(500))
    recipient = Column(String(500))
    received_at = Column(DateTime, default=datetime.utcnow)
    body_text = Column(Text)
    body_html = Column(Text)
    
    # 분석 결과
    severity = Column(String(50))          # critical, high, medium, low, info
    severity_score = Column(Float, default=0.0)
    is_false_positive = Column(Boolean, default=False)
    false_positive_reason = Column(Text)
    alert_type = Column(String(200))       # 알람 유형
    repeat_count = Column(Integer, default=1)  # 반복 횟수
    is_repeated = Column(Boolean, default=False)
    related_alert_ids = Column(JSON)       # 관련 알람 ID 목록
    
    # 추출된 데이터
    extracted_ips = Column(JSON)           # 탐지된 IP 목록
    extracted_domains = Column(JSON)       # 탐지된 도메인 목록
    extracted_users = Column(JSON)         # 관련 사용자 목록
    extracted_events = Column(JSON)        # 이벤트 목록
    
    # LLM 분석 결과
    llm_summary = Column(Text)
    llm_analysis = Column(Text)
    llm_recommendation = Column(Text)
    llm_analyzed_at = Column(DateTime)
    
    # 처리 상태
    status = Column(String(50), default="new")  # new, analyzing, analyzed, reported, closed
    labels = Column(JSON)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class IPIntelligence(Base):
    """IP 인텔리전스 정보"""
    __tablename__ = "ip_intelligence"

    id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(String(45), unique=True, index=True)
    country = Column(String(100))
    city = Column(String(100))
    region = Column(String(100))
    isp = Column(String(200))
    org = Column(String(200))
    asn = Column(String(100))
    latitude = Column(Float)
    longitude = Column(Float)
    
    # 위협 정보
    is_tor = Column(Boolean, default=False)
    is_proxy = Column(Boolean, default=False)
    is_vpn = Column(Boolean, default=False)
    is_datacenter = Column(Boolean, default=False)
    threat_score = Column(Integer, default=0)
    abuse_confidence = Column(Integer, default=0)
    
    # 히스토리
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)
    alert_count = Column(Integer, default=1)
    raw_data = Column(JSON)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class AlertReport(Base):
    """발송된 요약 리포트"""
    __tablename__ = "alert_reports"

    id = Column(Integer, primary_key=True, index=True)
    report_type = Column(String(50))  # daily, weekly, manual
    period_start = Column(DateTime)
    period_end = Column(DateTime)
    recipients = Column(JSON)
    subject = Column(String(500))
    html_content = Column(Text)
    
    # 통계
    total_alerts = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    false_positive_count = Column(Integer, default=0)
    
    sent_at = Column(DateTime)
    status = Column(String(50), default="pending")
    
    created_at = Column(DateTime, default=datetime.utcnow)


class KnowledgeBase(Base):
    """LLM 학습 지식베이스"""
    __tablename__ = "knowledge_base"

    id = Column(Integer, primary_key=True, index=True)
    category = Column(String(100), index=True)  # alert_pattern, false_positive, recommendation
    title = Column(String(500))
    content = Column(Text)
    embedding_text = Column(Text)  # 임베딩용 텍스트
    source_alert_id = Column(Integer)
    tags = Column(JSON)
    relevance_score = Column(Float, default=1.0)
    use_count = Column(Integer, default=0)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class Settings(Base):
    """시스템 설정"""
    __tablename__ = "settings"

    id = Column(Integer, primary_key=True, index=True)
    key = Column(String(200), unique=True, index=True)
    value = Column(Text)
    description = Column(String(500))
    is_encrypted = Column(Boolean, default=False)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class ChatHistory(Base):
    """LLM 채팅 히스토리"""
    __tablename__ = "chat_history"

    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(String(100), index=True)
    role = Column(String(20))  # user, assistant, system
    content = Column(Text)
    context_alert_ids = Column(JSON)
    model_used = Column(String(100))
    
    created_at = Column(DateTime, default=datetime.utcnow)


async def init_db():
    """데이터베이스 초기화"""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def get_db():
    """데이터베이스 세션 가져오기"""
    async with async_session() as session:
        try:
            yield session
        finally:
            await session.close()
