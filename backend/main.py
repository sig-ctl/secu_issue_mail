"""
Security Mail Analyzer - Main FastAPI Application
NVIDIA GB10 최적화 - 로컬 LLM 기반 보안 알람 분석 시스템
"""
import os
import sys
from pathlib import Path
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger

# 환경변수 로드
env_path = Path(__file__).parent.parent / ".env"
if env_path.exists():
    from dotenv import load_dotenv
    load_dotenv(env_path)

# DB 초기화
sys.path.insert(0, str(Path(__file__).parent.parent))


@asynccontextmanager
async def lifespan(app: FastAPI):
    """앱 시작/종료 이벤트"""
    # DB 초기화
    from backend.models.database import init_db
    await init_db()
    print("✅ 데이터베이스 초기화 완료")
    
    # 스케줄러 시작
    scheduler = AsyncIOScheduler(timezone="Asia/Seoul")
    
    # 매일 오전 9시 자동 수집 + 분석
    scheduler.add_job(
        scheduled_fetch_and_analyze,
        CronTrigger(hour=9, minute=0),
        id="daily_fetch",
        name="매일 메일 수집 및 분석",
        replace_existing=True,
    )
    
    # 매일 오전 9시 30분 일일 리포트 발송
    scheduler.add_job(
        scheduled_daily_report,
        CronTrigger(hour=9, minute=30),
        id="daily_report",
        name="일일 보안 리포트",
        replace_existing=True,
    )
    
    scheduler.start()
    print("✅ 스케줄러 시작 완료")
    print("🔐 Security Mail Analyzer 시작 완료")
    print("📊 NVIDIA GPU 가속 로컬 LLM 분석 지원")
    
    yield
    
    scheduler.shutdown()
    print("📴 Security Mail Analyzer 종료")


async def scheduled_fetch_and_analyze():
    """스케줄된 메일 수집 및 분석"""
    import json
    from backend.models.database import async_session, SecurityAlert
    from backend.services.gmail_service import GmailService
    from backend.services.analyzer_service import SecurityAnalyzerService
    from sqlalchemy import select
    from datetime import datetime
    
    try:
        gmail_query = os.environ.get('GMAIL_QUERY', '')
        label_ids_raw = os.environ.get('GMAIL_LABEL_IDS', '[]')
        try:
            label_ids = json.loads(label_ids_raw)
        except:
            label_ids = []
        
        gmail = GmailService()
        emails = gmail.fetch_security_alerts(
            label_ids=label_ids,
            query=gmail_query,
            max_results=50,
            after_date=datetime.utcnow().strftime("%Y/%m/%d"),
        )
        
        analyzer = SecurityAnalyzerService()
        
        async with async_session() as db:
            for email_data in emails:
                existing_stmt = select(SecurityAlert).where(
                    SecurityAlert.gmail_id == email_data['gmail_id']
                )
                existing = (await db.execute(existing_stmt)).scalar_one_or_none()
                
                if not existing:
                    received_at = datetime.utcnow()
                    if email_data.get('received_at'):
                        try:
                            received_at = datetime.fromisoformat(
                                email_data['received_at'].replace('Z', '+00:00')
                            )
                        except:
                            pass
                    
                    alert = SecurityAlert(
                        gmail_id=email_data['gmail_id'],
                        subject=email_data.get('subject', ''),
                        sender=email_data.get('sender', ''),
                        recipient=email_data.get('recipient', ''),
                        received_at=received_at,
                        body_text=email_data.get('body_text', ''),
                        body_html=email_data.get('body_html', ''),
                        labels=email_data.get('labels', []),
                        status="new",
                    )
                    db.add(alert)
                    await db.flush()
                    
                    await analyzer.analyze_alert(alert, db)
                    db.add(alert)
            
            await db.commit()
            print(f"✅ 스케줄 수집 완료: {len(emails)}개")
    except Exception as e:
        print(f"❌ 스케줄 수집 오류: {e}")


async def scheduled_daily_report():
    """스케줄된 일일 리포트 발송"""
    import json
    from backend.models.database import async_session
    from backend.services.report_service import ReportService
    
    recipients_raw = os.environ.get('REPORT_RECIPIENTS', '[]')
    try:
        recipients = json.loads(recipients_raw)
    except:
        recipients = []
    
    if not recipients:
        print("⚠️ 리포트 수신자가 설정되지 않았습니다.")
        return
    
    smtp_config = None
    if os.environ.get('SMTP_HOST') and os.environ.get('SMTP_USER'):
        smtp_config = {
            'host': os.environ.get('SMTP_HOST', 'smtp.gmail.com'),
            'port': int(os.environ.get('SMTP_PORT', 587)),
            'user': os.environ.get('SMTP_USER', ''),
            'password': os.environ.get('SMTP_PASSWORD', ''),
        }
    
    try:
        report_service = ReportService()
        async with async_session() as db:
            result = await report_service.generate_and_send_report(
                db=db,
                recipients=recipients,
                report_type="daily",
                days=1,
                send_via="smtp" if smtp_config else "gmail",
                smtp_config=smtp_config,
            )
            print(f"✅ 일일 리포트 발송: {result.get('success')}")
    except Exception as e:
        print(f"❌ 리포트 발송 오류: {e}")


# FastAPI 앱 생성
app = FastAPI(
    title="Security Mail Analyzer",
    description="NVIDIA GB10 기반 보안 알람 메일 분석 시스템",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS 설정
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 라우터 등록
from backend.routers.alerts import router as alerts_router
from backend.routers.gmail import router as gmail_router
from backend.routers.llm import router as llm_router
from backend.routers.settings import router as settings_router
from backend.routers.ip_intel import router as ip_router

app.include_router(alerts_router)
app.include_router(gmail_router)
app.include_router(llm_router)
app.include_router(settings_router)
app.include_router(ip_router)

# 정적 파일 (프론트엔드)
static_dir = Path(__file__).parent.parent / "frontend" / "dist"
if static_dir.exists():
    app.mount("/assets", StaticFiles(directory=str(static_dir / "assets")), name="assets")

    @app.get("/{full_path:path}")
    async def serve_spa(full_path: str):
        index_file = static_dir / "index.html"
        if index_file.exists():
            return FileResponse(str(index_file))
        return {"error": "Frontend not built"}
else:
    # 개발 모드 - 프론트엔드 파일 직접 제공
    frontend_dir = Path(__file__).parent.parent / "frontend"
    if frontend_dir.exists():
        app.mount("/static", StaticFiles(directory=str(frontend_dir)), name="frontend")

    @app.get("/")
    async def root():
        """루트 - 프론트엔드 HTML 제공"""
        index_file = frontend_dir / "index.html"
        if index_file.exists():
            return FileResponse(str(index_file))
        return {
            "message": "Security Mail Analyzer API",
            "docs": "/docs",
            "version": "1.0.0",
            "status": "running"
        }


@app.get("/health")
async def health_check():
    """헬스 체크"""
    return {
        "status": "healthy",
        "service": "Security Mail Analyzer",
        "gpu": "NVIDIA GB10",
    }
