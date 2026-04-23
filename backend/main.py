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


async def _load_settings_from_db():
    """DB에 저장된 설정을 환경변수로 로드 (컨테이너 재시작 후에도 설정 유지)
    
    DB 값이 docker-compose environment 블록보다 항상 우선합니다.
    사용자가 UI에서 설정한 값은 DB에 저장되므로, 재시작 후에도 유지됩니다.
    """
    try:
        from backend.models.database import async_session, Settings
        from sqlalchemy import select

        # 사용자 설정 키 (DB 값이 docker-compose 기본값보다 우선)
        USER_CONFIGURABLE_KEYS = [
            'GMAIL_USER', 'GMAIL_APP_PASSWORD', 'GMAIL_QUERY', 'GMAIL_LABEL_IDS',
            'GMAIL_MAILBOX', 'GMAIL_MAX_RESULTS', 'GMAIL_AFTER_DATE',
            'OLLAMA_URL', 'OLLAMA_MODEL',
            'SMTP_HOST', 'SMTP_PORT', 'SMTP_USER', 'SMTP_PASSWORD',
            'REPORT_RECIPIENTS',
            'ABUSEIPDB_API_KEY', 'IPINFO_TOKEN',
            'FETCH_INTERVAL_MINUTES',  # 자동 수집 주기 (분)
            'APP_TIMEZONE',            # 표시 시간대 (기본: Asia/Seoul)
            'BUSINESS_START_HOUR',     # 업무 시작 시간 (기본: 9)
            'BUSINESS_END_HOUR',       # 업무 종료 시간 (기본: 18)
            'DAILY_FETCH_HOUR',        # 일일 수집 시각 - 시 (기본: 9)
            'DAILY_FETCH_MINUTE',      # 일일 수집 시각 - 분 (기본: 0)
            'DAILY_REPORT_HOUR',       # 일일 리포트 시각 - 시 (기본: 9)
            'DAILY_REPORT_MINUTE',     # 일일 리포트 시각 - 분 (기본: 30)
        ]
        async with async_session() as db:
            stmt = select(Settings).where(Settings.key.in_(USER_CONFIGURABLE_KEYS))
            result = await db.execute(stmt)
            settings = result.scalars().all()
            loaded = 0
            for s in settings:
                if s.value and s.value.strip():
                    # DB 값이 항상 우선 (사용자가 UI에서 설정한 값)
                    # docker-compose environment 블록의 기본값을 덮어씀
                    os.environ[s.key] = s.value
                    loaded += 1
            print(f"✅ DB에서 사용자 설정 {loaded}개 로드 완료 (docker-compose 기본값 덮어씀)")
    except Exception as e:
        print(f"⚠️  DB 설정 로드 실패 (무시): {e}")


_scheduler: AsyncIOScheduler = None   # 전역 스케줄러 (동적 재설정용)


def _get_app_timezone() -> str:
    """현재 설정된 APP_TIMEZONE 반환 (기본: Asia/Seoul)"""
    return os.environ.get('APP_TIMEZONE', 'Asia/Seoul') or 'Asia/Seoul'


def _apply_fetch_schedule(scheduler: AsyncIOScheduler):
    """FETCH_INTERVAL_MINUTES 환경변수 기반으로 수집 스케줄 동적 적용"""
    from apscheduler.triggers.interval import IntervalTrigger

    interval_min = int(os.environ.get('FETCH_INTERVAL_MINUTES', '0') or 0)

    # 기존 주기 수집 job 제거
    try:
        scheduler.remove_job('periodic_fetch')
    except Exception:
        pass

    if interval_min >= 10:   # 최소 10분
        scheduler.add_job(
            scheduled_fetch_and_analyze,
            IntervalTrigger(minutes=interval_min),
            id='periodic_fetch',
            name=f'자동 메일 수집 ({interval_min}분마다)',
            replace_existing=True,
            next_run_time=None,          # 즉시 실행하지 않고 첫 인터벌 후 실행
        )
        print(f"✅ 자동 수집 스케줄 설정: {interval_min}분 간격")
    else:
        print("ℹ️  자동 수집 주기 미설정 (수동 또는 일 1회)")


def _apply_cron_schedules(scheduler: AsyncIOScheduler):
    """일일 수집/리포트 Cron 스케줄을 설정 기반으로 재적용"""
    tz = _get_app_timezone()
    fetch_h   = int(os.environ.get('DAILY_FETCH_HOUR',   '9')  or '9')
    fetch_m   = int(os.environ.get('DAILY_FETCH_MINUTE', '0')  or '0')
    report_h  = int(os.environ.get('DAILY_REPORT_HOUR',  '9')  or '9')
    report_m  = int(os.environ.get('DAILY_REPORT_MINUTE','30') or '30')

    scheduler.add_job(
        scheduled_fetch_and_analyze,
        CronTrigger(hour=fetch_h, minute=fetch_m, timezone=tz),
        id="daily_fetch",
        name=f"매일 {fetch_h:02d}:{fetch_m:02d} 메일 수집 및 분석",
        replace_existing=True,
    )
    scheduler.add_job(
        scheduled_daily_report,
        CronTrigger(hour=report_h, minute=report_m, timezone=tz),
        id="daily_report",
        name=f"일일 보안 리포트 ({report_h:02d}:{report_m:02d})",
        replace_existing=True,
    )
    print(f"✅ 일일 스케줄 재적용: 수집={fetch_h:02d}:{fetch_m:02d}, 리포트={report_h:02d}:{report_m:02d} [{tz}]")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """앱 시작/종료 이벤트"""
    global _scheduler

    # DB 초기화
    from backend.models.database import init_db
    await init_db()
    print("✅ 데이터베이스 초기화 완료")

    # DB에 저장된 설정 로드 → 환경변수 반영
    await _load_settings_from_db()
    print("✅ 설정 로드 완료")

    # 스케줄러 시작 (설정된 시간대 사용)
    _scheduler = AsyncIOScheduler(timezone=_get_app_timezone())

    # 일일 수집/리포트 Cron 적용 (APP_TIMEZONE, DAILY_FETCH_HOUR 등 반영)
    _apply_cron_schedules(_scheduler)

    # 주기 수집 설정이 있으면 추가
    _apply_fetch_schedule(_scheduler)

    _scheduler.start()
    print("✅ 스케줄러 시작 완료")
    print("🔐 Security Mail Analyzer 시작 완료")
    print("📊 NVIDIA GPU 가속 로컬 LLM 분석 지원")

    yield

    _scheduler.shutdown()
    print("📴 Security Mail Analyzer 종료")


async def scheduled_fetch_and_analyze():
    """스케줄된 메일 수집 및 분석 (수집 → commit → 분석 순서로 분리)"""
    import json
    import datetime as dt_module
    from backend.models.database import async_session, SecurityAlert
    from backend.services.gmail_service import GmailService
    from backend.services.analyzer_service import SecurityAnalyzerService
    from sqlalchemy import select
    from datetime import datetime

    try:
        gmail_query = os.environ.get('GMAIL_QUERY', '')
        gmail_mailbox = os.environ.get('GMAIL_MAILBOX', 'INBOX')
        gmail_max_results = int(os.environ.get('GMAIL_MAX_RESULTS', '50'))
        gmail_after_date = os.environ.get('GMAIL_AFTER_DATE', '')
        label_ids_raw = os.environ.get('GMAIL_LABEL_IDS', '[]')
        try:
            label_ids = json.loads(label_ids_raw)
        except Exception:
            label_ids = []

        # after_date: DB 설정 우선, 없으면 오늘 날짜(설정된 시간대)
        if not gmail_after_date:
            from zoneinfo import ZoneInfo
            tz_name = os.environ.get('APP_TIMEZONE', 'Asia/Seoul') or 'Asia/Seoul'
            now_local = datetime.now(ZoneInfo(tz_name))
            gmail_after_date = now_local.strftime("%Y/%m/%d")

        gmail = GmailService()
        emails = gmail.fetch_security_alerts(
            label_ids=label_ids,
            query=gmail_query,
            max_results=gmail_max_results,
            after_date=gmail_after_date,
            mailbox=gmail_mailbox,
        )

        # ── 1단계: 수집 → DB 저장만 commit ──────────────────────
        new_alert_ids = []
        async with async_session() as db:
            for email_data in emails:
                existing_stmt = select(SecurityAlert).where(
                    SecurityAlert.gmail_id == email_data['gmail_id']
                )
                existing = (await db.execute(existing_stmt)).scalar_one_or_none()
                if existing:
                    continue

                received_at = datetime.utcnow()
                if email_data.get('received_at'):
                    try:
                        parsed = datetime.fromisoformat(
                            email_data['received_at'].replace('Z', '+00:00')
                        )
                        if parsed.tzinfo is not None:
                            parsed = parsed.astimezone(dt_module.timezone.utc).replace(tzinfo=None)
                        received_at = parsed
                    except Exception:
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
                new_alert_ids.append(alert.id)

            await db.commit()
            print(f"✅ 스케줄 수집 완료: {len(emails)}개 수신 / {len(new_alert_ids)}개 신규 저장")

        # ── 2단계: 저장된 알람 LLM 분석 (별도 세션, 건별 commit) ──
        if new_alert_ids:
            analyzer = SecurityAnalyzerService()
            analyzed = 0
            for alert_id in new_alert_ids:
                try:
                    async with async_session() as db:
                        stmt = select(SecurityAlert).where(SecurityAlert.id == alert_id)
                        result = await db.execute(stmt)
                        alert = result.scalar_one_or_none()
                        if alert and alert.status == "new":
                            await analyzer.analyze_alert(alert, db)
                            db.add(alert)
                            await db.commit()
                            analyzed += 1
                except Exception as e:
                    print(f"⚠️ 알람 {alert_id} 분석 오류 (건너뜀): {e}")
            print(f"✅ 스케줄 분석 완료: {analyzed}/{len(new_alert_ids)}개")

    except Exception as e:
        print(f"❌ 스케줄 수집/분석 오류: {e}")


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
