"""
설정 API 라우터
"""
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import Dict, Any
import os
import json

from ..models.database import Settings, get_db
from ..services.report_service import ReportService
from ..services.gmail_service import GmailService

router = APIRouter(prefix="/api/settings", tags=["settings"])


@router.get("/system-info")
async def get_system_info():
    """시스템 정보 (DB 유형, 모델, GPU 등)"""
    from ..models.database import DATABASE_URL
    db_type = "PostgreSQL" if "postgresql" in DATABASE_URL else "SQLite"
    db_host = "localhost:5432" if db_type == "PostgreSQL" else "local file"
    
    # GPU 정보
    gpu_info = "N/A"
    try:
        import subprocess
        result = subprocess.run(
            ["nvidia-smi", "--query-gpu=name,memory.total", "--format=csv,noheader"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            gpu_info = result.stdout.strip()
    except Exception:
        pass
    
    return {
        "db_type": db_type,
        "db_host": db_host,
        "ollama_url": os.environ.get("OLLAMA_URL", "http://localhost:11434"),
        "ollama_model": os.environ.get("OLLAMA_MODEL", "gemma3:4b"),
        "gpu": gpu_info,
        "frontend_port": 61001,
        "api_port": 8000,
    }


@router.get("/")
async def get_settings(db: AsyncSession = Depends(get_db)):
    """모든 설정 조회 (민감 정보 마스킹)"""
    stmt = select(Settings)
    result = await db.execute(stmt)
    settings = result.scalars().all()
    
    settings_dict = {}
    for s in settings:
        value = s.value
        # 민감 정보 마스킹
        if s.is_encrypted and value and len(value) > 4:
            value = value[:4] + "****" + value[-2:]
        settings_dict[s.key] = {
            "value": value,
            "description": s.description,
            "is_encrypted": s.is_encrypted,
        }
    
    # 환경변수도 포함
    env_settings = {
        "GMAIL_USER": os.environ.get('GMAIL_USER', ''),
        "OLLAMA_URL": os.environ.get('OLLAMA_URL', 'http://localhost:11434'),
        "OLLAMA_MODEL": os.environ.get('OLLAMA_MODEL', 'gemma3:4b'),
        "ABUSEIPDB_API_KEY": "****" if os.environ.get('ABUSEIPDB_API_KEY') else '',
        "IPINFO_TOKEN": "****" if os.environ.get('IPINFO_TOKEN') else '',
    }
    
    return {
        "settings": settings_dict,
        "env": env_settings,
    }


@router.post("/")
async def save_settings(data: dict, db: AsyncSession = Depends(get_db)):
    """설정 저장"""
    settings_data = data.get('settings', {})
    
    for key, value_data in settings_data.items():
        value = value_data if isinstance(value_data, str) else value_data.get('value', '')
        description = value_data.get('description', '') if isinstance(value_data, dict) else ''
        is_encrypted = value_data.get('is_encrypted', False) if isinstance(value_data, dict) else False
        
        # 기존 설정 확인
        stmt = select(Settings).where(Settings.key == key)
        result = await db.execute(stmt)
        existing = result.scalar_one_or_none()
        
        if existing:
            if value and not value.endswith('****'):
                existing.value = value
                existing.description = description or existing.description
                db.add(existing)
        else:
            new_setting = Settings(
                key=key,
                value=value,
                description=description,
                is_encrypted=is_encrypted,
            )
            db.add(new_setting)
    
    await db.commit()
    return {"success": True, "message": "설정이 저장되었습니다."}


@router.post("/env")
async def save_env_settings(data: dict, db: AsyncSession = Depends(get_db)):
    """환경변수 설정 (실시간 적용 + DB 영구 저장)"""
    # 저장할 환경변수 맵 (빈 값은 건너뜀)
    env_vars = {}
    field_map = {
        'gmail_user':         'GMAIL_USER',
        'gmail_app_password': 'GMAIL_APP_PASSWORD',
        'ollama_url':         'OLLAMA_URL',
        'ollama_model':       'OLLAMA_MODEL',
        'smtp_host':          'SMTP_HOST',
        'smtp_port':          'SMTP_PORT',
        'smtp_user':          'SMTP_USER',
        'smtp_password':      'SMTP_PASSWORD',
        'abuseipdb_api_key':  'ABUSEIPDB_API_KEY',
        'ipinfo_token':       'IPINFO_TOKEN',
        'gmail_query':        'GMAIL_QUERY',
        'gmail_mailbox':      'GMAIL_MAILBOX',
        'gmail_max_results':  'GMAIL_MAX_RESULTS',
        'gmail_after_date':   'GMAIL_AFTER_DATE',
        'fetch_interval_minutes': 'FETCH_INTERVAL_MINUTES',
        # 시간대 / 업무시간 설정
        'app_timezone':           'APP_TIMEZONE',
        'business_start_hour':    'BUSINESS_START_HOUR',
        'business_end_hour':      'BUSINESS_END_HOUR',
        'daily_fetch_hour':       'DAILY_FETCH_HOUR',
        'daily_fetch_minute':     'DAILY_FETCH_MINUTE',
        'daily_report_hour':      'DAILY_REPORT_HOUR',
        'daily_report_minute':    'DAILY_REPORT_MINUTE',
    }
    for field, env_key in field_map.items():
        val = data.get(field)
        if val is not None and str(val).strip():
            env_vars[env_key] = str(val).strip()

    # JSON 배열 필드
    if 'report_recipients' in data:
        env_vars['REPORT_RECIPIENTS'] = json.dumps(data['report_recipients'])
    if 'gmail_label_ids' in data:
        env_vars['GMAIL_LABEL_IDS'] = json.dumps(data['gmail_label_ids'])

    # 1) 런타임 환경변수 즉시 적용
    for key, value in env_vars.items():
        os.environ[key] = value

    # FETCH_INTERVAL_MINUTES 변경 시 스케줄러 동적 재적용
    trigger_keys = {'FETCH_INTERVAL_MINUTES', 'APP_TIMEZONE',
                    'DAILY_FETCH_HOUR', 'DAILY_FETCH_MINUTE',
                    'DAILY_REPORT_HOUR', 'DAILY_REPORT_MINUTE'}
    if trigger_keys & set(env_vars.keys()):
        try:
            import backend.main as _main_mod
            if _main_mod._scheduler and _main_mod._scheduler.running:
                _main_mod._apply_fetch_schedule(_main_mod._scheduler)
                _main_mod._apply_cron_schedules(_main_mod._scheduler)
                print(f"🔄 스케줄 재적용: {env_vars}")
        except Exception as _e:
            print(f"⚠️ 스케줄 재적용 실패 (무시): {_e}")

    # 2) DB에 영구 저장 (재시작 후에도 유지)
    sensitive_keys = {'GMAIL_APP_PASSWORD', 'SMTP_PASSWORD', 'ABUSEIPDB_API_KEY', 'IPINFO_TOKEN'}
    for key, value in env_vars.items():
        stmt = select(Settings).where(Settings.key == key)
        result = await db.execute(stmt)
        existing = result.scalar_one_or_none()
        if existing:
            existing.value = value
            existing.is_encrypted = key in sensitive_keys
            db.add(existing)
        else:
            db.add(Settings(
                key=key,
                value=value,
                description=f"Auto-saved env: {key}",
                is_encrypted=key in sensitive_keys,
            ))
    await db.commit()

    return {"success": True, "message": "환경 설정이 적용되었습니다."}


@router.get("/env")
async def get_env_settings(db: AsyncSession = Depends(get_db)):
    """현재 환경변수 설정 조회 (환경변수 → DB 순으로 폴백)"""
    async def _get_val(key: str, default: str = '') -> str:
        """환경변수 우선, 없으면 DB에서 가져옴"""
        val = os.environ.get(key, '').strip()
        if val:
            return val
        try:
            stmt = select(Settings).where(Settings.key == key)
            result = await db.execute(stmt)
            s = result.scalar_one_or_none()
            return (s.value or default) if s else default
        except Exception:
            return default

    gmail_user = await _get_val('GMAIL_USER')
    has_app_password = bool(await _get_val('GMAIL_APP_PASSWORD'))
    ollama_url = await _get_val('OLLAMA_URL', 'http://localhost:11434')
    ollama_model = await _get_val('OLLAMA_MODEL', 'gemma3:4b')
    smtp_host = await _get_val('SMTP_HOST', 'smtp.gmail.com')
    smtp_port_str = await _get_val('SMTP_PORT', '587')
    smtp_user = await _get_val('SMTP_USER')
    has_smtp_password = bool(await _get_val('SMTP_PASSWORD'))
    has_abuseipdb = bool(await _get_val('ABUSEIPDB_API_KEY'))
    has_ipinfo = bool(await _get_val('IPINFO_TOKEN'))
    gmail_query = await _get_val('GMAIL_QUERY')
    gmail_mailbox = await _get_val('GMAIL_MAILBOX', 'INBOX')
    gmail_max_results_str = await _get_val('GMAIL_MAX_RESULTS', '50')
    gmail_after_date = await _get_val('GMAIL_AFTER_DATE', '')
    fetch_interval_str = await _get_val('FETCH_INTERVAL_MINUTES', '0')
    app_timezone = await _get_val('APP_TIMEZONE', 'Asia/Seoul')
    business_start_str = await _get_val('BUSINESS_START_HOUR', '9')
    business_end_str = await _get_val('BUSINESS_END_HOUR', '18')
    daily_fetch_hour_str = await _get_val('DAILY_FETCH_HOUR', '9')
    daily_fetch_minute_str = await _get_val('DAILY_FETCH_MINUTE', '0')
    daily_report_hour_str = await _get_val('DAILY_REPORT_HOUR', '9')
    daily_report_minute_str = await _get_val('DAILY_REPORT_MINUTE', '30')

    recipients_raw = await _get_val('REPORT_RECIPIENTS', '[]')
    try:
        recipients = json.loads(recipients_raw)
    except Exception:
        recipients = [recipients_raw] if recipients_raw else []

    label_ids_raw = await _get_val('GMAIL_LABEL_IDS', '[]')
    try:
        label_ids = json.loads(label_ids_raw)
    except Exception:
        label_ids = []

    return {
        "gmail_user": gmail_user,
        "gmail_app_password": "****" if has_app_password else '',
        "ollama_url": ollama_url,
        "ollama_model": ollama_model,
        "smtp_host": smtp_host,
        "smtp_port": int(smtp_port_str) if smtp_port_str.isdigit() else 587,
        "smtp_user": smtp_user,
        "smtp_password": "****" if has_smtp_password else '',
        "abuseipdb_api_key": "****" if has_abuseipdb else '',
        "ipinfo_token": "****" if has_ipinfo else '',
        "report_recipients": recipients,
        "gmail_query": gmail_query,
        "gmail_label_ids": label_ids,
        "gmail_mailbox": gmail_mailbox,
        "gmail_max_results": int(gmail_max_results_str) if gmail_max_results_str.isdigit() else 50,
        "gmail_after_date": gmail_after_date,
        "fetch_interval_minutes": int(fetch_interval_str) if fetch_interval_str.isdigit() else 0,
        "app_timezone": app_timezone,
        "business_start_hour": int(business_start_str) if business_start_str.isdigit() else 9,
        "business_end_hour": int(business_end_str) if business_end_str.isdigit() else 18,
        "daily_fetch_hour": int(daily_fetch_hour_str) if daily_fetch_hour_str.isdigit() else 9,
        "daily_fetch_minute": int(daily_fetch_minute_str) if daily_fetch_minute_str.isdigit() else 0,
        "daily_report_hour": int(daily_report_hour_str) if daily_report_hour_str.isdigit() else 9,
        "daily_report_minute": int(daily_report_minute_str) if daily_report_minute_str.isdigit() else 30,
    }


@router.post("/report/send")
async def send_report(data: dict, db: AsyncSession = Depends(get_db)):
    """수동 리포트 발송"""
    recipients = data.get('recipients', [])
    if not recipients:
        recipients_raw = os.environ.get('REPORT_RECIPIENTS', '[]')
        try:
            recipients = json.loads(recipients_raw)
        except:
            recipients = []
    
    if not recipients:
        raise HTTPException(status_code=400, detail="수신자 이메일이 필요합니다.")
    
    smtp_config = None
    if os.environ.get('SMTP_HOST') and os.environ.get('SMTP_USER'):
        smtp_config = {
            'host': os.environ.get('SMTP_HOST', 'smtp.gmail.com'),
            'port': int(os.environ.get('SMTP_PORT', 587)),
            'user': os.environ.get('SMTP_USER', ''),
            'password': os.environ.get('SMTP_PASSWORD', ''),
            'use_tls': True,
        }
    
    report_service = ReportService()
    result = await report_service.generate_and_send_report(
        db=db,
        recipients=recipients,
        report_type=data.get('report_type', 'manual'),
        days=data.get('days', 1),
        send_via="smtp" if smtp_config else "gmail",
        smtp_config=smtp_config,
    )
    
    return result


@router.get("/reports")
async def get_reports(db: AsyncSession = Depends(get_db)):
    """발송된 리포트 목록"""
    from ..models.database import AlertReport
    stmt = select(AlertReport).order_by(AlertReport.created_at.desc()).limit(50)
    result = await db.execute(stmt)
    reports = result.scalars().all()
    
    return {
        "reports": [
            {
                "id": r.id,
                "report_type": r.report_type,
                "period_start": r.period_start.isoformat() if r.period_start else None,
                "period_end": r.period_end.isoformat() if r.period_end else None,
                "recipients": r.recipients,
                "subject": r.subject,
                "total_alerts": r.total_alerts,
                "critical_count": r.critical_count,
                "high_count": r.high_count,
                "status": r.status,
                "sent_at": r.sent_at.isoformat() if r.sent_at else None,
                "created_at": r.created_at.isoformat() if r.created_at else None,
            }
            for r in reports
        ]
    }


@router.post("/analyze-pending")
async def analyze_pending_alerts(
    background_tasks: BackgroundTasks,
    data: dict = None,
    db: AsyncSession = Depends(get_db),
):
    """미분석(status=new) 알람 일괄 LLM 분석 트리거"""
    from ..models.database import SecurityAlert
    from ..services.analyzer_service import SecurityAnalyzerService
    from ..models.database import async_session

    limit = (data or {}).get('limit', 200)
    model = (data or {}).get('model', None)

    stmt2 = select(SecurityAlert).where(
        SecurityAlert.status == 'new'
    ).order_by(SecurityAlert.id.asc()).limit(limit)
    result = await db.execute(stmt2)
    pending = result.scalars().all()
    pending_ids = [a.id for a in pending]

    if not pending_ids:
        return {"success": True, "message": "미분석 알람 없음", "queued": 0}

    async def _run_batch(ids, mdl):
        print(f"🔄 일괄 분석 시작: {len(ids)}개")
        analyzer = SecurityAnalyzerService()
        done = 0
        for aid in ids:
            try:
                async with async_session() as s:
                    r = await s.execute(
                        select(SecurityAlert).where(SecurityAlert.id == aid)
                    )
                    alert = r.scalar_one_or_none()
                    if alert and alert.status == 'new':
                        await analyzer.analyze_alert(alert, s, mdl)
                        s.add(alert)
                        await s.commit()
                        print(f"  ✅ 분석 완료: #{aid} [{alert.severity}]{'⏰야간' if alert.after_hours_access else ''}")
                        done += 1
            except Exception as e:
                print(f"⚠️ 알람 {aid} 분석 오류: {str(e)[:100]}")
        print(f"✅ 일괄 분석 완료: {done}/{len(ids)}개")

    background_tasks.add_task(_run_batch, pending_ids, model)

    return {
        "success": True,
        "message": f"{len(pending_ids)}개 알람 분석 시작 (백그라운드 순차)",
        "queued": len(pending_ids),
    }


@router.get("/scheduler-status")
async def get_scheduler_status():
    """자동 수집 스케줄러 상태 조회"""
    try:
        import backend.main as _main_mod
        scheduler = _main_mod._scheduler
        if not scheduler:
            return {"running": False, "jobs": [], "fetch_interval_minutes": 0}

        jobs = []
        for job in scheduler.get_jobs():
            next_run = job.next_run_time
            jobs.append({
                "id": job.id,
                "name": job.name,
                "next_run": next_run.isoformat() if next_run else None,
            })

        interval = int(os.environ.get('FETCH_INTERVAL_MINUTES', '0') or 0)
        return {
            "running": scheduler.running,
            "jobs": jobs,
            "fetch_interval_minutes": interval,
        }
    except Exception as e:
        return {"running": False, "jobs": [], "error": str(e), "fetch_interval_minutes": 0}
