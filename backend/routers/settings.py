"""
설정 API 라우터
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import Dict, Any
import os
import json

from ..models.database import Settings, get_db
from ..services.report_service import ReportService
from ..services.gmail_service import GmailService

router = APIRouter(prefix="/api/settings", tags=["settings"])


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
        "OLLAMA_MODEL": os.environ.get('OLLAMA_MODEL', 'llama3.2:3b'),
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
async def save_env_settings(data: dict):
    """환경변수 설정 (실시간 적용)"""
    env_vars = {
        'GMAIL_USER': data.get('gmail_user', ''),
        'GMAIL_APP_PASSWORD': data.get('gmail_app_password', ''),
        'OLLAMA_URL': data.get('ollama_url', 'http://localhost:11434'),
        'OLLAMA_MODEL': data.get('ollama_model', 'llama3.2:3b'),
        'SMTP_HOST': data.get('smtp_host', 'smtp.gmail.com'),
        'SMTP_PORT': str(data.get('smtp_port', 587)),
        'SMTP_USER': data.get('smtp_user', ''),
        'SMTP_PASSWORD': data.get('smtp_password', ''),
        'ABUSEIPDB_API_KEY': data.get('abuseipdb_api_key', ''),
        'IPINFO_TOKEN': data.get('ipinfo_token', ''),
        'REPORT_RECIPIENTS': json.dumps(data.get('report_recipients', [])),
        'GMAIL_QUERY': data.get('gmail_query', ''),
        'GMAIL_LABEL_IDS': json.dumps(data.get('gmail_label_ids', [])),
    }
    
    for key, value in env_vars.items():
        if value:
            os.environ[key] = value
    
    # .env 파일에도 저장
    env_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
        ".env"
    )
    
    try:
        existing_env = {}
        if os.path.exists(env_path):
            with open(env_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if '=' in line and not line.startswith('#'):
                        k, v = line.split('=', 1)
                        existing_env[k.strip()] = v.strip()
        
        for key, value in env_vars.items():
            if value:
                existing_env[key] = f'"{value}"'
        
        with open(env_path, 'w') as f:
            f.write("# Security Mail Analyzer Configuration\n")
            for key, value in existing_env.items():
                f.write(f"{key}={value}\n")
    except Exception as e:
        print(f"Error saving .env: {e}")
    
    return {"success": True, "message": "환경 설정이 적용되었습니다."}


@router.get("/env")
async def get_env_settings():
    """현재 환경변수 설정 조회"""
    recipients_raw = os.environ.get('REPORT_RECIPIENTS', '[]')
    try:
        recipients = json.loads(recipients_raw)
    except:
        recipients = [recipients_raw] if recipients_raw else []
    
    label_ids_raw = os.environ.get('GMAIL_LABEL_IDS', '[]')
    try:
        label_ids = json.loads(label_ids_raw)
    except:
        label_ids = []
    
    return {
        "gmail_user": os.environ.get('GMAIL_USER', ''),
        "gmail_app_password": "****" if os.environ.get('GMAIL_APP_PASSWORD') else '',
        "ollama_url": os.environ.get('OLLAMA_URL', 'http://localhost:11434'),
        "ollama_model": os.environ.get('OLLAMA_MODEL', 'llama3.2:3b'),
        "smtp_host": os.environ.get('SMTP_HOST', 'smtp.gmail.com'),
        "smtp_port": int(os.environ.get('SMTP_PORT', 587)),
        "smtp_user": os.environ.get('SMTP_USER', ''),
        "smtp_password": "****" if os.environ.get('SMTP_PASSWORD') else '',
        "abuseipdb_api_key": "****" if os.environ.get('ABUSEIPDB_API_KEY') else '',
        "ipinfo_token": "****" if os.environ.get('IPINFO_TOKEN') else '',
        "report_recipients": recipients,
        "gmail_query": os.environ.get('GMAIL_QUERY', ''),
        "gmail_label_ids": label_ids,
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
