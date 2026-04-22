"""
Gmail 연동 API 라우터
"""
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import List, Optional
from datetime import datetime
import os

from ..models.database import SecurityAlert, Settings, get_db
from ..services.gmail_service import GmailService
from ..services.analyzer_service import SecurityAnalyzerService

router = APIRouter(prefix="/api/gmail", tags=["gmail"])

analyzer = SecurityAnalyzerService()


def get_gmail_service(db_settings: dict = None) -> GmailService:
    """Gmail 서비스 인스턴스 생성"""
    return GmailService()


@router.get("/labels")
async def get_labels(db: AsyncSession = Depends(get_db)):
    """Gmail 레이블(메일함) 목록 조회"""
    try:
        gmail = GmailService()
        labels = gmail.list_labels()
        return {"success": True, "labels": labels}
    except Exception as e:
        return {"success": False, "error": str(e), "labels": []}


@router.post("/oauth/init")
async def init_oauth(data: dict, db: AsyncSession = Depends(get_db)):
    """OAuth 인증 초기화"""
    client_secret_json = data.get('client_secret_json', '')
    if not client_secret_json:
        raise HTTPException(status_code=400, detail="client_secret_json이 필요합니다.")
    
    gmail = GmailService()
    result = gmail.connect_with_oauth(client_secret_json)
    return result


@router.post("/oauth/complete")
async def complete_oauth(data: dict, db: AsyncSession = Depends(get_db)):
    """OAuth 코드로 토큰 완성"""
    client_secret_json = data.get('client_secret_json', '')
    auth_code = data.get('auth_code', '')
    
    if not client_secret_json or not auth_code:
        raise HTTPException(status_code=400, detail="client_secret_json과 auth_code가 필요합니다.")
    
    gmail = GmailService()
    result = gmail.complete_oauth(client_secret_json, auth_code)
    return result


@router.get("/status")
async def get_gmail_status():
    """Gmail 연결 상태 확인"""
    gmail = GmailService()
    
    token_path = gmail.token_path
    has_token = os.path.exists(token_path)
    
    if has_token:
        try:
            creds = gmail._get_credentials()
            if creds and creds.valid:
                return {
                    "connected": True,
                    "token_exists": True,
                    "message": "Gmail 연결됨"
                }
            elif creds and creds.expired:
                return {
                    "connected": False,
                    "token_exists": True,
                    "expired": True,
                    "message": "토큰 만료 - 재인증 필요"
                }
        except Exception as e:
            pass
    
    # 환경변수 체크
    gmail_user = os.environ.get('GMAIL_USER', '')
    gmail_password = os.environ.get('GMAIL_APP_PASSWORD', '')
    
    if gmail_user and gmail_password:
        return {
            "connected": True,
            "method": "app_password",
            "user": gmail_user,
            "message": "App Password 방식 사용"
        }
    
    return {
        "connected": False,
        "token_exists": has_token,
        "message": "Gmail 인증 필요"
    }


@router.post("/fetch")
async def fetch_emails(
    data: dict,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    """Gmail에서 보안 알람 메일 수집"""
    label_ids = data.get('label_ids', [])
    query = data.get('query', '')
    max_results = min(data.get('max_results', 50), 100)
    after_date = data.get('after_date', '')
    auto_analyze = data.get('auto_analyze', True)
    analyze_model = data.get('model', None)
    
    try:
        gmail = GmailService()
        emails = gmail.fetch_security_alerts(
            label_ids=label_ids,
            query=query,
            max_results=max_results,
            after_date=after_date,
        )
        
        # DB에 저장 및 분석
        saved_count = 0
        duplicate_count = 0
        new_alert_ids = []
        
        for email_data in emails:
            # 중복 체크
            existing_stmt = select(SecurityAlert).where(
                SecurityAlert.gmail_id == email_data['gmail_id']
            )
            existing_result = await db.execute(existing_stmt)
            existing = existing_result.scalar_one_or_none()
            
            if existing:
                duplicate_count += 1
                continue
            
            # 날짜 파싱
            received_at = datetime.utcnow()
            if email_data.get('received_at'):
                try:
                    received_at = datetime.fromisoformat(email_data['received_at'].replace('Z', '+00:00'))
                except:
                    pass
            
            # 새 알람 생성
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
            saved_count += 1
        
        await db.commit()
        
        # 백그라운드 분석
        if auto_analyze and new_alert_ids:
            background_tasks.add_task(
                _batch_analyze_task, new_alert_ids, analyze_model
            )
        
        return {
            "success": True,
            "fetched": len(emails),
            "saved": saved_count,
            "duplicates": duplicate_count,
            "analyzing": auto_analyze,
            "alert_ids": new_alert_ids,
            "message": f"{saved_count}개 새 알람 수집{'(분석 중...)' if auto_analyze else ''}",
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"이메일 수집 오류: {str(e)}")


async def _batch_analyze_task(alert_ids: List[int], model: str = None):
    """백그라운드 배치 분석"""
    from ..models.database import async_session
    
    batch_size = 5
    for i in range(0, len(alert_ids), batch_size):
        batch = alert_ids[i:i + batch_size]
        
        async with async_session() as db:
            for alert_id in batch:
                try:
                    stmt = select(SecurityAlert).where(SecurityAlert.id == alert_id)
                    result = await db.execute(stmt)
                    alert = result.scalar_one_or_none()
                    
                    if alert and alert.status == "new":
                        await analyzer.analyze_alert(alert, db, model)
                        db.add(alert)
                except Exception as e:
                    print(f"Analysis error for alert {alert_id}: {e}")
            
            await db.commit()


@router.post("/test-connection")
async def test_gmail_connection():
    """Gmail 연결 테스트"""
    try:
        gmail = GmailService()
        labels = gmail.list_labels()
        return {
            "success": True,
            "message": f"연결 성공. 레이블 {len(labels)}개 발견",
            "labels_count": len(labels)
        }
    except Exception as e:
        return {"success": False, "error": str(e)}
