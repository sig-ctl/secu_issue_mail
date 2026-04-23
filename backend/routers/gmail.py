"""
Gmail 연동 API 라우터
OAuth + App Password(IMAP) 듀얼 지원
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


@router.get("/status")
async def get_gmail_status():
    """Gmail 연결 상태 확인"""
    gmail = GmailService()

    # 1순위: OAuth 토큰
    creds = gmail._get_credentials()
    if creds and creds.valid:
        return {
            "connected": True,
            "method": "oauth",
            "message": "OAuth 인증 연결됨",
            "token_exists": True,
        }
    if creds and creds.expired:
        return {
            "connected": False,
            "method": "oauth",
            "token_exists": True,
            "expired": True,
            "message": "OAuth 토큰 만료 - 재인증 필요",
        }

    # 2순위: App Password
    gmail_user = os.environ.get('GMAIL_USER', '').strip()
    gmail_password = os.environ.get('GMAIL_APP_PASSWORD', '').strip()

    if gmail_user and gmail_password:
        return {
            "connected": True,
            "method": "app_password",
            "user": gmail_user,
            "message": f"연결됨 ({gmail_user})",
        }

    return {
        "connected": False,
        "token_exists": gmail._has_oauth_token(),
        "message": "Gmail 인증 필요",
    }


@router.get("/labels")
async def get_labels(db: AsyncSession = Depends(get_db)):
    """Gmail 레이블(메일함) 목록 조회 (OAuth 전용)"""
    try:
        gmail = GmailService()
        labels = gmail.list_labels()
        return {"success": True, "labels": labels}
    except Exception as e:
        return {"success": False, "error": str(e), "labels": []}


def _decode_modified_utf7(s: str) -> str:
    """Modified UTF-7 (RFC 2060) → 유니코드 문자열 (Gmail IMAP 폴더명 디코딩)"""
    import base64 as _b64
    res = []
    i = 0
    while i < len(s):
        if s[i] == '&':
            j = s.find('-', i + 1)
            if j == -1:
                res.append(s[i:])
                break
            b64_part = s[i + 1:j]
            if not b64_part:
                res.append('&')
            else:
                b64_part = b64_part.replace(',', '+')
                pad = 4 - len(b64_part) % 4
                if pad != 4:
                    b64_part += '=' * pad
                try:
                    decoded = _b64.b64decode(b64_part).decode('utf-16-be')
                    res.append(decoded)
                except Exception:
                    res.append(s[i:j + 1])
            i = j + 1
        else:
            res.append(s[i])
            i += 1
    return ''.join(res)


@router.get("/mailboxes")
async def get_imap_mailboxes(db: AsyncSession = Depends(get_db)):
    """IMAP 메일함(폴더) 목록 조회 (App Password) - 한글 폴더명 포함"""
    import imaplib as _imap
    import re as _re

    # 환경변수 우선, 없으면 DB 폴백
    gmail_user = os.environ.get('GMAIL_USER', '').strip()
    gmail_password = os.environ.get('GMAIL_APP_PASSWORD', '').strip()

    if not gmail_user:
        stmt = select(Settings).where(Settings.key == 'GMAIL_USER')
        r = await db.execute(stmt)
        s_row = r.scalar_one_or_none()
        gmail_user = (s_row.value or '').strip() if s_row else ''

    if not gmail_password:
        stmt = select(Settings).where(Settings.key == 'GMAIL_APP_PASSWORD')
        r = await db.execute(stmt)
        s_row = r.scalar_one_or_none()
        gmail_password = (s_row.value or '').strip() if s_row else ''

    common = ["INBOX", "[Gmail]/All Mail", "[Gmail]/Spam", "[Gmail]/Sent Mail"]

    if not gmail_user or not gmail_password:
        return {
            "success": False,
            "error": "App Password가 설정되지 않았습니다.",
            "mailboxes": [],
            "common": common,
        }

    try:
        mail = _imap.IMAP4_SSL('imap.gmail.com', 993)
        mail.login(gmail_user, gmail_password)
        _, mailbox_list = mail.list()
        mail.logout()

        mailboxes = []
        for item in mailbox_list:
            if not item:
                continue
            # IMAP LIST 응답을 ASCII로 디코딩 (Modified UTF-7 이름 포함)
            try:
                raw = item.decode('ascii', errors='replace')
            except Exception:
                raw = str(item)

            # Gmail IMAP LIST 응답 형식: (\Flags) "/" "FolderName" 또는 (\Flags) "/" FolderName
            name_raw = None
            m = _re.search(r'(?:"/"|"\.")\s+"([^"]+)"\s*$', raw)
            if m:
                name_raw = m.group(1)
            else:
                m = _re.search(r'(?:"/"|"\.")\s+(\S+)\s*$', raw)
                if m:
                    name_raw = m.group(1).strip('"')

            if not name_raw or name_raw.startswith('\\'):
                continue

            # Modified UTF-7 → 유니코드
            try:
                name = _decode_modified_utf7(name_raw)
            except Exception:
                name = name_raw

            if name:
                mailboxes.append(name)

        if not mailboxes:
            mailboxes = common[:]

        return {
            "success": True,
            "mailboxes": sorted(set(mailboxes)),
            "common": common,
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "mailboxes": [],
            "common": common,
        }


@router.post("/oauth/init")
async def init_oauth(data: dict, db: AsyncSession = Depends(get_db)):
    """OAuth 인증 URL 생성"""
    client_secret_json = data.get('client_secret_json', '')
    if not client_secret_json:
        raise HTTPException(status_code=400, detail="client_secret_json이 필요합니다.")
    gmail = GmailService()
    result = gmail.connect_with_oauth(client_secret_json)
    return result


@router.post("/oauth/complete")
async def complete_oauth(data: dict, db: AsyncSession = Depends(get_db)):
    """OAuth 인증 코드로 토큰 완성"""
    client_secret_json = data.get('client_secret_json', '')
    auth_code = data.get('auth_code', '')
    if not client_secret_json or not auth_code:
        raise HTTPException(status_code=400, detail="client_secret_json과 auth_code가 필요합니다.")
    gmail = GmailService()
    result = gmail.complete_oauth(client_secret_json, auth_code)
    return result


@router.post("/app-password/save")
async def save_app_password(data: dict, db: AsyncSession = Depends(get_db)):
    """App Password 저장 (환경변수 + DB 영구 저장)"""
    gmail_user = data.get('gmail_user', '').strip()
    gmail_password = data.get('gmail_app_password', '').strip()

    if not gmail_user or not gmail_password:
        raise HTTPException(status_code=400, detail="gmail_user와 gmail_app_password가 필요합니다.")

    # 1) 런타임 환경변수 즉시 적용
    os.environ['GMAIL_USER'] = gmail_user
    os.environ['GMAIL_APP_PASSWORD'] = gmail_password
    os.environ['SMTP_USER'] = gmail_user
    os.environ['SMTP_PASSWORD'] = gmail_password
    if not os.environ.get('SMTP_HOST'):
        os.environ['SMTP_HOST'] = 'smtp.gmail.com'
    if not os.environ.get('SMTP_PORT'):
        os.environ['SMTP_PORT'] = '587'

    # 2) DB에 영구 저장 (컨테이너 재시작 후 _load_settings_from_db()에서 복원)
    save_pairs = [
        ('GMAIL_USER', gmail_user, False),
        ('GMAIL_APP_PASSWORD', gmail_password, True),
        ('SMTP_USER', gmail_user, False),
        ('SMTP_PASSWORD', gmail_password, True),
        ('SMTP_HOST', os.environ.get('SMTP_HOST', 'smtp.gmail.com'), False),
        ('SMTP_PORT', os.environ.get('SMTP_PORT', '587'), False),
    ]
    for key, value, is_encrypted in save_pairs:
        stmt = select(Settings).where(Settings.key == key)
        result = await db.execute(stmt)
        existing = result.scalar_one_or_none()
        if existing:
            existing.value = value
            existing.is_encrypted = is_encrypted
            db.add(existing)
        else:
            db.add(Settings(
                key=key,
                value=value,
                description=f"App Password 설정: {key}",
                is_encrypted=is_encrypted,
            ))
    await db.commit()

    # 3) IMAP 연결 테스트
    gmail = GmailService()
    test_result = gmail.test_imap_connection()

    if test_result.get('success'):
        return {
            "success": True,
            "message": f"App Password 저장 완료. {test_result.get('message', '')}",
            "user": gmail_user,
        }
    else:
        return {
            "success": False,
            "message": "설정은 저장됐지만 IMAP 연결 테스트 실패. Gmail에서 2단계 인증 및 앱 비밀번호를 확인하세요.",
            "error": test_result.get('error', ''),
            "user": gmail_user,
        }


@router.post("/fetch")
async def fetch_emails(
    data: dict,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    """Gmail에서 보안 알람 메일 수집 (OAuth 또는 IMAP 자동 선택)"""
    label_ids = data.get('label_ids', [])
    query = data.get('query', '') or os.environ.get('GMAIL_QUERY', '')
    max_results = min(data.get('max_results', 50), 200)
    after_date = data.get('after_date', '')
    # IMAP 메일함: 요청값 → 환경변수 → 기본값 순
    mailbox = (
        data.get('mailbox', '')
        or os.environ.get('GMAIL_MAILBOX', 'INBOX')
    ).strip() or 'INBOX'
    auto_analyze = data.get('auto_analyze', True)
    analyze_model = data.get('model', None)

    try:
        gmail = GmailService()
        emails = gmail.fetch_security_alerts(
            label_ids=label_ids,
            query=query,
            max_results=max_results,
            after_date=after_date,
            mailbox=mailbox,
        )

        saved_count = 0
        duplicate_count = 0
        new_alert_ids = []

        for email_data in emails:
            existing_stmt = select(SecurityAlert).where(
                SecurityAlert.gmail_id == email_data['gmail_id']
            )
            existing_result = await db.execute(existing_stmt)
            existing = existing_result.scalar_one_or_none()

            if existing:
                duplicate_count += 1
                continue

            received_at = datetime.utcnow()
            if email_data.get('received_at'):
                try:
                    import datetime as dt_module
                    parsed = datetime.fromisoformat(
                        email_data['received_at'].replace('Z', '+00:00')
                    )
                    # timezone-aware → naive UTC (PostgreSQL TIMESTAMP WITHOUT TIME ZONE 호환)
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
            saved_count += 1

        await db.commit()

        if auto_analyze and new_alert_ids:
            background_tasks.add_task(
                _batch_analyze_task, new_alert_ids, analyze_model
            )

        return {
            "success": True,
            "fetched": len(emails),
            "saved": saved_count,
            "duplicates": duplicate_count,
            "analyzing": auto_analyze and bool(new_alert_ids),
            "alert_ids": new_alert_ids,
            "message": f"{saved_count}개 새 알람 수집{'(분석 중...)' if auto_analyze and new_alert_ids else ''}",
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
    """Gmail 연결 테스트 (OAuth 또는 IMAP 자동 선택)"""
    gmail = GmailService()
    method = gmail._get_auth_method()

    if method == 'oauth':
        try:
            labels = gmail.list_labels()
            return {
                "success": True,
                "method": "oauth",
                "message": f"OAuth 연결 성공. 레이블 {len(labels)}개 확인됨",
            }
        except Exception as e:
            return {"success": False, "method": "oauth", "error": str(e)}

    elif method == 'app_password':
        return gmail.test_imap_connection()

    else:
        return {
            "success": False,
            "error": "Gmail 인증이 설정되지 않았습니다. App Password 또는 OAuth를 설정해주세요.",
        }
