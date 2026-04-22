"""
Gmail Service - 보안 알람 메일 수집 및 발송
"""
import base64
import json
import re
import os
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import List, Optional, Dict, Any
from datetime import datetime

from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
import pickle


SCOPES = [
    'https://www.googleapis.com/auth/gmail.readonly',
    'https://www.googleapis.com/auth/gmail.send',
    'https://www.googleapis.com/auth/gmail.modify',
]


class GmailService:
    def __init__(self, credentials_json: str = None, token_path: str = None):
        self.credentials_json = credentials_json
        self.token_path = token_path or os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
            "data", "db", "gmail_token.pickle"
        )
        self.service = None

    def _get_credentials(self) -> Optional[Credentials]:
        """Google API 자격증명 가져오기"""
        creds = None
        
        if os.path.exists(self.token_path):
            with open(self.token_path, 'rb') as token:
                creds = pickle.load(token)
        
        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                try:
                    creds.refresh(Request())
                    with open(self.token_path, 'wb') as token:
                        pickle.dump(creds, token)
                    return creds
                except Exception as e:
                    print(f"Token refresh failed: {e}")
                    return None
            return None
        
        return creds

    def _init_service_from_env(self) -> bool:
        """환경변수 기반 OAuth 또는 App Password 인증"""
        gmail_user = os.environ.get('GMAIL_USER', '')
        gmail_password = os.environ.get('GMAIL_APP_PASSWORD', '')
        
        if gmail_user and gmail_password:
            # SMTP/IMAP App Password 방식
            return True
        
        return False

    def connect_with_oauth(self, client_secret_json: str) -> dict:
        """OAuth 인증 URL 생성"""
        try:
            import json as json_module
            client_config = json_module.loads(client_secret_json)
            
            flow = InstalledAppFlow.from_client_config(client_config, SCOPES)
            flow.redirect_uri = 'urn:ietf:wg:oauth:2.0:oob'
            
            auth_url, _ = flow.authorization_url(
                access_type='offline',
                include_granted_scopes='true',
                prompt='consent'
            )
            
            return {
                "success": True,
                "auth_url": auth_url,
                "message": "아래 URL을 브라우저에서 열어 인증 코드를 받아 입력하세요."
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    def complete_oauth(self, client_secret_json: str, auth_code: str) -> dict:
        """OAuth 인증 코드로 토큰 완성"""
        try:
            import json as json_module
            client_config = json_module.loads(client_secret_json)
            
            flow = InstalledAppFlow.from_client_config(client_config, SCOPES)
            flow.redirect_uri = 'urn:ietf:wg:oauth:2.0:oob'
            flow.fetch_token(code=auth_code)
            
            creds = flow.credentials
            with open(self.token_path, 'wb') as token:
                pickle.dump(creds, token)
            
            return {"success": True, "message": "인증 완료"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def get_service(self):
        """Gmail API 서비스 초기화"""
        if self.service:
            return self.service
        
        creds = self._get_credentials()
        if not creds:
            raise Exception("Gmail 인증이 필요합니다. 설정에서 Gmail 연동을 완료해주세요.")
        
        self.service = build('gmail', 'v1', credentials=creds)
        return self.service

    def list_labels(self) -> List[Dict]:
        """메일함 레이블 목록 가져오기"""
        try:
            service = self.get_service()
            results = service.users().labels().list(userId='me').execute()
            labels = results.get('labels', [])
            return [{"id": l['id'], "name": l['name']} for l in labels]
        except Exception as e:
            return []

    def fetch_security_alerts(
        self, 
        label_ids: List[str] = None,
        query: str = None,
        max_results: int = 50,
        after_date: str = None
    ) -> List[Dict[str, Any]]:
        """보안 알람 메일 가져오기"""
        try:
            service = self.get_service()
            
            # 검색 쿼리 구성
            search_query = query or ""
            if after_date:
                search_query += f" after:{after_date}"
            
            # 메시지 목록 가져오기
            params = {
                'userId': 'me',
                'maxResults': max_results,
            }
            if label_ids:
                params['labelIds'] = label_ids
            if search_query:
                params['q'] = search_query
            
            results = service.users().messages().list(**params).execute()
            messages = results.get('messages', [])
            
            emails = []
            for msg in messages:
                email_data = self._get_email_detail(service, msg['id'])
                if email_data:
                    emails.append(email_data)
            
            return emails
        except Exception as e:
            print(f"Gmail fetch error: {e}")
            raise

    def _get_email_detail(self, service, message_id: str) -> Optional[Dict]:
        """이메일 상세 정보 가져오기"""
        try:
            msg = service.users().messages().get(
                userId='me',
                id=message_id,
                format='full'
            ).execute()
            
            headers = msg.get('payload', {}).get('headers', [])
            header_map = {h['name'].lower(): h['value'] for h in headers}
            
            # 날짜 파싱
            date_str = header_map.get('date', '')
            try:
                from email.utils import parsedate_to_datetime
                received_at = parsedate_to_datetime(date_str)
            except:
                received_at = datetime.utcnow()
            
            # 본문 추출
            body_text, body_html = self._extract_body(msg['payload'])
            
            # Gmail 라벨
            labels = msg.get('labelIds', [])
            
            return {
                'gmail_id': message_id,
                'subject': header_map.get('subject', '(제목 없음)'),
                'sender': header_map.get('from', ''),
                'recipient': header_map.get('to', ''),
                'received_at': received_at.isoformat() if hasattr(received_at, 'isoformat') else str(received_at),
                'body_text': body_text,
                'body_html': body_html,
                'labels': labels,
                'snippet': msg.get('snippet', ''),
            }
        except Exception as e:
            print(f"Email detail fetch error for {message_id}: {e}")
            return None

    def _extract_body(self, payload) -> tuple:
        """이메일 본문 추출"""
        body_text = ""
        body_html = ""
        
        def decode_part(part):
            nonlocal body_text, body_html
            
            mime_type = part.get('mimeType', '')
            body = part.get('body', {})
            data = body.get('data', '')
            
            if data:
                try:
                    decoded = base64.urlsafe_b64decode(data + '==').decode('utf-8', errors='ignore')
                    if mime_type == 'text/plain':
                        body_text += decoded
                    elif mime_type == 'text/html':
                        body_html += decoded
                except Exception:
                    pass
            
            for sub_part in part.get('parts', []):
                decode_part(sub_part)
        
        decode_part(payload)
        return body_text, body_html

    def send_email(
        self,
        to: List[str],
        subject: str,
        html_content: str,
        text_content: str = "",
        sender: str = None
    ) -> dict:
        """이메일 발송"""
        try:
            service = self.get_service()
            
            message = MIMEMultipart('alternative')
            message['To'] = ', '.join(to)
            message['Subject'] = subject
            if sender:
                message['From'] = sender
            
            if text_content:
                part1 = MIMEText(text_content, 'plain', 'utf-8')
                message.attach(part1)
            
            part2 = MIMEText(html_content, 'html', 'utf-8')
            message.attach(part2)
            
            raw = base64.urlsafe_b64encode(message.as_bytes()).decode()
            result = service.users().messages().send(
                userId='me',
                body={'raw': raw}
            ).execute()
            
            return {"success": True, "message_id": result.get('id')}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def send_email_smtp(
        self,
        to: List[str],
        subject: str,
        html_content: str,
        smtp_host: str,
        smtp_port: int,
        smtp_user: str,
        smtp_password: str,
        use_tls: bool = True
    ) -> dict:
        """SMTP로 이메일 발송 (App Password 방식)"""
        try:
            import smtplib
            from email.mime.multipart import MIMEMultipart as MIME
            from email.mime.text import MIMEText as MIMET
            
            msg = MIME('alternative')
            msg['Subject'] = subject
            msg['From'] = smtp_user
            msg['To'] = ', '.join(to)
            
            part = MIMET(html_content, 'html', 'utf-8')
            msg.attach(part)
            
            if use_tls:
                server = smtplib.SMTP(smtp_host, smtp_port)
                server.ehlo()
                server.starttls()
            else:
                server = smtplib.SMTP_SSL(smtp_host, smtp_port)
            
            server.login(smtp_user, smtp_password)
            server.sendmail(smtp_user, to, msg.as_string())
            server.quit()
            
            return {"success": True, "message": f"{len(to)}명에게 발송 완료"}
        except Exception as e:
            return {"success": False, "error": str(e)}
