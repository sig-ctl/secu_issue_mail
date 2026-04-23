"""
Gmail Service - 보안 알람 메일 수집 및 발송
OAuth + App Password(IMAP) 듀얼 지원
"""
import base64
import json
import re
import os
import imaplib
import email
from email.header import decode_header
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

    # ── 인증 방식 판별 ──────────────────────────────────────────

    def _has_app_password(self) -> bool:
        """App Password 환경변수 설정 여부"""
        return bool(
            os.environ.get('GMAIL_USER', '').strip() and
            os.environ.get('GMAIL_APP_PASSWORD', '').strip()
        )

    def _has_oauth_token(self) -> bool:
        """OAuth 토큰 파일 존재 여부"""
        return os.path.exists(self.token_path)

    def _get_auth_method(self) -> str:
        """현재 사용 가능한 인증 방식 반환: 'oauth' | 'app_password' | 'none'"""
        creds = self._get_credentials()
        if creds and creds.valid:
            return 'oauth'
        if self._has_app_password():
            return 'app_password'
        return 'none'

    # ── OAuth 인증 ──────────────────────────────────────────────

    def _get_credentials(self) -> Optional[Credentials]:
        """Google OAuth 자격증명 가져오기"""
        creds = None

        if os.path.exists(self.token_path):
            try:
                with open(self.token_path, 'rb') as token:
                    creds = pickle.load(token)
            except Exception:
                return None

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

    def connect_with_oauth(self, client_secret_json: str) -> dict:
        """OAuth 인증 URL 생성"""
        try:
            client_config = json.loads(client_secret_json)
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
            client_config = json.loads(client_secret_json)
            flow = InstalledAppFlow.from_client_config(client_config, SCOPES)
            flow.redirect_uri = 'urn:ietf:wg:oauth:2.0:oob'
            flow.fetch_token(code=auth_code)
            creds = flow.credentials
            with open(self.token_path, 'wb') as token:
                pickle.dump(creds, token)
            return {"success": True, "message": "OAuth 인증 완료"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    # ── Gmail API 서비스 (OAuth 전용) ────────────────────────────

    def get_service(self):
        """Gmail API 서비스 초기화 (OAuth 전용)"""
        if self.service:
            return self.service
        creds = self._get_credentials()
        if not creds:
            raise Exception("Gmail OAuth 인증이 필요합니다. 설정에서 OAuth 연동을 완료해주세요.")
        self.service = build('gmail', 'v1', credentials=creds)
        return self.service

    def list_labels(self) -> List[Dict]:
        """메일함 레이블 목록 (OAuth 전용)"""
        try:
            service = self.get_service()
            results = service.users().labels().list(userId='me').execute()
            labels = results.get('labels', [])
            return [{"id": l['id'], "name": l['name']} for l in labels]
        except Exception:
            return []

    # ── IMAP 수집 (App Password) ────────────────────────────────

    @staticmethod
    def _encode_mailbox_utf7(mailbox: str) -> str:
        """
        Gmail IMAP 메일함명을 Modified UTF-7 (RFC 2060)으로 인코딩.
        실제 Gmail IMAP 서버에서 사용하는 인코딩 방식과 동일하게 처리.
        - ASCII 문자: 그대로
        - '&': '&-'로 이스케이프
        - '/' 구분자: 그대로 (하위폴더 구분자)
        - 한글 등 비ASCII: Modified UTF-7 (&...base64...-)
        """
        if not mailbox:
            return 'INBOX'
        try:
            mailbox.encode('ascii')
            return mailbox  # 순수 ASCII면 그대로
        except UnicodeEncodeError:
            pass

        # 폴더 구분자 '/'를 기준으로 각 파트를 따로 인코딩
        parts = mailbox.split('/')
        encoded_parts = []
        for part in parts:
            try:
                part.encode('ascii')
                encoded_parts.append(part)
                continue
            except UnicodeEncodeError:
                pass
            # Modified UTF-7 인코딩
            res = []
            non_ascii_buf = []

            def flush_buf(buf, out):
                if buf:
                    s = ''.join(buf)
                    b64 = base64.b64encode(s.encode('utf-16-be')).decode('ascii')
                    # Modified UTF-7: base64의 '+'를 ','로 변환
                    b64 = b64.replace('+', ',')
                    # padding '=' 제거
                    b64 = b64.rstrip('=')
                    out.append('&' + b64 + '-')
                    buf.clear()

            for ch in part:
                try:
                    ch.encode('ascii')
                    flush_buf(non_ascii_buf, res)
                    if ch == '&':
                        res.append('&-')
                    else:
                        res.append(ch)
                except UnicodeEncodeError:
                    non_ascii_buf.append(ch)
            flush_buf(non_ascii_buf, res)
            encoded_parts.append(''.join(res))

        return '/'.join(encoded_parts)

    @staticmethod
    def _decode_modified_utf7(name: str) -> str:
        """
        Modified UTF-7 (IMAP RFC 2060) 폴더명을 유니코드 문자열로 디코딩.
        예: "&x3S8pNK4rQC5rA-" → "이벤트관리"
        """
        result = []
        i = 0
        while i < len(name):
            ch = name[i]
            if ch == '&':
                j = name.find('-', i + 1)
                if j == -1:
                    result.append(ch)
                    i += 1
                    continue
                encoded = name[i + 1:j]
                if encoded == '':
                    result.append('&')
                else:
                    # Modified UTF-7: ',' → '+', 패딩 복원
                    b64 = encoded.replace(',', '+')
                    pad = (4 - len(b64) % 4) % 4
                    b64 += '=' * pad
                    try:
                        decoded_bytes = base64.b64decode(b64)
                        result.append(decoded_bytes.decode('utf-16-be'))
                    except Exception:
                        result.append(name[i:j + 1])
                i = j + 1
            else:
                result.append(ch)
                i += 1
        return ''.join(result)

    @staticmethod
    def _find_mailbox_in_list(mailbox_list_raw: list, target_decoded: str) -> Optional[str]:
        """
        IMAP LIST 응답에서 사용자가 입력한 폴더명(유니코드)에 해당하는
        실제 IMAP 인코딩된 폴더명을 찾아 반환.
        
        Gmail IMAP LIST 응답 형식 예시:
        b'(\\HasNoChildren) "/" "INBOX"'
        b'(\\HasNoChildren) "/" "&x3S8pNK4rQC5rA-"'
        b'(\\HasChildren) "/" "[Gmail]"'
        """
        import re as _re
        for item in mailbox_list_raw:
            if not item:
                continue
            try:
                raw = item.decode('ascii', errors='replace')
            except Exception:
                continue
            
            # Gmail IMAP LIST 응답에서 폴더명 추출
            # 형식: (\Flags) "separator" "FolderName" 또는 (\Flags) "/" FolderName
            # 마지막 토큰이 폴더명
            name_raw = None
            
            # 따옴표로 감싸진 폴더명
            m = _re.search(r'"([^"]*)"\\s*$', raw)
            if m:
                name_raw = m.group(1)
            else:
                # 따옴표 없는 폴더명 (구분자 이후)
                m = _re.search(r'(?:"/"|"\."|NIL)\s+(\S+)\s*$', raw)
                if m:
                    name_raw = m.group(1).strip('"')
            
            if not name_raw:
                continue
            
            # Modified UTF-7 디코딩
            try:
                name_decoded = GmailService._decode_modified_utf7(name_raw)
            except Exception:
                name_decoded = name_raw
            
            if name_decoded == target_decoded:
                return name_raw  # 실제 IMAP 전송용 인코딩 이름 반환
        return None

    def _imap_connect(self) -> imaplib.IMAP4_SSL:
        """IMAP 연결 (App Password)"""
        gmail_user = os.environ.get('GMAIL_USER', '').strip()
        gmail_password = os.environ.get('GMAIL_APP_PASSWORD', '').strip()

        if not gmail_user or not gmail_password:
            raise Exception("GMAIL_USER 또는 GMAIL_APP_PASSWORD가 설정되지 않았습니다.")

        try:
            mail = imaplib.IMAP4_SSL('imap.gmail.com', 993)
            mail.login(gmail_user, gmail_password)
            return mail
        except imaplib.IMAP4.error as e:
            raise Exception(f"IMAP 로그인 실패: {str(e)}. App Password가 올바른지 확인하세요.")

    def _decode_mime_header(self, header_value: str) -> str:
        """MIME 인코딩된 헤더 디코딩"""
        if not header_value:
            return ''
        try:
            parts = decode_header(header_value)
            decoded = ''
            for part, charset in parts:
                if isinstance(part, bytes):
                    decoded += part.decode(charset or 'utf-8', errors='ignore')
                else:
                    decoded += str(part)
            return decoded
        except Exception:
            return str(header_value)

    def _extract_body_from_imap(self, msg) -> tuple:
        """IMAP 메시지에서 본문 추출"""
        body_text = ''
        body_html = ''

        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get('Content-Disposition', ''))
                if 'attachment' in content_disposition:
                    continue
                try:
                    payload = part.get_payload(decode=True)
                    if payload is None:
                        continue
                    charset = part.get_content_charset() or 'utf-8'
                    decoded = payload.decode(charset, errors='ignore')
                    if content_type == 'text/plain':
                        body_text += decoded
                    elif content_type == 'text/html':
                        body_html += decoded
                except Exception:
                    pass
        else:
            try:
                payload = msg.get_payload(decode=True)
                if payload:
                    charset = msg.get_content_charset() or 'utf-8'
                    content_type = msg.get_content_type()
                    decoded = payload.decode(charset, errors='ignore')
                    if content_type == 'text/html':
                        body_html = decoded
                    else:
                        body_text = decoded
            except Exception:
                pass

        return body_text, body_html

    def fetch_security_alerts_imap(
        self,
        query: str = None,
        max_results: int = 50,
        after_date: str = None,
        mailbox: str = 'INBOX',
    ) -> List[Dict[str, Any]]:
        """IMAP으로 보안 알람 메일 수집 (App Password)"""
        mail = self._imap_connect()
        emails = []

        try:
            # ── 메일함 선택 ──────────────────────────────────────
            # 전략: IMAP LIST에서 실제 인코딩명을 찾고, 없으면 직접 인코딩 시도
            target_mailbox = (mailbox or 'INBOX').strip()
            selected_mailbox = 'INBOX'
            selected_ok = False

            # 1단계: ASCII면 바로 SELECT 시도
            if target_mailbox != 'INBOX':
                try:
                    target_mailbox.encode('ascii')
                    # 순수 ASCII 폴더명
                    result = mail.select(f'"{target_mailbox}"')
                    if result[0] == 'OK':
                        selected_mailbox = target_mailbox
                        selected_ok = True
                        print(f"메일함 선택 성공 (ASCII): {target_mailbox}")
                except UnicodeEncodeError:
                    pass  # 비ASCII → 아래 단계로
                except Exception as e:
                    print(f"ASCII 폴더 선택 오류: {e}")
            else:
                result = mail.select('INBOX')
                if result[0] == 'OK':
                    selected_mailbox = 'INBOX'
                    selected_ok = True

            # 2단계: IMAP LIST에서 정확한 인코딩명 찾기 (비ASCII 폴더명용)
            if not selected_ok:
                try:
                    _, mailbox_list_raw = mail.list()
                    # 입력한 폴더명과 구분자 변형(- ↔ /)도 함께 시도
                    candidates = [target_mailbox]
                    if '-' in target_mailbox:
                        candidates.append(target_mailbox.replace('-', '/'))
                    if '/' in target_mailbox:
                        candidates.append(target_mailbox.replace('/', '-'))

                    for candidate in candidates:
                        actual_name = self._find_mailbox_in_list(mailbox_list_raw, candidate)
                        if actual_name:
                            # SELECT는 항상 따옴표로 감싸서 전송
                            select_name = f'"{actual_name}"'
                            result = mail.select(select_name)
                            if result[0] == 'OK':
                                selected_mailbox = candidate
                                selected_ok = True
                                print(f"메일함 선택 성공 (LIST 조회): {target_mailbox} → {actual_name}")
                                break
                except Exception as e:
                    print(f"LIST 조회 오류: {e}")

            # 3단계: INBOX 폴백
            if not selected_ok:
                print(f"메일함 '{target_mailbox}' 선택 실패 → INBOX로 폴백")
                mail.select('INBOX')
                selected_mailbox = 'INBOX'

            # ── 검색 조건 구성 ────────────────────────────────────
            search_criteria = []

            if after_date:
                try:
                    date_str = after_date.replace('/', '-')
                    dt = datetime.strptime(date_str, '%Y-%m-%d')
                    imap_date = dt.strftime('%d-%b-%Y')
                    search_criteria.append(f'SINCE "{imap_date}"')
                except Exception:
                    pass

            if query:
                keywords = self._parse_query_to_imap(query)
                # 'ALL'이 아닌 실제 키워드만 추가
                if keywords != ['ALL']:
                    search_criteria.extend(keywords)

            if not search_criteria:
                search_criteria = ['ALL']

            # ── 검색 실행 ─────────────────────────────────────────
            search_str = ' '.join(search_criteria)
            message_ids = None
            try:
                _, message_ids = mail.search(None, search_str)
            except Exception as e:
                print(f"IMAP 검색 오류 ({search_str}): {e}, ALL로 폴백")
                try:
                    _, message_ids = mail.search(None, 'ALL')
                except Exception as e2:
                    print(f"IMAP ALL 검색도 실패: {e2}")
                    return []

            if not message_ids or not message_ids[0]:
                print(f"검색 결과 없음 (폴더: {selected_mailbox}, 조건: {search_str})")
                return []

            # 최신순 정렬 (역순), max_results 제한
            id_list = message_ids[0].split()
            total_found = len(id_list)
            id_list = list(reversed(id_list))[:max_results]
            print(f"IMAP 검색 결과: {total_found}개 중 {len(id_list)}개 처리 (폴더: {selected_mailbox})")

            for num in id_list:
                try:
                    _, msg_data = mail.fetch(num, '(RFC822)')
                    if not msg_data or not msg_data[0]:
                        continue

                    raw_email = msg_data[0][1]
                    if not isinstance(raw_email, bytes):
                        continue

                    msg = email.message_from_bytes(raw_email)

                    # 헤더 파싱
                    subject = self._decode_mime_header(msg.get('Subject', '(제목 없음)'))
                    sender = self._decode_mime_header(msg.get('From', ''))
                    recipient = self._decode_mime_header(msg.get('To', ''))
                    date_str = msg.get('Date', '')
                    message_id_header = msg.get('Message-ID', '')
                    num_str = num.decode() if isinstance(num, bytes) else str(num)

                    # 고유 ID: Message-ID 우선, 없으면 폴더+번호+날짜 조합
                    if message_id_header:
                        gmail_id = re.sub(r'[<>\s]', '', message_id_header)[:255]
                    else:
                        gmail_id = f'imap_{selected_mailbox}_{num_str}_{date_str[:20]}'

                    # 날짜 파싱 → PostgreSQL TIMESTAMP WITHOUT TIME ZONE용 naive UTC datetime
                    received_at = self._parse_date_to_naive_utc(date_str)

                    # 본문 추출
                    body_text, body_html = self._extract_body_from_imap(msg)

                    emails.append({
                        'gmail_id': gmail_id,
                        'subject': subject,
                        'sender': sender,
                        'recipient': recipient,
                        'received_at': received_at.isoformat(),
                        'body_text': body_text,
                        'body_html': body_html,
                        'labels': [selected_mailbox],
                        'snippet': (body_text or body_html)[:200],
                    })

                except Exception as e:
                    print(f"IMAP 메일 파싱 오류 (num={num}): {e}")
                    continue

        finally:
            try:
                mail.logout()
            except Exception:
                pass

        return emails

    @staticmethod
    def _parse_date_to_naive_utc(date_str: str) -> datetime:
        """
        이메일 Date 헤더를 파싱하여 naive UTC datetime 반환.
        PostgreSQL TIMESTAMP WITHOUT TIME ZONE 컬럼 호환.
        timezone-aware datetime은 UTC로 변환 후 tzinfo 제거.
        """
        if date_str:
            try:
                from email.utils import parsedate_to_datetime
                import datetime as dt_module
                parsed = parsedate_to_datetime(date_str)
                if parsed.tzinfo is not None:
                    # UTC로 변환 후 tzinfo 제거 → naive UTC
                    utc_dt = parsed.astimezone(dt_module.timezone.utc)
                    return utc_dt.replace(tzinfo=None)
                return parsed
            except Exception:
                pass
        return datetime.utcnow()

    def _parse_query_to_imap(self, query: str) -> List[str]:
        """Gmail 검색 쿼리를 IMAP 검색 조건으로 변환
        
        지원:
        - subject:키워드 → SUBJECT "키워드"
        - from:주소 → FROM "주소"
        - label:레이블명 → 무시 (IMAP은 폴더 선택으로 처리)
        - in:레이블 → 무시
        - 순수 키워드 → SUBJECT "키워드"
        - 한글 키워드 → UTF-8 인코딩으로 처리
        """
        criteria = []

        # label:, in: 은 IMAP에서 폴더 선택으로 처리되므로 쿼리에서 제거
        clean_query = re.sub(r'(?:label|in):\S+', '', query, flags=re.IGNORECASE).strip()

        # subject: 키워드 추출 (한글 포함)
        subject_matches = re.findall(r'subject:(\S+)', clean_query, re.IGNORECASE)
        for kw in subject_matches:
            # ASCII 전용 키워드만 IMAP SUBJECT 필터로 사용
            try:
                kw.encode('ascii')
                criteria.append(f'SUBJECT "{kw}"')
            except UnicodeEncodeError:
                # 한글 키워드는 UTF-8 search로 시도 (fetch_security_alerts_imap에서 처리)
                criteria.append(('UTF8_SUBJECT', kw))

        # from: 키워드 추출
        from_matches = re.findall(r'from:(\S+)', clean_query, re.IGNORECASE)
        for kw in from_matches:
            try:
                kw.encode('ascii')
                criteria.append(f'FROM "{kw}"')
            except UnicodeEncodeError:
                pass

        # 순수 키워드 (subject:, from: 등 특수 접두사 없는 것)
        if not subject_matches and not from_matches:
            simple_keywords = [
                w for w in clean_query.split()
                if w.upper() not in ('OR', 'AND', 'NOT') and ':' not in w
            ]
            for kw in simple_keywords[:3]:
                try:
                    kw.encode('ascii')
                    criteria.append(f'SUBJECT "{kw}"')
                except UnicodeEncodeError:
                    criteria.append(('UTF8_SUBJECT', kw))

        # UTF8 특수 항목 분리
        ascii_criteria = [c for c in criteria if isinstance(c, str)]
        # utf8_criteria = [c for c in criteria if isinstance(c, tuple)]  # 추후 사용

        if not ascii_criteria:
            return ['ALL']

        # criteria가 여러 개면 OR로 묶기 (IMAP OR은 2개씩)
        if len(ascii_criteria) > 1:
            result = ascii_criteria[0]
            for c in ascii_criteria[1:]:
                result = f'OR ({result}) ({c})'
            return [result]

        return ascii_criteria

    def test_imap_connection(self) -> dict:
        """IMAP 연결 테스트"""
        try:
            mail = self._imap_connect()
            _, mailboxes = mail.list()
            mail.logout()
            return {
                "success": True,
                "method": "app_password",
                "message": f"IMAP 연결 성공. 메일함 {len(mailboxes)}개 확인됨",
                "user": os.environ.get('GMAIL_USER', '')
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    def get_imap_mailbox_list(self) -> List[Dict]:
        """IMAP 메일함 목록 조회 (한글 디코딩 포함)"""
        import re as _re
        mail = self._imap_connect()
        try:
            _, mailbox_list_raw = mail.list()
            mail.logout()
            result = []
            for item in mailbox_list_raw:
                if not item:
                    continue
                try:
                    raw = item.decode('ascii', errors='replace')
                except Exception:
                    continue
                # Gmail IMAP LIST 응답: (\Flags) "separator" "Name" 또는 (\Flags) "/" Name
                name_raw = None
                m = _re.search(r'(?:"/"|"\.")\s+"([^"]+)"\s*$', raw)
                if m:
                    name_raw = m.group(1)
                else:
                    m = _re.search(r'(?:"/"|"\.")\s+(\S+)\s*$', raw)
                    if m:
                        name_raw = m.group(1).strip('"')
                if not name_raw:
                    continue
                try:
                    name_decoded = GmailService._decode_modified_utf7(name_raw)
                except Exception:
                    name_decoded = name_raw
                if name_decoded and not name_decoded.startswith('\\'):
                    result.append({'encoded': name_raw, 'decoded': name_decoded})
            return result
        except Exception:
            try:
                mail.logout()
            except Exception:
                pass
            return []

    # ── 통합 메일 수집 (OAuth 우선, App Password 폴백) ───────────

    def fetch_security_alerts(
        self,
        label_ids: List[str] = None,
        query: str = None,
        max_results: int = 50,
        after_date: str = None,
        mailbox: str = None,
    ) -> List[Dict[str, Any]]:
        """
        보안 알람 메일 수집
        - OAuth 토큰 유효 → Gmail API 사용
        - App Password 설정 → IMAP 사용
        """
        method = self._get_auth_method()
        imap_mailbox = mailbox or os.environ.get('GMAIL_MAILBOX', 'INBOX') or 'INBOX'

        if method == 'oauth':
            return self._fetch_via_gmail_api(label_ids, query, max_results, after_date)
        elif method == 'app_password':
            return self.fetch_security_alerts_imap(query, max_results, after_date, mailbox=imap_mailbox)
        else:
            raise Exception(
                "Gmail 인증이 설정되지 않았습니다. "
                "Gmail 설정에서 App Password 또는 OAuth를 설정해주세요."
            )

    def _fetch_via_gmail_api(
        self,
        label_ids: List[str] = None,
        query: str = None,
        max_results: int = 50,
        after_date: str = None,
    ) -> List[Dict[str, Any]]:
        """Gmail API로 메일 수집 (OAuth)"""
        service = self.get_service()

        search_query = query or ""
        if after_date:
            search_query += f" after:{after_date}"

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

    def _get_email_detail(self, service, message_id: str) -> Optional[Dict]:
        """Gmail API: 이메일 상세 정보"""
        try:
            msg = service.users().messages().get(
                userId='me',
                id=message_id,
                format='full'
            ).execute()

            headers = msg.get('payload', {}).get('headers', [])
            header_map = {h['name'].lower(): h['value'] for h in headers}

            date_str = header_map.get('date', '')
            try:
                from email.utils import parsedate_to_datetime
                import datetime as dt_module
                received_at = parsedate_to_datetime(date_str)
                # timezone-aware → naive UTC (PostgreSQL TIMESTAMP WITHOUT TIME ZONE 호환)
                if received_at.tzinfo is not None:
                    received_at = received_at.astimezone(dt_module.timezone.utc).replace(tzinfo=None)
            except Exception:
                received_at = datetime.utcnow()

            body_text, body_html = self._extract_body_from_api(msg['payload'])
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
            print(f"Gmail API 메일 상세 오류 ({message_id}): {e}")
            return None

    def _extract_body_from_api(self, payload) -> tuple:
        """Gmail API 페이로드에서 본문 추출"""
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

    # ── 이메일 발송 ─────────────────────────────────────────────

    def send_email(
        self,
        to: List[str],
        subject: str,
        html_content: str,
        text_content: str = "",
        sender: str = None
    ) -> dict:
        """Gmail API로 이메일 발송 (OAuth)"""
        try:
            service = self.get_service()
            message = MIMEMultipart('alternative')
            message['To'] = ', '.join(to)
            message['Subject'] = subject
            if sender:
                message['From'] = sender
            if text_content:
                message.attach(MIMEText(text_content, 'plain', 'utf-8'))
            message.attach(MIMEText(html_content, 'html', 'utf-8'))

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
        """SMTP로 이메일 발송 (App Password)"""
        try:
            import smtplib
            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From'] = smtp_user
            msg['To'] = ', '.join(to)
            msg.attach(MIMEText(html_content, 'html', 'utf-8'))

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
