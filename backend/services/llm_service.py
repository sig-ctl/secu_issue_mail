"""
LLM Service - Ollama 기반 로컬 LLM 연동
NVIDIA GB10 최적화
"""
import httpx
import json
import os
from typing import Optional, List, Dict, Any, AsyncGenerator
from datetime import datetime
import asyncio


class OllamaLLMService:
    def __init__(self, base_url: str = None, model: str = None):
        self.base_url = base_url or os.environ.get('OLLAMA_URL', 'http://localhost:11434')
        self.model = model or os.environ.get('OLLAMA_MODEL', 'llama3.2:3b')
        self.timeout = httpx.Timeout(120.0, connect=10.0)

    async def check_connection(self) -> dict:
        """Ollama 연결 확인"""
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(f"{self.base_url}/api/tags")
                if resp.status_code == 200:
                    data = resp.json()
                    models = [m['name'] for m in data.get('models', [])]
                    return {
                        "connected": True,
                        "models": models,
                        "message": f"연결 성공. 모델 {len(models)}개 사용 가능"
                    }
                return {"connected": False, "error": f"Status {resp.status_code}"}
        except Exception as e:
            return {"connected": False, "error": str(e)}

    async def list_models(self) -> List[str]:
        """사용 가능한 모델 목록"""
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(f"{self.base_url}/api/tags")
                if resp.status_code == 200:
                    data = resp.json()
                    return [m['name'] for m in data.get('models', [])]
        except:
            pass
        return []

    async def pull_model(self, model_name: str) -> AsyncGenerator[str, None]:
        """모델 다운로드"""
        async with httpx.AsyncClient(timeout=httpx.Timeout(600.0)) as client:
            async with client.stream('POST', f"{self.base_url}/api/pull",
                                     json={"name": model_name}) as resp:
                async for line in resp.aiter_lines():
                    if line:
                        try:
                            data = json.loads(line)
                            yield json.dumps(data)
                        except:
                            pass

    async def analyze_security_alert(
        self,
        email_subject: str,
        email_body: str,
        email_sender: str = "",
        context: str = "",
        received_at_kst=None,
        after_hours: bool = False,
        model: str = None
    ) -> Dict[str, Any]:
        """보안 알람 메일 분석"""
        
        system_prompt = """당신은 SOC(Security Operations Center) 보안 전문가 AI입니다.
보안 알람 이메일을 분석하여 다음 항목을 평가하세요:

1. 심각도 (critical/high/medium/low/info)
   - critical: 즉각 대응 필요 (침해사고, 랜섬웨어, 데이터 유출 등)
   - high: 높은 위험 (외부 공격 성공 가능성, 민감 시스템 접근)
   - medium: 주의 필요 (반복 스캔, 의심 접속 시도, 권한 남용)
   - low: 낮은 위험 (단순 차단된 시도, 일반 스캔)
   - info: 정보성 (정상 운영 알람, 오탐 가능성 높음)

2. 알람 유형 (예: 네트워크스캔, 원격접속시도, 포트스캔, 무차별대입, 내부스캔, 악성코드, DDoS, 정보유출시도 등)

3. 오탐(False Positive) 여부
   - 업무용 원격접속 솔루션(AnyDesk, TeamViewer, Chrome Remote Desktop)의 정상 차단은 오탐 가능
   - 단, 업무시간 외에 발생했거나 반복적이면 실제 위협 가능성 상향

4. 시간외 접속 분석 (after_hours_access)
   - 평일 09:00~18:00 이외 또는 주말/공휴일 발생은 위험도 상향 요인
   - 시간외 내부 IP 이상 접속, 관리자 계정 접근, 민감 포트 접근은 특히 위험
   - after_hours_risk 필드에 시간외 접속의 위험성을 구체적으로 기술

5. 핵심 지표 추출: IP 주소, 도메인, 사용자 계정, 보안 이벤트 등

6. 대응 권고사항 (구체적이고 실행 가능하게)

반드시 JSON 형식으로만 응답하세요."""

        # body는 최대 2000자로 제한 (속도 최적화)
        body_excerpt = (email_body or '')[:2000]

        # 시간 정보 구성
        time_part = ""
        if received_at_kst:
            weekday_names = ["월", "화", "수", "목", "금", "토", "일"]
            wd = weekday_names[received_at_kst.weekday()]
            time_label = "⚠️ 업무시간 외(야간/주말)" if after_hours else "업무시간 내(평일 09-18시)"
            time_part = f"알람 발생 시각(KST): {received_at_kst.strftime('%Y-%m-%d %H:%M')} ({wd}요일) [{time_label}]\n"

        context_part = f"참고 컨텍스트: {context}\n" if context else ""

        user_prompt = f"""다음 보안 알람을 분석하세요:

제목: {email_subject}
발신자: {email_sender}
{time_part}{context_part}
이메일 내용:
{body_excerpt}

JSON 형식으로만 응답하세요 (다른 설명 없이):
{{
  "severity": "critical|high|medium|low|info",
  "severity_score": 0.0,
  "alert_type": "알람 유형",
  "summary": "한 문장 요약",
  "analysis": "상세 분석 (시간외 발생 여부 포함)",
  "is_false_positive": false,
  "false_positive_reason": "오탐 이유 (오탐 아니면 빈 문자열)",
  "is_repeated": false,
  "after_hours_access": false,
  "after_hours_risk": "시간외 접속 위험 평가 (해당 없으면 빈 문자열)",
  "extracted_ips": [],
  "extracted_domains": [],
  "extracted_users": [],
  "extracted_events": [],
  "recommendation": "구체적 대응 권고사항"
}}"""

        return await self._chat(system_prompt, user_prompt, model or self.model, expect_json=True)

    async def analyze_batch_alerts(
        self,
        alerts: List[Dict],
        model: str = None
    ) -> Dict[str, Any]:
        """다수 알람 배치 분석 - 패턴 및 트렌드 파악"""
        
        alert_summaries = []
        for i, alert in enumerate(alerts[:20]):  # 최대 20개
            alert_summaries.append(
                f"{i+1}. [{alert.get('severity','?')}] {alert.get('subject','')[:100]}"
                f" | IP: {', '.join((alert.get('extracted_ips') or [])[:3])}"
            )
        
        system_prompt = """당신은 SOC(Security Operations Center) 분석가입니다. 
여러 보안 알람들의 패턴을 분석하여 전체적인 보안 상황을 평가합니다."""

        user_prompt = f"""다음 {len(alerts)}개의 보안 알람을 종합 분석해주세요:

{chr(10).join(alert_summaries)}

JSON 형식으로 응답:
{{
  "overall_risk_level": "critical|high|medium|low",
  "threat_summary": "전체 위협 상황 요약",
  "attack_patterns": ["감지된 공격 패턴"],
  "top_threat_ips": ["주요 위협 IP"],
  "recurring_issues": ["반복적인 문제"],
  "false_positive_patterns": ["오탐 패턴"],
  "recommendations": ["우선순위별 권고사항"],
  "trend_analysis": "트렌드 분석"
}}"""

        return await self._chat(system_prompt, user_prompt, model or self.model, expect_json=True)

    async def chat(
        self,
        messages: List[Dict[str, str]],
        context_alerts: List[Dict] = None,   # 하위 호환 (pinned_alerts와 동일)
        pinned_alerts: List[Dict] = None,    # 특정 알람 고정 컨텍스트
        db_context: Dict = None,             # DB 전체 통계 컨텍스트
        model: str = None
    ) -> str:
        """일반 채팅 - 보안 지식 질의응답 (DB 알람 데이터 자동 컨텍스트 주입)"""

        # pinned_alerts는 context_alerts와 통합
        all_pinned = list(pinned_alerts or []) + list(context_alerts or [])

        # ── 시스템 프롬프트 구성 ──────────────────────────────
        tz_name = os.environ.get('APP_TIMEZONE', 'Asia/Seoul') or 'Asia/Seoul'
        biz_start = int(os.environ.get('BUSINESS_START_HOUR', '9') or '9')
        biz_end   = int(os.environ.get('BUSINESS_END_HOUR', '18') or '18')

        system_lines = [
            "당신은 SOC(Security Operations Center) 보안 전문가 AI 어시스턴트입니다.",
            "현재 시스템에 수집된 실제 보안 알람 데이터를 기반으로 분석하고 답변합니다.",
            f"표시 시간대: {tz_name} | 업무시간: {biz_start:02d}:00~{biz_end:02d}:00 (평일)",
            "한국어로 명확하고 구체적으로 답변하세요.",
            "",
        ]

        # DB 전체 통계 주입
        if db_context and db_context.get('total', 0) > 0:
            days = db_context.get('days', 7)
            sev = db_context.get('sev_stats', {})
            system_lines += [
                f"=== 최근 {days}일 보안 알람 현황 (실시간 DB 데이터) ===",
                f"총 알람: {db_context['total']}건"
                f" | Critical:{sev.get('critical',0)} High:{sev.get('high',0)}"
                f" Medium:{sev.get('medium',0)} Low:{sev.get('low',0)} Info:{sev.get('info',0)}",
                f"오탐: {db_context.get('fp_count',0)}건"
                f" | 야간발생: {db_context.get('after_hours_count',0)}건"
                f" | 반복알람: {db_context.get('repeated_count',0)}건",
                "",
            ]

            alert_lines = db_context.get('alert_lines', [])
            if alert_lines:
                system_lines.append(f"--- 최근 알람 목록 (최대 20개) ---")
                system_lines.extend(alert_lines[:20])
                system_lines.append("")

            ip_lines = db_context.get('ip_lines', [])
            if ip_lines:
                system_lines.append("--- 상위 위협 IP ---")
                system_lines.extend(ip_lines)
                system_lines.append("")

            system_lines.append("위 데이터를 기반으로 사용자 질문에 정확하게 답변하세요.")
        else:
            system_lines.append(
                "※ 현재 분석된 보안 알람 데이터가 없습니다. "
                "Gmail 수집 후 LLM 분석을 진행하면 실제 데이터 기반 답변이 가능합니다."
            )

        # 특정 알람 고정 컨텍스트
        if all_pinned:
            system_lines.append("")
            system_lines.append("=== 현재 조회 중인 특정 알람 ===")
            for a in all_pinned[:5]:
                system_lines.append(
                    f"[ID:{a.get('id')} {(a.get('severity','?')).upper()}] "
                    f"{a.get('alert_type','')} | {a.get('subject','')}"
                )
                if a.get('llm_summary'):
                    system_lines.append(f"  요약: {a['llm_summary'][:200]}")
                if a.get('llm_analysis'):
                    system_lines.append(f"  분석: {a['llm_analysis'][:200]}")
                if a.get('llm_recommendation'):
                    system_lines.append(f"  권고: {a['llm_recommendation'][:150]}")
                if a.get('extracted_ips'):
                    system_lines.append(f"  IP: {', '.join(a['extracted_ips'][:5])}")
                if a.get('after_hours_access'):
                    system_lines.append("  ⚠️ 야간/업무외 발생 알람")

        system_msg = "\n".join(system_lines)

        # ── Ollama 메시지 구성 ────────────────────────────────
        ollama_messages = [{"role": "system", "content": system_msg}]
        for msg in messages:
            ollama_messages.append({"role": msg['role'], "content": msg['content']})

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post(
                    f"{self.base_url}/api/chat",
                    json={
                        "model": model or self.model,
                        "messages": ollama_messages,
                        "stream": False,
                        "options": {
                            "temperature": 0.7,
                            "num_ctx": 8192,   # 컨텍스트 확대 (통계 데이터 포함)
                        }
                    }
                )
                
                if resp.status_code == 200:
                    data = resp.json()
                    return data.get('message', {}).get('content', '응답 없음')
                else:
                    return f"LLM 오류: {resp.status_code}"
        except Exception as e:
            return f"LLM 연결 오류: {str(e)}"

    async def generate_report_summary(
        self,
        alerts: List[Dict],
        period: str = "오늘",
        model: str = None
    ) -> str:
        """요약 리포트 생성"""
        
        stats = {
            "total": len(alerts),
            "critical": sum(1 for a in alerts if a.get('severity') == 'critical'),
            "high": sum(1 for a in alerts if a.get('severity') == 'high'),
            "medium": sum(1 for a in alerts if a.get('severity') == 'medium'),
            "low": sum(1 for a in alerts if a.get('severity') in ('low', 'info')),
            "false_positives": sum(1 for a in alerts if a.get('is_false_positive')),
        }
        
        top_ips = {}
        for alert in alerts:
            for ip in (alert.get('extracted_ips') or []):
                top_ips[ip] = top_ips.get(ip, 0) + 1
        
        top_ips_text = ", ".join([f"{ip}({cnt}회)" for ip, cnt in 
                                   sorted(top_ips.items(), key=lambda x: -x[1])[:5]])

        system_prompt = "당신은 SOC 보고서 작성 전문가입니다. 경영진도 이해할 수 있는 명확하고 간결한 보안 리포트를 작성합니다."
        
        user_prompt = f"""{period} 보안 알람 요약 리포트를 작성해주세요.

통계:
- 전체 알람: {stats['total']}건
- Critical: {stats['critical']}건
- High: {stats['high']}건  
- Medium: {stats['medium']}건
- Low/Info: {stats['low']}건
- 오탐: {stats['false_positives']}건
- 주요 위협 IP: {top_ips_text or '없음'}

HTML 형식의 경영진 보고서를 작성하세요. 제목, 핵심 요약, 위협 현황, 주요 발견사항, 권고사항 순서로 작성하세요."""

        return await self._generate(system_prompt, user_prompt, model or self.model)

    async def analyze_correlation(
        self,
        alerts: List[Dict],
        model: str = None
    ) -> Dict[str, Any]:
        """2차 침해·횡전개 상관분석 - 복수 알람 조합 분석"""

        # 알람 요약 구성 (최대 30개)
        lines = []
        for i, a in enumerate(alerts[:30]):
            ips = ", ".join((a.get('extracted_ips') or [])[:4])
            ah = "⏰야간" if a.get('after_hours_access') else ""
            lines.append(
                f"{i+1}. [{(a.get('severity') or '?').upper()}] {a.get('alert_type','') or ''} | "
                f"{(a.get('subject','') or '')[:80]} | IP: {ips} | {(a.get('received_at','') or '')[:16]} {ah}"
            )

        system_prompt = """당신은 침해사고대응팀(CERT) 시니어 분석가입니다.
여러 보안 알람들의 상관관계를 분석하여 다음을 판단합니다:
1. 2차 침해 가능성: 초기 침투 후 내부 확산(횡전개, lateral movement) 징후
2. 공격 캠페인 연관성: 동일 공격자/그룹의 연속 공격 패턴
3. APT(지능형지속위협) 징후: 지속적·은밀한 공격 패턴
4. 내부자 위협: 업무시간 외 내부 IP 이상 접근
5. 복합 공격 시나리오: 스캔→침투→권한상승→데이터유출 등 단계적 공격
반드시 JSON 형식으로만 응답하세요."""

        user_prompt = f"""다음 {len(alerts)}개 보안 알람의 상관관계를 분석하세요:

{chr(10).join(lines)}

JSON 형식으로만 응답하세요:
{{
  "overall_risk": "critical|high|medium|low",
  "lateral_movement_detected": false,
  "lateral_movement_evidence": "횡전개 징후 근거 (없으면 빈 문자열)",
  "attack_campaign": false,
  "campaign_description": "캠페인 패턴 설명 (없으면 빈 문자열)",
  "apt_indicators": false,
  "apt_description": "APT 징후 설명 (없으면 빈 문자열)",
  "insider_threat_risk": false,
  "insider_description": "내부자 위협 근거 (없으면 빈 문자열)",
  "attack_timeline": "공격 단계별 시나리오 (없으면 빈 문자열)",
  "correlated_ips": ["상관관계 있는 주요 IP 목록"],
  "key_findings": ["핵심 발견사항 목록 (최대 5개)"],
  "priority_actions": ["즉각 조치 항목 목록 (최대 5개)"],
  "risk_summary": "전체 위험 상황 요약 (2~3문장)"
}}"""

        return await self._chat(system_prompt, user_prompt, model or self.model, expect_json=True)

    async def learn_from_feedback(
        self,
        alert_data: Dict,
        feedback: str,
        correct_severity: str = None,
        is_false_positive: bool = None,
        model: str = None
    ) -> Dict:
        """사용자 피드백으로 학습 데이터 생성"""
        
        system_prompt = """당신은 보안 AI 트레이너입니다. 
사용자 피드백을 분석하여 향후 유사한 알람 분석에 활용할 수 있는 학습 데이터를 생성합니다."""

        user_prompt = f"""다음 보안 알람에 대한 사용자 피드백을 분석하고 학습 포인트를 추출하세요:

알람 제목: {alert_data.get('subject', '')}
원래 분석 심각도: {alert_data.get('severity', '')}
피드백: {feedback}
{'수정된 심각도: ' + correct_severity if correct_severity else ''}
{'오탐 여부 수정: ' + str(is_false_positive) if is_false_positive is not None else ''}

JSON으로 응답:
{{
  "learning_points": ["학습 포인트 목록"],
  "pattern_rule": "이 케이스에서 배울 수 있는 패턴 규칙",
  "knowledge_entry": "지식베이스에 추가할 내용",
  "category": "false_positive|severity_calibration|new_pattern|alert_pattern"
}}"""

        return await self._chat(system_prompt, user_prompt, model or self.model, expect_json=True)

    async def _chat(self, system: str, user: str, model: str, expect_json: bool = False) -> Dict:
        """내부 채팅 메서드"""
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post(
                    f"{self.base_url}/api/chat",
                    json={
                        "model": model,
                        "messages": [
                            {"role": "system", "content": system},
                            {"role": "user", "content": user}
                        ],
                        "stream": False,
                        "options": {
                            "temperature": 0.1 if expect_json else 0.7,
                            "num_ctx": 2048,
                        }
                    }
                )
                
                if resp.status_code == 200:
                    data = resp.json()
                    content = data.get('message', {}).get('content', '')
                    if not content:
                        # Ollama가 빈 응답을 반환한 경우 (동시 요청 충돌 등) 재시도
                        print(f"⚠️ LLM 빈 응답 수신, 재시도...")
                        await asyncio.sleep(2)
                        resp2 = await client.post(
                            f"{self.base_url}/api/chat",
                            json={
                                "model": model,
                                "messages": [
                                    {"role": "system", "content": system},
                                    {"role": "user", "content": user}
                                ],
                                "stream": False,
                                "options": {
                                    "temperature": 0.1 if expect_json else 0.7,
                                    "num_ctx": 2048,
                                }
                            }
                        )
                        if resp2.status_code == 200:
                            data = resp2.json()
                            content = data.get('message', {}).get('content', '')
                    
                    if expect_json:
                        result = self._parse_json_response(content)
                        if not result.get('summary') and not result.get('error'):
                            print(f"⚠️ LLM JSON 파싱 결과 summary 없음. content len={len(content)}")
                        return result
                    return content
                else:
                    err_text = resp.text[:200] if resp.text else ''
                    print(f"❌ LLM HTTP {resp.status_code}: {err_text}")
                    return {"error": f"LLM Error: {resp.status_code}"}
        except Exception as e:
            print(f"❌ LLM 예외: {e}")
            if expect_json:
                return {"error": str(e), "severity": "unknown"}
            return f"오류: {str(e)}"

    async def _generate(self, system: str, user: str, model: str) -> str:
        """내부 생성 메서드"""
        result = await self._chat(system, user, model, expect_json=False)
        return result if isinstance(result, str) else str(result)

    def _parse_json_response(self, content: str) -> Dict:
        """LLM 응답에서 JSON 파싱"""
        import re

        if not content:
            return {"severity": "unknown", "summary": "분석 결과 없음", "error": "LLM 응답 없음"}

        # 1) ```json ... ``` 또는 ``` ... ``` 블록 (greedy)
        json_match = re.search(r'```(?:json)?\s*(\{.*\})\s*```', content, re.DOTALL)
        if json_match:
            try:
                return json.loads(json_match.group(1))
            except Exception:
                pass

        # 2) 첫 번째 { 부터 마지막 } 까지 직접 파싱
        start = content.find('{')
        end = content.rfind('}') + 1
        if start >= 0 and end > start:
            try:
                return json.loads(content[start:end])
            except Exception:
                pass

        # 3) 파싱 실패시 raw_response + 기본값 반환 (analyzed로 마킹은 되도록)
        return {
            "raw_response": content,
            "severity": "info",
            "severity_score": 0.0,
            "summary": content[:200] if content else "분석 결과 없음",
            "analysis": content[:500] if content else "",
            "alert_type": "",
            "is_false_positive": False,
            "false_positive_reason": "",
            "is_repeated": False,
            "extracted_ips": [],
            "extracted_domains": [],
            "extracted_users": [],
            "recommendation": "",
            "error": "JSON 파싱 실패 - 원문 저장됨",
        }
