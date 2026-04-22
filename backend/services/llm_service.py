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
        model: str = None
    ) -> Dict[str, Any]:
        """보안 알람 메일 분석"""
        
        system_prompt = """당신은 보안 전문가 AI입니다. 보안 알람 이메일을 분석하여 다음을 평가합니다:
1. 심각도 (critical/high/medium/low/info)
2. 알람 유형 및 설명
3. 오탐(False Positive) 여부와 이유
4. 반복성 평가
5. 탐지된 IP, 도메인, 사용자 등 핵심 지표
6. 대응 권고사항

항상 JSON 형식으로 응답하세요."""

        user_prompt = f"""다음 보안 알람 이메일을 분석해주세요:

제목: {email_subject}
발신자: {email_sender}
{f'추가 컨텍스트: {context}' if context else ''}

이메일 내용:
{email_body[:3000]}

다음 JSON 형식으로 분석 결과를 제공하세요:
{{
  "severity": "critical|high|medium|low|info",
  "severity_score": 0.0-10.0,
  "alert_type": "알람 유형",
  "summary": "한 문장 요약",
  "analysis": "상세 분석 (3-5문장)",
  "is_false_positive": true/false,
  "false_positive_reason": "오탐 이유 (오탐인 경우)",
  "is_repeated": true/false,
  "repeat_indicators": ["반복성 지표"],
  "extracted_ips": ["IP 목록"],
  "extracted_domains": ["도메인 목록"],
  "extracted_users": ["사용자 목록"],
  "extracted_events": ["이벤트 목록"],
  "recommendation": "대응 권고사항",
  "tags": ["관련 태그"]
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
        context_alerts: List[Dict] = None,
        model: str = None
    ) -> str:
        """일반 채팅 - 보안 지식 질의응답"""
        
        system_msg = """당신은 보안 전문가 AI 어시스턴트입니다. 
보안 알람 이메일 데이터를 학습하여 보안 위협 분석, 대응 방안, 트렌드 파악 등을 도와드립니다.
한국어로 응답하세요."""

        if context_alerts:
            context_text = "\n현재 분석된 보안 알람 컨텍스트:\n"
            for alert in context_alerts[:5]:
                context_text += f"- [{alert.get('severity','?')}] {alert.get('subject','')}: {alert.get('llm_summary','')}\n"
            system_msg += context_text

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
                            "num_ctx": 4096,
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
                            "num_ctx": 4096,
                        }
                    }
                )
                
                if resp.status_code == 200:
                    data = resp.json()
                    content = data.get('message', {}).get('content', '')
                    
                    if expect_json:
                        return self._parse_json_response(content)
                    return content
                else:
                    return {"error": f"LLM Error: {resp.status_code}"}
        except Exception as e:
            if expect_json:
                return {"error": str(e), "severity": "unknown"}
            return f"오류: {str(e)}"

    async def _generate(self, system: str, user: str, model: str) -> str:
        """내부 생성 메서드"""
        result = await self._chat(system, user, model, expect_json=False)
        return result if isinstance(result, str) else str(result)

    def _parse_json_response(self, content: str) -> Dict:
        """LLM 응답에서 JSON 파싱"""
        # JSON 블록 추출 시도
        import re
        
        # ```json ... ``` 형식
        json_match = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', content, re.DOTALL)
        if json_match:
            try:
                return json.loads(json_match.group(1))
            except:
                pass
        
        # 직접 JSON 파싱
        try:
            # 첫 번째 { 부터 마지막 } 까지
            start = content.find('{')
            end = content.rfind('}') + 1
            if start >= 0 and end > start:
                return json.loads(content[start:end])
        except:
            pass
        
        # 파싱 실패시 원문 반환
        return {
            "raw_response": content,
            "severity": "unknown",
            "summary": content[:500] if content else "분석 결과 없음",
            "error": "JSON 파싱 실패"
        }
