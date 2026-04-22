"""
Security Alert Analyzer - 보안 알람 분석 엔진
"""
import json
import re
from typing import List, Dict, Optional, Any
from datetime import datetime, timedelta
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_, or_
from sqlalchemy.orm import selectinload

from ..models.database import SecurityAlert, KnowledgeBase, IPIntelligence
from .llm_service import OllamaLLMService
from .ip_service import IPIntelligenceService


class SecurityAnalyzerService:
    def __init__(self, llm_service: OllamaLLMService = None, ip_service: IPIntelligenceService = None):
        self.llm = llm_service or OllamaLLMService()
        self.ip_service = ip_service or IPIntelligenceService()

    async def analyze_alert(
        self, 
        alert: SecurityAlert,
        db: AsyncSession,
        model: str = None
    ) -> SecurityAlert:
        """단일 보안 알람 분석"""
        
        # 1. IP/도메인 추출
        full_text = f"{alert.subject or ''} {alert.body_text or ''}"
        extracted_ips = self.ip_service.extract_ips_from_text(full_text)
        extracted_domains = self.ip_service.extract_domains_from_text(full_text)
        
        alert.extracted_ips = extracted_ips
        alert.extracted_domains = extracted_domains
        
        # 2. 유사 알람 검색 (반복성 체크)
        similar_alerts = await self._find_similar_alerts(db, alert)
        
        # 3. 컨텍스트 구성
        context = ""
        if similar_alerts:
            context = f"유사한 알람이 이전에 {len(similar_alerts)}번 발생했습니다. "
            context += f"마지막 발생: {similar_alerts[0].received_at}"
        
        # 4. 지식베이스에서 관련 패턴 검색
        kb_context = await self._get_knowledge_context(db, alert.subject or "")
        if kb_context:
            context += f"\n관련 패턴: {kb_context}"
        
        # 5. LLM 분석
        alert.status = "analyzing"
        
        analysis_result = await self.llm.analyze_security_alert(
            email_subject=alert.subject or "",
            email_body=alert.body_text or alert.body_html or "",
            email_sender=alert.sender or "",
            context=context,
            model=model
        )
        
        # 6. 분석 결과 적용
        if analysis_result and not analysis_result.get('error'):
            alert.severity = analysis_result.get('severity', 'medium')
            alert.severity_score = float(analysis_result.get('severity_score', 5.0))
            alert.alert_type = analysis_result.get('alert_type', '')
            alert.llm_summary = analysis_result.get('summary', '')
            alert.llm_analysis = analysis_result.get('analysis', '')
            alert.llm_recommendation = analysis_result.get('recommendation', '')
            alert.is_false_positive = bool(analysis_result.get('is_false_positive', False))
            alert.false_positive_reason = analysis_result.get('false_positive_reason', '')
            alert.is_repeated = bool(analysis_result.get('is_repeated', False)) or len(similar_alerts) > 0
            
            # 추가 추출 데이터
            if analysis_result.get('extracted_ips'):
                existing = alert.extracted_ips or []
                new_ips = analysis_result['extracted_ips']
                alert.extracted_ips = list(set(existing + new_ips))[:20]
            
            if analysis_result.get('extracted_users'):
                alert.extracted_users = analysis_result['extracted_users']
            
            if analysis_result.get('extracted_events'):
                alert.extracted_events = analysis_result['extracted_events']
            
            # 반복 알람 처리
            if similar_alerts:
                alert.repeat_count = len(similar_alerts) + 1
                alert.is_repeated = True
                alert.related_alert_ids = [a.id for a in similar_alerts[:10]]
                
                # 이전 알람들의 repeat_count 업데이트
                for prev_alert in similar_alerts[:3]:
                    prev_alert.repeat_count = (prev_alert.repeat_count or 1) + 1
                    db.add(prev_alert)
        
        alert.llm_analyzed_at = datetime.utcnow()
        alert.status = "analyzed"
        
        # 7. IP 정보 업데이트 (백그라운드로 처리 가능)
        if alert.extracted_ips:
            await self._update_ip_intelligence(db, alert.extracted_ips[:5])
        
        return alert

    async def _find_similar_alerts(
        self, 
        db: AsyncSession,
        alert: SecurityAlert,
        days_back: int = 30
    ) -> List[SecurityAlert]:
        """유사 알람 검색"""
        try:
            cutoff = datetime.utcnow() - timedelta(days=days_back)
            
            # 제목 유사성 기반 검색
            subject_parts = self._extract_key_terms(alert.subject or "")
            
            if not subject_parts:
                return []
            
            stmt = select(SecurityAlert).where(
                and_(
                    SecurityAlert.id != alert.id,
                    SecurityAlert.received_at >= cutoff,
                    SecurityAlert.gmail_id != alert.gmail_id,
                )
            ).order_by(SecurityAlert.received_at.desc()).limit(10)
            
            result = await db.execute(stmt)
            all_recent = result.scalars().all()
            
            # 유사도 필터링
            similar = []
            for prev in all_recent:
                prev_terms = self._extract_key_terms(prev.subject or "")
                if self._calculate_similarity(subject_parts, prev_terms) > 0.5:
                    similar.append(prev)
            
            return similar
        except Exception as e:
            print(f"Similar alert search error: {e}")
            return []

    def _extract_key_terms(self, text: str) -> set:
        """핵심 용어 추출"""
        # 일반적인 불용어 제거
        stopwords = {'the', 'a', 'an', 'is', 'are', 'was', 'were', 'be', 'been',
                     'alert', 'alarm', 'notification', 'warning', 'security'}
        
        words = re.findall(r'\b\w+\b', text.lower())
        return {w for w in words if len(w) > 3 and w not in stopwords}

    def _calculate_similarity(self, terms1: set, terms2: set) -> float:
        """두 용어 집합의 유사도 계산 (Jaccard)"""
        if not terms1 or not terms2:
            return 0.0
        intersection = len(terms1 & terms2)
        union = len(terms1 | terms2)
        return intersection / union if union > 0 else 0.0

    async def _get_knowledge_context(self, db: AsyncSession, subject: str) -> str:
        """지식베이스에서 관련 패턴 검색"""
        try:
            terms = self._extract_key_terms(subject)
            if not terms:
                return ""
            
            stmt = select(KnowledgeBase).order_by(
                KnowledgeBase.relevance_score.desc()
            ).limit(3)
            
            result = await db.execute(stmt)
            kb_entries = result.scalars().all()
            
            relevant = []
            for entry in kb_entries:
                entry_terms = self._extract_key_terms(entry.title + " " + (entry.content or ""))
                if self._calculate_similarity(terms, entry_terms) > 0.3:
                    relevant.append(entry.content[:200])
            
            return "; ".join(relevant)
        except:
            return ""

    async def _update_ip_intelligence(self, db: AsyncSession, ips: List[str]):
        """IP 인텔리전스 데이터베이스 업데이트"""
        for ip in ips:
            try:
                # 기존 IP 확인
                stmt = select(IPIntelligence).where(IPIntelligence.ip_address == ip)
                result = await db.execute(stmt)
                existing = result.scalar_one_or_none()
                
                if existing:
                    existing.last_seen = datetime.utcnow()
                    existing.alert_count = (existing.alert_count or 0) + 1
                    db.add(existing)
                else:
                    # 새 IP 조회
                    ip_data = await self.ip_service.lookup_ip(ip)
                    geo = ip_data.get('geo', {})
                    threat = ip_data.get('threat', {})
                    
                    new_ip = IPIntelligence(
                        ip_address=ip,
                        country=geo.get('country', ''),
                        city=geo.get('city', ''),
                        region=geo.get('region', ''),
                        isp=geo.get('isp', ''),
                        org=geo.get('org', ''),
                        asn=geo.get('asn', ''),
                        latitude=geo.get('latitude', 0),
                        longitude=geo.get('longitude', 0),
                        is_proxy=geo.get('is_proxy', False),
                        is_datacenter=geo.get('is_datacenter', False),
                        abuse_confidence=threat.get('abuse_confidence', 0),
                        is_tor=threat.get('is_tor', False),
                        threat_score=self.ip_service.calculate_threat_score(ip_data),
                        raw_data=ip_data,
                    )
                    db.add(new_ip)
            except Exception as e:
                print(f"IP intelligence update error for {ip}: {e}")

    async def add_to_knowledge_base(
        self,
        db: AsyncSession,
        alert: SecurityAlert,
        category: str,
        title: str,
        content: str,
        tags: List[str] = None
    ) -> KnowledgeBase:
        """지식베이스에 패턴 추가"""
        kb = KnowledgeBase(
            category=category,
            title=title,
            content=content,
            embedding_text=f"{title} {content}",
            source_alert_id=alert.id,
            tags=tags or [],
        )
        db.add(kb)
        await db.commit()
        await db.refresh(kb)
        return kb

    async def get_dashboard_stats(self, db: AsyncSession, days: int = 7) -> Dict[str, Any]:
        """대시보드 통계 조회"""
        cutoff = datetime.utcnow() - timedelta(days=days)
        
        try:
            # 전체 통계
            total_stmt = select(func.count(SecurityAlert.id)).where(
                SecurityAlert.received_at >= cutoff
            )
            total = (await db.execute(total_stmt)).scalar()

            # 심각도별 통계
            sev_stats = {}
            for sev in ['critical', 'high', 'medium', 'low', 'info']:
                stmt = select(func.count(SecurityAlert.id)).where(
                    and_(
                        SecurityAlert.received_at >= cutoff,
                        SecurityAlert.severity == sev
                    )
                )
                sev_stats[sev] = (await db.execute(stmt)).scalar()

            # 오탐 통계
            fp_stmt = select(func.count(SecurityAlert.id)).where(
                and_(
                    SecurityAlert.received_at >= cutoff,
                    SecurityAlert.is_false_positive == True
                )
            )
            false_positives = (await db.execute(fp_stmt)).scalar()

            # 반복 알람
            rep_stmt = select(func.count(SecurityAlert.id)).where(
                and_(
                    SecurityAlert.received_at >= cutoff,
                    SecurityAlert.is_repeated == True
                )
            )
            repeated = (await db.execute(rep_stmt)).scalar()

            # 최근 알람 목록
            recent_stmt = select(SecurityAlert).where(
                SecurityAlert.received_at >= cutoff
            ).order_by(SecurityAlert.received_at.desc()).limit(10)
            recent_result = await db.execute(recent_stmt)
            recent_alerts = recent_result.scalars().all()

            # 상위 IP 목록
            top_ips_stmt = select(IPIntelligence).order_by(
                IPIntelligence.alert_count.desc()
            ).limit(10)
            top_ips_result = await db.execute(top_ips_stmt)
            top_ips = top_ips_result.scalars().all()

            # 알람 유형 통계
            type_stats = {}
            type_stmt = select(SecurityAlert.alert_type, func.count(SecurityAlert.id)).where(
                and_(
                    SecurityAlert.received_at >= cutoff,
                    SecurityAlert.alert_type.isnot(None)
                )
            ).group_by(SecurityAlert.alert_type).order_by(func.count(SecurityAlert.id).desc()).limit(10)
            type_result = await db.execute(type_stmt)
            for row in type_result:
                if row[0]:
                    type_stats[row[0]] = row[1]

            return {
                "period_days": days,
                "total": total,
                "by_severity": sev_stats,
                "false_positives": false_positives,
                "repeated": repeated,
                "by_type": type_stats,
                "recent_alerts": [
                    {
                        "id": a.id,
                        "subject": a.subject,
                        "severity": a.severity,
                        "sender": a.sender,
                        "received_at": a.received_at.isoformat() if a.received_at else None,
                        "is_false_positive": a.is_false_positive,
                        "is_repeated": a.is_repeated,
                        "llm_summary": a.llm_summary,
                        "extracted_ips": a.extracted_ips,
                        "alert_type": a.alert_type,
                    }
                    for a in recent_alerts
                ],
                "top_threat_ips": [
                    {
                        "ip": ip.ip_address,
                        "country": ip.country,
                        "city": ip.city,
                        "isp": ip.isp,
                        "threat_score": ip.threat_score,
                        "alert_count": ip.alert_count,
                        "abuse_confidence": ip.abuse_confidence,
                    }
                    for ip in top_ips
                ],
                "generated_at": datetime.utcnow().isoformat()
            }
        except Exception as e:
            print(f"Dashboard stats error: {e}")
            return {"error": str(e), "total": 0}
