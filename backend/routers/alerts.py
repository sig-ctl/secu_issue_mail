"""
알람 관리 API 라우터
"""
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, or_, desc, func
from typing import List, Optional
from datetime import datetime, timedelta
import json

from ..models.database import SecurityAlert, get_db
from ..services.analyzer_service import SecurityAnalyzerService
from ..services.llm_service import OllamaLLMService
from ..services.ip_service import IPIntelligenceService
from ..services.gmail_service import GmailService

router = APIRouter(prefix="/api/alerts", tags=["alerts"])

analyzer = SecurityAnalyzerService()
llm_service = OllamaLLMService()
ip_service = IPIntelligenceService()


@router.get("/")
async def get_alerts(
    db: AsyncSession = Depends(get_db),
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
    severity: Optional[str] = None,
    status: Optional[str] = None,
    is_false_positive: Optional[bool] = None,
    is_repeated: Optional[bool] = None,
    days: int = Query(30, ge=1, le=365),
    search: Optional[str] = None,
    sort_by: str = "received_at",
):
    """알람 목록 조회"""
    cutoff = datetime.utcnow() - timedelta(days=days)
    
    conditions = [SecurityAlert.received_at >= cutoff]
    
    if severity:
        conditions.append(SecurityAlert.severity == severity)
    if status:
        conditions.append(SecurityAlert.status == status)
    if is_false_positive is not None:
        conditions.append(SecurityAlert.is_false_positive == is_false_positive)
    if is_repeated is not None:
        conditions.append(SecurityAlert.is_repeated == is_repeated)
    if search:
        conditions.append(
            or_(
                SecurityAlert.subject.ilike(f"%{search}%"),
                SecurityAlert.sender.ilike(f"%{search}%"),
                SecurityAlert.llm_summary.ilike(f"%{search}%"),
            )
        )
    
    # 정렬
    order_col = getattr(SecurityAlert, sort_by, SecurityAlert.received_at)
    
    # 전체 카운트
    count_stmt = select(func.count(SecurityAlert.id)).where(and_(*conditions))
    total = (await db.execute(count_stmt)).scalar()
    
    # 페이지네이션
    offset = (page - 1) * limit
    stmt = select(SecurityAlert).where(
        and_(*conditions)
    ).order_by(desc(order_col)).offset(offset).limit(limit)
    
    result = await db.execute(stmt)
    alerts = result.scalars().all()
    
    return {
        "total": total,
        "page": page,
        "limit": limit,
        "pages": (total + limit - 1) // limit,
        "alerts": [_alert_to_dict(a) for a in alerts],
    }


@router.get("/stats")
async def get_stats(
    db: AsyncSession = Depends(get_db),
    days: int = Query(7, ge=1, le=365),
):
    """대시보드 통계"""
    stats = await analyzer.get_dashboard_stats(db, days)
    return stats


@router.get("/{alert_id}")
async def get_alert(alert_id: int, db: AsyncSession = Depends(get_db)):
    """특정 알람 상세 조회"""
    stmt = select(SecurityAlert).where(SecurityAlert.id == alert_id)
    result = await db.execute(stmt)
    alert = result.scalar_one_or_none()
    
    if not alert:
        raise HTTPException(status_code=404, detail="알람을 찾을 수 없습니다.")
    
    alert_dict = _alert_to_dict(alert)
    
    # 관련 알람
    if alert.related_alert_ids:
        related_stmt = select(SecurityAlert).where(
            SecurityAlert.id.in_(alert.related_alert_ids[:5])
        )
        related_result = await db.execute(related_stmt)
        related = related_result.scalars().all()
        alert_dict['related_alerts'] = [_alert_to_dict(a) for a in related]
    
    return alert_dict


@router.post("/{alert_id}/reanalyze")
async def reanalyze_alert(
    alert_id: int,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    model: Optional[str] = None,
):
    """알람 재분석"""
    stmt = select(SecurityAlert).where(SecurityAlert.id == alert_id)
    result = await db.execute(stmt)
    alert = result.scalar_one_or_none()
    
    if not alert:
        raise HTTPException(status_code=404, detail="알람을 찾을 수 없습니다.")
    
    background_tasks.add_task(_analyze_alert_task, alert_id, model)
    
    return {"success": True, "message": "재분석이 시작되었습니다.", "alert_id": alert_id}


async def _analyze_alert_task(alert_id: int, model: str = None):
    """백그라운드 분석 태스크"""
    from ..models.database import async_session
    async with async_session() as db:
        stmt = select(SecurityAlert).where(SecurityAlert.id == alert_id)
        result = await db.execute(stmt)
        alert = result.scalar_one_or_none()
        if alert:
            await analyzer.analyze_alert(alert, db, model)
            db.add(alert)
            await db.commit()


@router.patch("/{alert_id}/feedback")
async def submit_feedback(
    alert_id: int,
    feedback: dict,
    db: AsyncSession = Depends(get_db),
):
    """사용자 피드백 제출 (학습 데이터)"""
    stmt = select(SecurityAlert).where(SecurityAlert.id == alert_id)
    result = await db.execute(stmt)
    alert = result.scalar_one_or_none()
    
    if not alert:
        raise HTTPException(status_code=404, detail="알람을 찾을 수 없습니다.")
    
    # 피드백 적용
    if 'severity' in feedback:
        alert.severity = feedback['severity']
    if 'is_false_positive' in feedback:
        alert.is_false_positive = feedback['is_false_positive']
        if feedback['is_false_positive'] and feedback.get('false_positive_reason'):
            alert.false_positive_reason = feedback['false_positive_reason']
    if 'status' in feedback:
        alert.status = feedback['status']
    
    # LLM으로 학습 데이터 생성
    if feedback.get('feedback_text'):
        learn_result = await llm_service.learn_from_feedback(
            alert_data=_alert_to_dict(alert),
            feedback=feedback['feedback_text'],
            correct_severity=feedback.get('severity'),
            is_false_positive=feedback.get('is_false_positive'),
        )
        
        # 지식베이스에 추가
        if learn_result and not learn_result.get('error'):
            await analyzer.add_to_knowledge_base(
                db=db,
                alert=alert,
                category=learn_result.get('category', 'alert_pattern'),
                title=f"[피드백] {alert.subject[:100]}",
                content=learn_result.get('knowledge_entry', ''),
                tags=['feedback', alert.severity or 'unknown'],
            )
    
    alert.updated_at = datetime.utcnow()
    db.add(alert)
    await db.commit()
    
    return {"success": True, "message": "피드백이 저장되었습니다."}


@router.delete("/{alert_id}")
async def delete_alert(alert_id: int, db: AsyncSession = Depends(get_db)):
    """알람 삭제"""
    stmt = select(SecurityAlert).where(SecurityAlert.id == alert_id)
    result = await db.execute(stmt)
    alert = result.scalar_one_or_none()
    
    if not alert:
        raise HTTPException(status_code=404, detail="알람을 찾을 수 없습니다.")
    
    await db.delete(alert)
    await db.commit()
    
    return {"success": True, "message": "삭제되었습니다."}


def _alert_to_dict(alert: SecurityAlert) -> dict:
    """알람 모델을 딕셔너리로 변환"""
    return {
        "id": alert.id,
        "gmail_id": alert.gmail_id,
        "subject": alert.subject,
        "sender": alert.sender,
        "recipient": alert.recipient,
        "received_at": alert.received_at.isoformat() if alert.received_at else None,
        "severity": alert.severity,
        "severity_score": alert.severity_score,
        "is_false_positive": alert.is_false_positive,
        "false_positive_reason": alert.false_positive_reason,
        "alert_type": alert.alert_type,
        "repeat_count": alert.repeat_count,
        "is_repeated": alert.is_repeated,
        "related_alert_ids": alert.related_alert_ids,
        "extracted_ips": alert.extracted_ips,
        "extracted_domains": alert.extracted_domains,
        "extracted_users": alert.extracted_users,
        "extracted_events": alert.extracted_events,
        "llm_summary": alert.llm_summary,
        "llm_analysis": alert.llm_analysis,
        "llm_recommendation": alert.llm_recommendation,
        "llm_analyzed_at": alert.llm_analyzed_at.isoformat() if alert.llm_analyzed_at else None,
        "status": alert.status,
        "labels": alert.labels,
        "body_text": alert.body_text,
        "created_at": alert.created_at.isoformat() if alert.created_at else None,
        "updated_at": alert.updated_at.isoformat() if alert.updated_at else None,
    }
