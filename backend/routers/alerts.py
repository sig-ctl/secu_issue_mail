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
    after_hours: Optional[bool] = None,
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
    if after_hours is not None:
        conditions.append(SecurityAlert.after_hours_access == after_hours)
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


@router.post("/correlate")
async def correlate_alerts(
    data: dict = None,
    db: AsyncSession = Depends(get_db),
):
    """복수 알람 상관분석 - 2차 침해/횡전개/APT 징후 분석
    
    data:
      alert_ids: List[int]  - 분석할 알람 ID 목록 (최대 30개). 미제공시 최근 analyzed 알람 사용
      days: int             - 최근 N일 분석 (기본 7일)
      model: str            - 사용할 LLM 모델 (선택)
    """
    from datetime import datetime, timedelta
    data = data or {}
    alert_ids = data.get('alert_ids') or []
    days = int(data.get('days', 7))
    model = data.get('model')

    if alert_ids:
        # 지정된 알람 조회
        stmt = select(SecurityAlert).where(
            and_(SecurityAlert.id.in_(alert_ids[:30]))
        ).order_by(SecurityAlert.received_at.asc())
    else:
        # 최근 N일 분석완료 알람 (최대 30개)
        cutoff = datetime.utcnow() - timedelta(days=days)
        stmt = select(SecurityAlert).where(
            and_(
                SecurityAlert.received_at >= cutoff,
                SecurityAlert.status == "analyzed",
            )
        ).order_by(SecurityAlert.received_at.asc()).limit(30)

    result = await db.execute(stmt)
    alerts = result.scalars().all()

    if len(alerts) < 2:
        return {
            "success": False,
            "message": f"상관분석을 위한 알람이 부족합니다. (현재 {len(alerts)}개, 최소 2개 필요)",
            "alert_count": len(alerts),
        }

    # 알람 데이터 직렬화
    alert_dicts = [_alert_to_dict(a) for a in alerts]

    # LLM 상관분석 실행
    correlation = await llm_service.analyze_correlation(alert_dicts, model=model)

    # ─── 통계 계산 (LLM 결과와 함께 반환) ────────────────────────────
    # 공통 IP 추출 (2개 이상 알람에 등장)
    from collections import Counter
    ip_counter: Counter = Counter()
    for a in alerts:
        for ip in (a.extracted_ips or []):
            ip_counter[ip] += 1
    shared_ips = [ip for ip, cnt in ip_counter.most_common(10) if cnt >= 2]

    # 야간 알람 비율
    after_hours_count = sum(1 for a in alerts if a.after_hours_access)
    severity_dist = {}
    for a in alerts:
        sev = a.severity or "unknown"
        severity_dist[sev] = severity_dist.get(sev, 0) + 1

    return {
        "success": True,
        "alert_count": len(alerts),
        "alert_ids": [a.id for a in alerts],
        "period_days": days,
        "statistics": {
            "severity_distribution": severity_dist,
            "after_hours_alerts": after_hours_count,
            "shared_ips": shared_ips,
            "total_unique_ips": len(ip_counter),
        },
        "correlation": correlation,
    }


@router.post("/analyze-all")
async def analyze_all_pending(
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    data: dict = None,
):
    """미분석(new) 알람 전체 일괄 분석"""
    data = data or {}
    model = data.get('model') if data else None

    stmt = select(SecurityAlert.id).where(SecurityAlert.status == "new")
    result = await db.execute(stmt)
    pending_ids = [row[0] for row in result.fetchall()]

    if not pending_ids:
        return {"success": True, "message": "분석할 알람이 없습니다.", "queued": 0}

    background_tasks.add_task(_batch_analyze_all_task, pending_ids, model)
    return {
        "success": True,
        "message": f"{len(pending_ids)}개 알람 분석을 백그라운드에서 시작합니다.",
        "queued": len(pending_ids),
    }


async def _batch_analyze_all_task(alert_ids: list, model: str = None):
    """전체 미분석 알람 순차 분석 태스크"""
    from ..models.database import async_session
    print(f"🔄 일괄 분석 시작: {len(alert_ids)}개")
    success, failed = 0, 0
    for alert_id in alert_ids:
        async with async_session() as db:
            try:
                stmt = select(SecurityAlert).where(SecurityAlert.id == alert_id)
                result = await db.execute(stmt)
                alert = result.scalar_one_or_none()
                if alert and alert.status == "new":
                    await analyzer.analyze_alert(alert, db, model)
                    db.add(alert)
                    await db.commit()
                    success += 1
                    print(f"  ✅ 분석 완료: #{alert_id} [{alert.severity}]")
            except Exception as e:
                failed += 1
                print(f"  ❌ 분석 오류 #{alert_id}: {e}")
    print(f"✅ 일괄 분석 완료: 성공 {success}개 / 실패 {failed}개")


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
            # 커밋 후 실제 저장 여부 확인
            await db.refresh(alert)
            print(f"✅ 재분석 저장 확인 #{alert_id}: severity={alert.severity}, summary_len={len(alert.llm_summary or '')}, analysis_len={len(alert.llm_analysis or '')}")


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
        "after_hours_access": alert.after_hours_access,
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
