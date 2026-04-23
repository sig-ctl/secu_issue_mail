"""
LLM API 라우터
"""
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc, func, and_
from typing import List, Optional
from datetime import datetime, timedelta
import json
import uuid
import os

from ..models.database import SecurityAlert, ChatHistory, KnowledgeBase, get_db
from ..services.llm_service import OllamaLLMService

router = APIRouter(prefix="/api/llm", tags=["llm"])
llm_service = OllamaLLMService()


@router.get("/status")
async def get_llm_status():
    """LLM 연결 상태"""
    status = await llm_service.check_connection()
    return status


@router.get("/models")
async def list_models():
    """사용 가능한 모델 목록"""
    models = await llm_service.list_models()
    return {"models": models}


@router.post("/pull")
async def pull_model(data: dict):
    """모델 다운로드"""
    model_name = data.get('model', 'llama3.2:3b')
    
    async def generate():
        async for chunk in llm_service.pull_model(model_name):
            yield f"data: {chunk}\n\n"
        yield "data: {\"status\": \"complete\"}\n\n"
    
    return StreamingResponse(generate(), media_type="text/event-stream")


async def _build_db_context(db: AsyncSession, days: int = 7) -> dict:
    """DB에서 최근 알람 통계 및 목록을 가져와 채팅 컨텍스트 구성"""
    try:
        cutoff = datetime.utcnow() - timedelta(days=days)

        # 전체 통계
        total = (await db.execute(
            select(func.count(SecurityAlert.id)).where(SecurityAlert.received_at >= cutoff)
        )).scalar() or 0

        # 심각도별 통계
        sev_stats = {}
        for sev in ['critical', 'high', 'medium', 'low', 'info']:
            cnt = (await db.execute(
                select(func.count(SecurityAlert.id)).where(
                    and_(SecurityAlert.received_at >= cutoff, SecurityAlert.severity == sev)
                )
            )).scalar() or 0
            sev_stats[sev] = cnt

        # 오탐 통계
        fp_count = (await db.execute(
            select(func.count(SecurityAlert.id)).where(
                and_(SecurityAlert.received_at >= cutoff, SecurityAlert.is_false_positive == True)
            )
        )).scalar() or 0

        # 야간 알람
        after_hours_count = (await db.execute(
            select(func.count(SecurityAlert.id)).where(
                and_(SecurityAlert.received_at >= cutoff, SecurityAlert.after_hours_access == True)
            )
        )).scalar() or 0

        # 반복 알람
        repeated_count = (await db.execute(
            select(func.count(SecurityAlert.id)).where(
                and_(SecurityAlert.received_at >= cutoff, SecurityAlert.is_repeated == True)
            )
        )).scalar() or 0

        # 최근 알람 상세 (분석 완료 우선, 최대 20개)
        recent_stmt = select(SecurityAlert).where(
            SecurityAlert.received_at >= cutoff
        ).order_by(
            SecurityAlert.severity.asc(),   # critical 먼저
            SecurityAlert.received_at.desc()
        ).limit(20)
        recent_result = await db.execute(recent_stmt)
        recent_alerts = recent_result.scalars().all()

        # 알람 목록 텍스트 구성
        alert_lines = []
        for a in recent_alerts:
            tz_name = os.environ.get('APP_TIMEZONE', 'Asia/Seoul')
            try:
                from zoneinfo import ZoneInfo
                local_dt = a.received_at.replace(tzinfo=__import__('datetime').timezone.utc).astimezone(ZoneInfo(tz_name)) if a.received_at else None
                dt_str = local_dt.strftime('%m/%d %H:%M') if local_dt else '-'
            except Exception:
                dt_str = str(a.received_at)[:16] if a.received_at else '-'

            ips = ", ".join((a.extracted_ips or [])[:3])
            flags = []
            if a.is_false_positive: flags.append("오탐")
            if a.is_repeated:       flags.append(f"반복{a.repeat_count or 1}회")
            if a.after_hours_access: flags.append("야간")
            flag_str = f" [{','.join(flags)}]" if flags else ""

            alert_lines.append(
                f"  - ID:{a.id} [{(a.severity or '?').upper()}] {dt_str}"
                f" | {(a.alert_type or '알람')} | {(a.subject or '')[:60]}"
                + (f" | IP:{ips}" if ips else "")
                + flag_str
                + (f"\n    요약: {(a.llm_summary or '미분석')[:100]}" if a.llm_summary else "")
            )

        # 상위 위협 IP (반복 탐지)
        from ..models.database import IPIntelligence
        top_ip_result = await db.execute(
            select(IPIntelligence).order_by(IPIntelligence.alert_count.desc()).limit(5)
        )
        top_ips = top_ip_result.scalars().all()
        ip_lines = [
            f"  - {ip.ip_address} ({ip.country or '?'}) 위협점수:{ip.threat_score or 0} 탐지:{ip.alert_count or 0}회"
            for ip in top_ips
        ]

        return {
            "total": total,
            "sev_stats": sev_stats,
            "fp_count": fp_count,
            "after_hours_count": after_hours_count,
            "repeated_count": repeated_count,
            "alert_lines": alert_lines,
            "ip_lines": ip_lines,
            "days": days,
        }
    except Exception as e:
        print(f"⚠️ DB 컨텍스트 빌드 오류: {e}")
        return {"total": 0, "sev_stats": {}, "alert_lines": [], "ip_lines": [], "days": days}


@router.get("/db-context")
async def get_db_context(days: int = 7, db: AsyncSession = Depends(get_db)):
    """채팅에 사용되는 DB 컨텍스트 미리보기 (디버깅용)"""
    ctx = await _build_db_context(db, days)
    return ctx


@router.post("/chat")
async def chat(
    data: dict,
    db: AsyncSession = Depends(get_db),
):
    """LLM 채팅 (Q&A) - DB 알람 데이터 자동 컨텍스트 주입"""
    messages = data.get('messages', [])
    session_id = data.get('session_id', str(uuid.uuid4()))
    model = data.get('model', None)
    context_alert_ids = data.get('context_alert_ids', [])
    days = int(data.get('context_days', 7))

    if not messages:
        raise HTTPException(status_code=400, detail="메시지가 필요합니다.")

    # 1) 특정 알람 컨텍스트 (alert_ids가 있을 때)
    pinned_alerts = []
    if context_alert_ids:
        stmt = select(SecurityAlert).where(
            SecurityAlert.id.in_(context_alert_ids[:10])
        )
        result = await db.execute(stmt)
        alerts = result.scalars().all()
        pinned_alerts = [
            {
                "id": a.id,
                "subject": a.subject,
                "severity": a.severity,
                "received_at": str(a.received_at)[:16] if a.received_at else '',
                "llm_summary": a.llm_summary,
                "llm_analysis": a.llm_analysis,
                "llm_recommendation": a.llm_recommendation,
                "extracted_ips": a.extracted_ips,
                "extracted_domains": a.extracted_domains,
                "alert_type": a.alert_type,
                "is_false_positive": a.is_false_positive,
                "after_hours_access": a.after_hours_access,
                "repeat_count": a.repeat_count,
            }
            for a in alerts
        ]

    # 2) DB 전체 통계 자동 주입 (매 채팅마다 최신 DB 상태 반영)
    db_ctx = await _build_db_context(db, days)

    # 3) 히스토리에서 이전 메시지 불러오기 (최근 10턴)
    history_stmt = select(ChatHistory).where(
        ChatHistory.session_id == session_id
    ).order_by(ChatHistory.created_at.asc()).limit(20)
    history_result = await db.execute(history_stmt)
    history = history_result.scalars().all()

    all_messages = []
    for h in history:
        if h.role in ('user', 'assistant'):
            all_messages.append({"role": h.role, "content": h.content})
    all_messages.extend(messages)

    # 4) LLM 응답 (DB 컨텍스트 포함)
    response = await llm_service.chat(
        messages=all_messages,
        pinned_alerts=pinned_alerts,
        db_context=db_ctx,
        model=model,
    )

    # 5) 히스토리 저장
    for msg in messages:
        db.add(ChatHistory(
            session_id=session_id,
            role=msg['role'],
            content=msg['content'],
            context_alert_ids=context_alert_ids,
            model_used=model or llm_service.model,
        ))

    db.add(ChatHistory(
        session_id=session_id,
        role="assistant",
        content=response,
        context_alert_ids=context_alert_ids,
        model_used=model or llm_service.model,
    ))
    await db.commit()

    return {
        "response": response,
        "session_id": session_id,
        "model": model or llm_service.model,
        "context_used": {
            "total_alerts": db_ctx.get("total", 0),
            "days": days,
            "pinned_count": len(pinned_alerts),
        }
    }


@router.get("/chat/history/{session_id}")
async def get_chat_history(session_id: str, db: AsyncSession = Depends(get_db)):
    """채팅 히스토리 조회"""
    stmt = select(ChatHistory).where(
        ChatHistory.session_id == session_id
    ).order_by(ChatHistory.created_at.asc())
    result = await db.execute(stmt)
    history = result.scalars().all()
    
    return {
        "session_id": session_id,
        "messages": [
            {
                "id": h.id,
                "role": h.role,
                "content": h.content,
                "created_at": h.created_at.isoformat() if h.created_at else None,
            }
            for h in history
        ]
    }


@router.get("/sessions")
async def get_sessions(db: AsyncSession = Depends(get_db)):
    """채팅 세션 목록"""
    stmt = select(
        ChatHistory.session_id,
        func.count(ChatHistory.id).label('message_count'),
        func.max(ChatHistory.created_at).label('last_message'),
        func.min(ChatHistory.content).label('first_message'),
    ).group_by(ChatHistory.session_id).order_by(
        func.max(ChatHistory.created_at).desc()
    ).limit(20)
    
    result = await db.execute(stmt)
    sessions = []
    for row in result:
        sessions.append({
            "session_id": row[0],
            "message_count": row[1],
            "last_message": row[2].isoformat() if row[2] else None,
            "preview": (row[3] or '')[:100],
        })
    
    return {"sessions": sessions}


@router.post("/knowledge")
async def add_knowledge(data: dict, db: AsyncSession = Depends(get_db)):
    """지식베이스에 수동 추가"""
    kb = KnowledgeBase(
        category=data.get('category', 'manual'),
        title=data.get('title', ''),
        content=data.get('content', ''),
        embedding_text=f"{data.get('title', '')} {data.get('content', '')}",
        tags=data.get('tags', []),
    )
    db.add(kb)
    await db.commit()
    await db.refresh(kb)
    
    return {"success": True, "id": kb.id, "message": "지식베이스에 추가되었습니다."}


@router.get("/knowledge")
async def list_knowledge(
    db: AsyncSession = Depends(get_db),
    category: Optional[str] = None,
    limit: int = 50,
):
    """지식베이스 목록"""
    conditions = []
    if category:
        conditions.append(KnowledgeBase.category == category)
    
    from sqlalchemy import and_
    stmt = select(KnowledgeBase)
    if conditions:
        stmt = stmt.where(and_(*conditions))
    stmt = stmt.order_by(desc(KnowledgeBase.created_at)).limit(limit)
    
    result = await db.execute(stmt)
    items = result.scalars().all()
    
    return {
        "items": [
            {
                "id": kb.id,
                "category": kb.category,
                "title": kb.title,
                "content": kb.content[:200],
                "tags": kb.tags,
                "use_count": kb.use_count,
                "created_at": kb.created_at.isoformat() if kb.created_at else None,
            }
            for kb in items
        ]
    }


@router.post("/analyze-batch")
async def analyze_batch(data: dict, db: AsyncSession = Depends(get_db)):
    """선택된 알람들 배치 분석"""
    alert_ids = data.get('alert_ids', [])
    model = data.get('model', None)
    
    if not alert_ids:
        raise HTTPException(status_code=400, detail="alert_ids가 필요합니다.")
    
    stmt = select(SecurityAlert).where(
        SecurityAlert.id.in_(alert_ids[:20])
    )
    result = await db.execute(stmt)
    alerts = result.scalars().all()
    
    alerts_data = [
        {
            "subject": a.subject,
            "severity": a.severity,
            "extracted_ips": a.extracted_ips,
            "alert_type": a.alert_type,
            "llm_summary": a.llm_summary,
        }
        for a in alerts
    ]
    
    analysis = await llm_service.analyze_batch_alerts(alerts_data, model)
    
    return {
        "success": True,
        "alert_count": len(alerts),
        "analysis": analysis,
    }
