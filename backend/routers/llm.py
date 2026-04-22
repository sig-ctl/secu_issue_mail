"""
LLM API 라우터
"""
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from typing import List, Optional
from datetime import datetime
import json
import uuid

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


@router.post("/chat")
async def chat(
    data: dict,
    db: AsyncSession = Depends(get_db),
):
    """LLM 채팅 (Q&A)"""
    messages = data.get('messages', [])
    session_id = data.get('session_id', str(uuid.uuid4()))
    model = data.get('model', None)
    context_alert_ids = data.get('context_alert_ids', [])
    
    if not messages:
        raise HTTPException(status_code=400, detail="메시지가 필요합니다.")
    
    # 컨텍스트 알람 조회
    context_alerts = []
    if context_alert_ids:
        stmt = select(SecurityAlert).where(
            SecurityAlert.id.in_(context_alert_ids[:10])
        )
        result = await db.execute(stmt)
        alerts = result.scalars().all()
        context_alerts = [
            {
                "id": a.id,
                "subject": a.subject,
                "severity": a.severity,
                "llm_summary": a.llm_summary,
                "llm_analysis": a.llm_analysis,
                "extracted_ips": a.extracted_ips,
                "alert_type": a.alert_type,
            }
            for a in alerts
        ]
    
    # 히스토리에서 이전 메시지 불러오기
    history_stmt = select(ChatHistory).where(
        ChatHistory.session_id == session_id
    ).order_by(ChatHistory.created_at.asc()).limit(10)
    history_result = await db.execute(history_stmt)
    history = history_result.scalars().all()
    
    # 이전 대화 포함
    all_messages = []
    for h in history:
        if h.role in ('user', 'assistant'):
            all_messages.append({"role": h.role, "content": h.content})
    all_messages.extend(messages)
    
    # LLM 응답
    response = await llm_service.chat(
        messages=all_messages,
        context_alerts=context_alerts,
        model=model,
    )
    
    # 히스토리 저장
    for msg in messages:
        chat_h = ChatHistory(
            session_id=session_id,
            role=msg['role'],
            content=msg['content'],
            context_alert_ids=context_alert_ids,
            model_used=model or llm_service.model,
        )
        db.add(chat_h)
    
    # 응답 저장
    assistant_h = ChatHistory(
        session_id=session_id,
        role="assistant",
        content=response,
        context_alert_ids=context_alert_ids,
        model_used=model or llm_service.model,
    )
    db.add(assistant_h)
    await db.commit()
    
    return {
        "response": response,
        "session_id": session_id,
        "model": model or llm_service.model,
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
    from sqlalchemy import func
    
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
