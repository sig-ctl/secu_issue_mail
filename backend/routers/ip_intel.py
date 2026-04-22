"""
IP 인텔리전스 API 라우터
"""
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc, func
from typing import List, Optional

from ..models.database import IPIntelligence, SecurityAlert, get_db
from ..services.ip_service import IPIntelligenceService

router = APIRouter(prefix="/api/ip", tags=["ip"])
ip_service = IPIntelligenceService()


@router.get("/lookup/{ip_address}")
async def lookup_ip(ip_address: str, db: AsyncSession = Depends(get_db)):
    """IP 상세 정보 조회"""
    # 유효한 IP 형식 체크
    import re
    if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip_address):
        raise HTTPException(status_code=400, detail="유효하지 않은 IP 주소입니다.")
    
    # DB 캐시 확인
    stmt = select(IPIntelligence).where(IPIntelligence.ip_address == ip_address)
    result = await db.execute(stmt)
    cached = result.scalar_one_or_none()
    
    # 실시간 조회
    live_data = await ip_service.lookup_ip(ip_address)
    
    # 이 IP와 관련된 알람 조회
    related_alerts = []
    # JSON 배열 내 IP 검색 (SQLite 방식)
    all_alerts_stmt = select(SecurityAlert).order_by(
        SecurityAlert.received_at.desc()
    ).limit(200)
    all_result = await db.execute(all_alerts_stmt)
    all_alerts = all_result.scalars().all()
    
    for alert in all_alerts:
        if alert.extracted_ips and ip_address in alert.extracted_ips:
            related_alerts.append({
                "id": alert.id,
                "subject": alert.subject,
                "severity": alert.severity,
                "received_at": alert.received_at.isoformat() if alert.received_at else None,
                "llm_summary": alert.llm_summary,
            })
    
    # DB 업데이트
    if not cached:
        geo = live_data.get('geo', {})
        threat = live_data.get('threat', {})
        
        new_ip = IPIntelligence(
            ip_address=ip_address,
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
            threat_score=ip_service.calculate_threat_score(live_data),
            raw_data=live_data,
            alert_count=len(related_alerts),
        )
        db.add(new_ip)
        await db.commit()
        await db.refresh(new_ip)
        cached = new_ip
    else:
        from datetime import datetime
        cached.last_seen = datetime.utcnow()
        cached.alert_count = len(related_alerts)
        cached.raw_data = live_data
        db.add(cached)
        await db.commit()
    
    return {
        "ip": ip_address,
        "geo": live_data.get('geo', {}),
        "threat": live_data.get('threat', {}),
        "reputation": live_data.get('reputation', {}),
        "links": live_data.get('links', {}),
        "threat_score": ip_service.calculate_threat_score(live_data),
        "related_alerts": related_alerts[:10],
        "related_alert_count": len(related_alerts),
        "db_info": {
            "first_seen": cached.first_seen.isoformat() if cached.first_seen else None,
            "last_seen": cached.last_seen.isoformat() if cached.last_seen else None,
            "alert_count": cached.alert_count,
        } if cached else None,
    }


@router.get("/threats")
async def get_threat_ips(
    db: AsyncSession = Depends(get_db),
    limit: int = Query(50, ge=1, le=200),
    min_threat_score: int = Query(0, ge=0, le=100),
):
    """위협 IP 목록"""
    stmt = select(IPIntelligence).where(
        IPIntelligence.threat_score >= min_threat_score
    ).order_by(
        desc(IPIntelligence.threat_score),
        desc(IPIntelligence.alert_count)
    ).limit(limit)
    
    result = await db.execute(stmt)
    ips = result.scalars().all()
    
    return {
        "ips": [
            {
                "ip": ip.ip_address,
                "country": ip.country,
                "city": ip.city,
                "isp": ip.isp,
                "org": ip.org,
                "threat_score": ip.threat_score,
                "abuse_confidence": ip.abuse_confidence,
                "is_tor": ip.is_tor,
                "is_proxy": ip.is_proxy,
                "is_datacenter": ip.is_datacenter,
                "alert_count": ip.alert_count,
                "first_seen": ip.first_seen.isoformat() if ip.first_seen else None,
                "last_seen": ip.last_seen.isoformat() if ip.last_seen else None,
            }
            for ip in ips
        ],
        "total": len(ips),
    }


@router.post("/bulk-lookup")
async def bulk_lookup(data: dict, db: AsyncSession = Depends(get_db)):
    """여러 IP 일괄 조회"""
    ips = data.get('ips', [])
    if not ips or len(ips) > 20:
        raise HTTPException(
            status_code=400,
            detail="IP 목록이 필요합니다. (최대 20개)"
        )
    
    results = {}
    for ip in ips[:20]:
        try:
            result = await ip_service.lookup_ip(ip)
            result['threat_score'] = ip_service.calculate_threat_score(result)
            results[ip] = result
        except Exception as e:
            results[ip] = {"error": str(e)}
    
    return {"results": results}


@router.delete("/{ip_address}")
async def delete_ip_intel(ip_address: str, db: AsyncSession = Depends(get_db)):
    """IP 인텔리전스 데이터 삭제"""
    stmt = select(IPIntelligence).where(IPIntelligence.ip_address == ip_address)
    result = await db.execute(stmt)
    ip = result.scalar_one_or_none()
    
    if not ip:
        raise HTTPException(status_code=404, detail="IP 정보를 찾을 수 없습니다.")
    
    await db.delete(ip)
    await db.commit()
    
    return {"success": True, "message": f"{ip_address} 정보가 삭제되었습니다."}
