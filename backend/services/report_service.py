"""
Report Service - 보안 요약 대시보드 메일 생성 및 발송
"""
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Any
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_

from ..models.database import SecurityAlert, AlertReport
from .gmail_service import GmailService
from .llm_service import OllamaLLMService


class ReportService:
    def __init__(
        self, 
        gmail_service: GmailService = None,
        llm_service: OllamaLLMService = None
    ):
        self.gmail = gmail_service or GmailService()
        self.llm = llm_service or OllamaLLMService()

    async def generate_and_send_report(
        self,
        db: AsyncSession,
        recipients: List[str],
        report_type: str = "manual",
        days: int = 1,
        send_via: str = "gmail",
        smtp_config: Dict = None,
        sender_email: str = None,
    ) -> Dict:
        """보안 요약 리포트 생성 및 발송"""
        
        period_end = datetime.utcnow()
        period_start = period_end - timedelta(days=days)
        
        # 알람 데이터 수집
        stmt = select(SecurityAlert).where(
            and_(
                SecurityAlert.received_at >= period_start,
                SecurityAlert.received_at <= period_end,
            )
        ).order_by(SecurityAlert.received_at.desc())
        
        result = await db.execute(stmt)
        alerts = result.scalars().all()
        
        # 통계 계산
        stats = self._calculate_stats(alerts)
        
        # HTML 리포트 생성
        html_content = self._generate_html_report(alerts, stats, period_start, period_end, report_type)
        
        # 제목
        date_str = period_end.strftime("%Y-%m-%d")
        subject = f"🔐 보안 알람 요약 리포트 [{date_str}] - {stats['risk_level']} 위험"
        
        # 리포트 저장
        report = AlertReport(
            report_type=report_type,
            period_start=period_start,
            period_end=period_end,
            recipients=recipients,
            subject=subject,
            html_content=html_content,
            total_alerts=stats['total'],
            critical_count=stats['by_severity'].get('critical', 0),
            high_count=stats['by_severity'].get('high', 0),
            medium_count=stats['by_severity'].get('medium', 0),
            low_count=stats['by_severity'].get('low', 0) + stats['by_severity'].get('info', 0),
            false_positive_count=stats['false_positives'],
            status="sending"
        )
        db.add(report)
        await db.commit()
        
        # 메일 발송
        send_result = None
        if send_via == "smtp" and smtp_config:
            send_result = self.gmail.send_email_smtp(
                to=recipients,
                subject=subject,
                html_content=html_content,
                smtp_host=smtp_config.get('host', 'smtp.gmail.com'),
                smtp_port=smtp_config.get('port', 587),
                smtp_user=smtp_config.get('user', ''),
                smtp_password=smtp_config.get('password', ''),
                use_tls=smtp_config.get('use_tls', True),
            )
        else:
            try:
                send_result = self.gmail.send_email(
                    to=recipients,
                    subject=subject,
                    html_content=html_content,
                    sender=sender_email,
                )
            except Exception as e:
                send_result = {"success": False, "error": str(e)}
        
        # 상태 업데이트
        report.sent_at = datetime.utcnow()
        report.status = "sent" if (send_result and send_result.get('success')) else "failed"
        await db.commit()
        
        return {
            "success": send_result.get('success', False) if send_result else False,
            "report_id": report.id,
            "stats": stats,
            "send_result": send_result,
            "html_preview": html_content[:500] + "..." if html_content else "",
        }

    def _calculate_stats(self, alerts: List[SecurityAlert]) -> Dict:
        """알람 통계 계산"""
        by_severity = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        
        for alert in alerts:
            sev = alert.severity or 'info'
            if sev in by_severity:
                by_severity[sev] += 1
            else:
                by_severity['info'] += 1
        
        false_positives = sum(1 for a in alerts if a.is_false_positive)
        repeated = sum(1 for a in alerts if a.is_repeated)
        
        # 전체 위험도 결정
        if by_severity['critical'] > 0:
            risk_level = "CRITICAL"
        elif by_severity['high'] > 3:
            risk_level = "HIGH"
        elif by_severity['high'] > 0 or by_severity['medium'] > 5:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"
        
        # 상위 IP 수집
        ip_counts = {}
        for alert in alerts:
            for ip in (alert.extracted_ips or []):
                ip_counts[ip] = ip_counts.get(ip, 0) + 1
        
        top_ips = sorted(ip_counts.items(), key=lambda x: -x[1])[:5]
        
        # 알람 유형 수집
        type_counts = {}
        for alert in alerts:
            if alert.alert_type:
                type_counts[alert.alert_type] = type_counts.get(alert.alert_type, 0) + 1
        
        return {
            "total": len(alerts),
            "by_severity": by_severity,
            "false_positives": false_positives,
            "repeated": repeated,
            "risk_level": risk_level,
            "top_ips": top_ips,
            "alert_types": sorted(type_counts.items(), key=lambda x: -x[1])[:5],
        }

    def _generate_html_report(
        self,
        alerts: List[SecurityAlert],
        stats: Dict,
        period_start: datetime,
        period_end: datetime,
        report_type: str
    ) -> str:
        """HTML 대시보드 리포트 생성"""
        
        risk_color = {
            "CRITICAL": "#dc3545",
            "HIGH": "#fd7e14",
            "MEDIUM": "#ffc107",
            "LOW": "#28a745",
        }.get(stats['risk_level'], "#6c757d")
        
        # 최근 알람 목록 (최대 20개)
        alert_rows = ""
        for alert in alerts[:20]:
            sev = alert.severity or 'info'
            sev_badge = {
                'critical': '<span style="background:#dc3545;color:white;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:bold;">CRITICAL</span>',
                'high': '<span style="background:#fd7e14;color:white;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:bold;">HIGH</span>',
                'medium': '<span style="background:#ffc107;color:black;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:bold;">MEDIUM</span>',
                'low': '<span style="background:#28a745;color:white;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:bold;">LOW</span>',
                'info': '<span style="background:#17a2b8;color:white;padding:2px 8px;border-radius:4px;font-size:11px;">INFO</span>',
            }.get(sev, f'<span style="background:#6c757d;color:white;padding:2px 8px;border-radius:4px;font-size:11px;">{sev.upper()}</span>')
            
            received_str = alert.received_at.strftime("%Y-%m-%d %H:%M") if alert.received_at else "-"
            fp_badge = '<span style="color:#6c757d;font-size:11px;">오탐</span>' if alert.is_false_positive else ''
            rep_badge = '<span style="color:#17a2b8;font-size:11px;">반복</span>' if alert.is_repeated else ''
            ips_str = ', '.join((alert.extracted_ips or [])[:3])
            
            alert_rows += f"""
            <tr style="border-bottom:1px solid #eee;">
                <td style="padding:8px;font-size:12px;">{received_str}</td>
                <td style="padding:8px;">{sev_badge}</td>
                <td style="padding:8px;font-size:13px;">{(alert.subject or '')[:80]} {fp_badge} {rep_badge}</td>
                <td style="padding:8px;font-size:11px;color:#666;">{ips_str}</td>
                <td style="padding:8px;font-size:12px;color:#555;">{(alert.llm_summary or '')[:100]}</td>
            </tr>"""
        
        # 상위 IP 목록
        ip_rows = ""
        for ip, count in stats['top_ips']:
            ip_rows += f"""
            <tr style="border-bottom:1px solid #eee;">
                <td style="padding:6px;font-family:monospace;font-size:13px;">{ip}</td>
                <td style="padding:6px;text-align:center;"><strong>{count}</strong></td>
            </tr>"""
        
        # 알람 유형 목록
        type_rows = ""
        for alert_type, count in stats['alert_types']:
            type_rows += f"""
            <tr style="border-bottom:1px solid #eee;">
                <td style="padding:6px;font-size:13px;">{alert_type[:50]}</td>
                <td style="padding:6px;text-align:center;"><strong>{count}</strong></td>
            </tr>"""
        
        fp_rate = round(stats['false_positives'] / max(stats['total'], 1) * 100, 1)
        
        html = f"""<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>보안 알람 요약 리포트</title>
</head>
<body style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;margin:0;padding:0;background:#f5f6fa;">
<div style="max-width:900px;margin:0 auto;padding:20px;">

<!-- 헤더 -->
<div style="background:linear-gradient(135deg,#1a1a2e 0%,#16213e 50%,#0f3460 100%);color:white;padding:30px;border-radius:12px;margin-bottom:20px;">
    <div style="display:flex;justify-content:space-between;align-items:center;">
        <div>
            <h1 style="margin:0;font-size:24px;font-weight:700;">🔐 보안 알람 요약 리포트</h1>
            <p style="margin:8px 0 0;opacity:0.8;font-size:14px;">
                분석 기간: {period_start.strftime("%Y-%m-%d %H:%M")} ~ {period_end.strftime("%Y-%m-%d %H:%M")}
            </p>
        </div>
        <div style="text-align:right;">
            <div style="background:{risk_color};padding:12px 24px;border-radius:8px;font-size:20px;font-weight:bold;">
                {stats['risk_level']}
            </div>
            <p style="margin:4px 0 0;font-size:12px;opacity:0.7;">{report_type.upper()} 리포트</p>
        </div>
    </div>
</div>

<!-- 요약 카드 -->
<div style="display:grid;grid-template-columns:repeat(4,1fr);gap:15px;margin-bottom:20px;">
    <div style="background:white;padding:20px;border-radius:10px;text-align:center;box-shadow:0 2px 8px rgba(0,0,0,0.06);border-top:4px solid #4361ee;">
        <div style="font-size:36px;font-weight:bold;color:#4361ee;">{stats['total']}</div>
        <div style="color:#666;font-size:13px;margin-top:4px;">전체 알람</div>
    </div>
    <div style="background:white;padding:20px;border-radius:10px;text-align:center;box-shadow:0 2px 8px rgba(0,0,0,0.06);border-top:4px solid #dc3545;">
        <div style="font-size:36px;font-weight:bold;color:#dc3545;">{stats['by_severity'].get('critical', 0) + stats['by_severity'].get('high', 0)}</div>
        <div style="color:#666;font-size:13px;margin-top:4px;">높은 위험</div>
    </div>
    <div style="background:white;padding:20px;border-radius:10px;text-align:center;box-shadow:0 2px 8px rgba(0,0,0,0.06);border-top:4px solid #ffc107;">
        <div style="font-size:36px;font-weight:bold;color:#e6a800;">{stats['false_positives']}</div>
        <div style="color:#666;font-size:13px;margin-top:4px;">오탐 ({fp_rate}%)</div>
    </div>
    <div style="background:white;padding:20px;border-radius:10px;text-align:center;box-shadow:0 2px 8px rgba(0,0,0,0.06);border-top:4px solid #17a2b8;">
        <div style="font-size:36px;font-weight:bold;color:#17a2b8;">{stats['repeated']}</div>
        <div style="color:#666;font-size:13px;margin-top:4px;">반복 알람</div>
    </div>
</div>

<!-- 심각도 분포 -->
<div style="background:white;padding:20px;border-radius:10px;margin-bottom:20px;box-shadow:0 2px 8px rgba(0,0,0,0.06);">
    <h2 style="margin:0 0 15px;font-size:16px;color:#333;">📊 심각도별 현황</h2>
    <div style="display:grid;grid-template-columns:repeat(5,1fr);gap:10px;">
        {''.join([
            f'<div style="text-align:center;padding:12px;background:#fff3f3;border-radius:8px;">'
            f'<div style="font-size:24px;font-weight:bold;color:#dc3545;">{stats["by_severity"]["critical"]}</div>'
            f'<div style="font-size:11px;color:#666;margin-top:2px;">CRITICAL</div></div>',
            f'<div style="text-align:center;padding:12px;background:#fff8f0;border-radius:8px;">'
            f'<div style="font-size:24px;font-weight:bold;color:#fd7e14;">{stats["by_severity"]["high"]}</div>'
            f'<div style="font-size:11px;color:#666;margin-top:2px;">HIGH</div></div>',
            f'<div style="text-align:center;padding:12px;background:#fffdf0;border-radius:8px;">'
            f'<div style="font-size:24px;font-weight:bold;color:#e6a800;">{stats["by_severity"]["medium"]}</div>'
            f'<div style="font-size:11px;color:#666;margin-top:2px;">MEDIUM</div></div>',
            f'<div style="text-align:center;padding:12px;background:#f0fff4;border-radius:8px;">'
            f'<div style="font-size:24px;font-weight:bold;color:#28a745;">{stats["by_severity"]["low"]}</div>'
            f'<div style="font-size:11px;color:#666;margin-top:2px;">LOW</div></div>',
            f'<div style="text-align:center;padding:12px;background:#f0faff;border-radius:8px;">'
            f'<div style="font-size:24px;font-weight:bold;color:#17a2b8;">{stats["by_severity"]["info"]}</div>'
            f'<div style="font-size:11px;color:#666;margin-top:2px;">INFO</div></div>',
        ])}
    </div>
</div>

<!-- 주요 위협 IP & 알람 유형 -->
<div style="display:grid;grid-template-columns:1fr 1fr;gap:15px;margin-bottom:20px;">
    <div style="background:white;padding:20px;border-radius:10px;box-shadow:0 2px 8px rgba(0,0,0,0.06);">
        <h2 style="margin:0 0 15px;font-size:16px;color:#333;">🌐 주요 위협 IP</h2>
        {'<table style="width:100%;border-collapse:collapse;"><thead><tr><th style="padding:6px;text-align:left;font-size:12px;color:#666;border-bottom:2px solid #eee;">IP 주소</th><th style="padding:6px;text-align:center;font-size:12px;color:#666;border-bottom:2px solid #eee;">탐지 횟수</th></tr></thead><tbody>' + ip_rows + '</tbody></table>' if ip_rows else '<p style="color:#999;font-size:13px;">탐지된 외부 IP 없음</p>'}
    </div>
    <div style="background:white;padding:20px;border-radius:10px;box-shadow:0 2px 8px rgba(0,0,0,0.06);">
        <h2 style="margin:0 0 15px;font-size:16px;color:#333;">📋 알람 유형</h2>
        {'<table style="width:100%;border-collapse:collapse;"><thead><tr><th style="padding:6px;text-align:left;font-size:12px;color:#666;border-bottom:2px solid #eee;">유형</th><th style="padding:6px;text-align:center;font-size:12px;color:#666;border-bottom:2px solid #eee;">건수</th></tr></thead><tbody>' + type_rows + '</tbody></table>' if type_rows else '<p style="color:#999;font-size:13px;">분류된 알람 없음</p>'}
    </div>
</div>

<!-- 알람 목록 -->
<div style="background:white;padding:20px;border-radius:10px;margin-bottom:20px;box-shadow:0 2px 8px rgba(0,0,0,0.06);">
    <h2 style="margin:0 0 15px;font-size:16px;color:#333;">📬 최근 알람 상세 (상위 20건)</h2>
    {'<table style="width:100%;border-collapse:collapse;"><thead><tr style="border-bottom:2px solid #eee;"><th style="padding:8px;text-align:left;font-size:12px;color:#666;">수신시간</th><th style="padding:8px;text-align:left;font-size:12px;color:#666;">심각도</th><th style="padding:8px;text-align:left;font-size:12px;color:#666;">제목</th><th style="padding:8px;text-align:left;font-size:12px;color:#666;">IP</th><th style="padding:8px;text-align:left;font-size:12px;color:#666;">AI 요약</th></tr></thead><tbody>' + alert_rows + '</tbody></table>' if alert_rows else '<p style="color:#999;text-align:center;padding:20px;">해당 기간 알람 없음</p>'}
</div>

<!-- 푸터 -->
<div style="text-align:center;color:#999;font-size:12px;padding:20px;">
    <p>이 리포트는 AI 보안 알람 분석 시스템에 의해 자동 생성되었습니다.</p>
    <p>생성 시각: {datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")} UTC</p>
    <p style="margin-top:8px;">⚡ NVIDIA GPU 가속 로컬 LLM 분석 | 🔒 보안 데이터 로컬 처리</p>
</div>

</div>
</body>
</html>"""
        
        return html
