"""
스케줄러 유틸리티
"""
import os
import json
from datetime import datetime
from typing import Optional


async def get_scheduler_status():
    """스케줄러 상태 반환"""
    return {
        "daily_fetch": "09:00 KST",
        "daily_report": "09:30 KST",
        "status": "running",
    }
