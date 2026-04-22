"""
IP Intelligence Service - IP 정보 조회 및 위협 분석
"""
import httpx
import re
import os
from typing import Dict, List, Optional, Any
from datetime import datetime


class IPIntelligenceService:
    def __init__(self):
        self.timeout = httpx.Timeout(30.0)
        self.abuseipdb_key = os.environ.get('ABUSEIPDB_API_KEY', '')
        self.ipinfo_token = os.environ.get('IPINFO_TOKEN', '')

    @staticmethod
    def extract_ips_from_text(text: str) -> List[str]:
        """텍스트에서 IP 주소 추출"""
        if not text:
            return []
        
        # IPv4 패턴
        ipv4_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        
        # Private IP 제외
        private_ranges = [
            r'^10\.',
            r'^172\.(1[6-9]|2[0-9]|3[01])\.',
            r'^192\.168\.',
            r'^127\.',
            r'^0\.',
            r'^169\.254\.',
        ]
        
        ips = re.findall(ipv4_pattern, text)
        
        filtered = []
        for ip in ips:
            is_private = any(re.match(pattern, ip) for pattern in private_ranges)
            if not is_private and ip not in filtered:
                filtered.append(ip)
        
        return filtered[:20]  # 최대 20개

    @staticmethod
    def extract_domains_from_text(text: str) -> List[str]:
        """텍스트에서 도메인 추출"""
        if not text:
            return []
        
        domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
        
        # 제외할 도메인
        exclude_domains = ['gmail.com', 'google.com', 'microsoft.com', 
                          'example.com', 'localhost']
        
        domains = re.findall(domain_pattern, text)
        
        filtered = []
        for domain in domains:
            domain_lower = domain.lower()
            if domain_lower not in exclude_domains and domain_lower not in filtered:
                filtered.append(domain_lower)
        
        return filtered[:10]

    async def lookup_ip(self, ip: str) -> Dict[str, Any]:
        """IP 종합 정보 조회"""
        result = {
            "ip": ip,
            "geo": {},
            "threat": {},
            "reputation": {},
            "timestamp": datetime.utcnow().isoformat()
        }
        
        # 기본 GeoIP 조회 (무료 API)
        geo_data = await self._get_geo_info(ip)
        result["geo"] = geo_data
        
        # AbuseIPDB 조회 (API 키가 있는 경우)
        if self.abuseipdb_key:
            abuse_data = await self._get_abuseipdb_info(ip)
            result["threat"] = abuse_data
        
        # IPInfo 조회
        if self.ipinfo_token:
            ipinfo_data = await self._get_ipinfo(ip)
            result["reputation"] = ipinfo_data
        else:
            # 무료 ipapi.co 사용
            ipapi_data = await self._get_ipapi(ip)
            result["geo"].update(ipapi_data)
        
        # Shodan 링크 (무료 제공)
        result["links"] = {
            "shodan": f"https://www.shodan.io/host/{ip}",
            "virustotal": f"https://www.virustotal.com/gui/ip-address/{ip}",
            "abuseipdb": f"https://www.abuseipdb.com/check/{ip}",
            "ipinfo": f"https://ipinfo.io/{ip}",
            "greynoise": f"https://viz.greynoise.io/ip/{ip}",
        }
        
        return result

    async def _get_geo_info(self, ip: str) -> Dict:
        """기본 지리 정보 조회 (ip-api.com - 무료)"""
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(
                    f"http://ip-api.com/json/{ip}",
                    params={"fields": "status,country,countryCode,regionName,city,lat,lon,isp,org,as,proxy,hosting,mobile"}
                )
                if resp.status_code == 200:
                    data = resp.json()
                    if data.get('status') == 'success':
                        return {
                            "country": data.get('country', ''),
                            "country_code": data.get('countryCode', ''),
                            "region": data.get('regionName', ''),
                            "city": data.get('city', ''),
                            "latitude": data.get('lat', 0),
                            "longitude": data.get('lon', 0),
                            "isp": data.get('isp', ''),
                            "org": data.get('org', ''),
                            "asn": data.get('as', ''),
                            "is_proxy": data.get('proxy', False),
                            "is_datacenter": data.get('hosting', False),
                            "is_mobile": data.get('mobile', False),
                        }
        except Exception as e:
            print(f"GeoIP lookup error for {ip}: {e}")
        return {}

    async def _get_ipapi(self, ip: str) -> Dict:
        """ipapi.co 무료 조회"""
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(f"https://ipapi.co/{ip}/json/")
                if resp.status_code == 200:
                    data = resp.json()
                    if not data.get('error'):
                        return {
                            "timezone": data.get('timezone', ''),
                            "currency": data.get('currency', ''),
                            "calling_code": data.get('country_calling_code', ''),
                        }
        except:
            pass
        return {}

    async def _get_abuseipdb_info(self, ip: str) -> Dict:
        """AbuseIPDB 위협 정보 조회"""
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(
                    "https://api.abuseipdb.com/api/v2/check",
                    params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
                    headers={"Key": self.abuseipdb_key, "Accept": "application/json"}
                )
                if resp.status_code == 200:
                    data = resp.json().get('data', {})
                    return {
                        "abuse_confidence": data.get('abuseConfidenceScore', 0),
                        "total_reports": data.get('totalReports', 0),
                        "last_reported": data.get('lastReportedAt', ''),
                        "usage_type": data.get('usageType', ''),
                        "domain": data.get('domain', ''),
                        "is_tor": data.get('isTor', False),
                        "is_whitelisted": data.get('isWhitelisted', False),
                    }
        except Exception as e:
            print(f"AbuseIPDB error: {e}")
        return {}

    async def _get_ipinfo(self, ip: str) -> Dict:
        """IPInfo 조회"""
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(
                    f"https://ipinfo.io/{ip}/json",
                    headers={"Authorization": f"Bearer {self.ipinfo_token}"}
                )
                if resp.status_code == 200:
                    data = resp.json()
                    return {
                        "hostname": data.get('hostname', ''),
                        "privacy": data.get('privacy', {}),
                        "abuse": data.get('abuse', {}),
                    }
        except:
            pass
        return {}

    def calculate_threat_score(self, ip_data: Dict) -> int:
        """위협 점수 계산 (0-100)"""
        score = 0
        
        geo = ip_data.get('geo', {})
        threat = ip_data.get('threat', {})
        
        # AbuseIPDB 점수
        abuse_score = threat.get('abuse_confidence', 0)
        score += min(abuse_score, 50)
        
        # 프록시/VPN
        if geo.get('is_proxy'):
            score += 20
        
        # 데이터센터
        if geo.get('is_datacenter'):
            score += 10
        
        # Tor
        if threat.get('is_tor'):
            score += 30
        
        return min(score, 100)

    async def bulk_lookup(self, ips: List[str]) -> Dict[str, Dict]:
        """여러 IP 일괄 조회"""
        results = {}
        for ip in ips[:10]:  # 최대 10개
            results[ip] = await self.lookup_ip(ip)
        return results
