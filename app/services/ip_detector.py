import httpx
import logging
from typing import Optional
from datetime import datetime, timezone, timedelta
from app.core.config import settings

logger = logging.getLogger(__name__)

_cached_ip: Optional[str] = None
_cached_time: Optional[datetime] = None
CACHE_TTL = timedelta(hours=1)

IP_SERVICES = [
    "https://api.ipify.org",
    "https://ifconfig.me/ip",
    "https://icanhazip.com",
    "https://checkip.amazonaws.com"
]

async def get_server_public_ip() -> str:
    """
    Returns the server public IP address.
    Checks environment override first, then memory cache, then queries external IP services.
    """
    global _cached_ip, _cached_time

    if settings.SERVER_PUBLIC_IP and settings.SERVER_PUBLIC_IP.strip():
        return settings.SERVER_PUBLIC_IP.strip()

    now = datetime.now(timezone.utc)
    if _cached_ip and _cached_time and (now - _cached_time) < CACHE_TTL:
        return _cached_ip

    async with httpx.AsyncClient(timeout=4.0) as client:
        for url in IP_SERVICES:
            try:
                response = await client.get(url)
                if response.status_code == 200:
                    ip = response.text.strip()
                    if ip and len(ip.split('.')) == 4:
                        _cached_ip = ip
                        _cached_time = now
                        logger.info(f"Auto-detected server public IP: {ip} via {url}")
                        return ip
            except Exception as e:
                logger.debug(f"Failed to fetch IP from {url}: {e}")

    logger.warning("Could not auto-detect public IP. Falling back to 127.0.0.1")
    return "127.0.0.1"
