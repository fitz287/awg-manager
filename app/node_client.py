"""
AmneziaWG Node Client
Used by Master Control Panel to communicate with Node Agents over HTTP REST API.
"""

import logging
from typing import Any, Dict, List, Optional
import httpx

logger = logging.getLogger("node_client")


class NodeClient:
    def __init__(self, server: Dict[str, Any], timeout: float = 8.0):
        self.server_id = server.get("id")
        self.host = server.get("host", "").strip()
        self.port = server.get("api_port", 8089)
        self.token = server.get("api_token", "").strip()
        self.base_url = f"http://{self.host}:{self.port}"
        self.timeout = timeout

    def _headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
        }

    def health(self) -> Dict[str, Any]:
        try:
            with httpx.Client(timeout=self.timeout) as client:
                res = client.get(f"{self.base_url}/api/agent/health")
                if res.status_code == 200:
                    return res.json()
                return {"status": "error", "code": res.status_code}
        except Exception as e:
            return {"status": "offline", "error": str(e)}

    def check_health_with_latency(self) -> Dict[str, Any]:
        import time
        t0 = time.perf_counter()
        try:
            with httpx.Client(timeout=self.timeout) as client:
                res = client.get(f"{self.base_url}/api/agent/health")
                latency_ms = round((time.perf_counter() - t0) * 1000, 1)
                if res.status_code == 200:
                    data = res.json()
                    # Try to fetch metrics too
                    try:
                        metrics_res = client.get(f"{self.base_url}/api/agent/metrics", headers=self._headers())
                        metrics = metrics_res.json() if metrics_res.status_code == 200 else {}
                    except Exception:
                        metrics = {}

                    return {
                        "status": "online",
                        "latency_ms": latency_ms,
                        "cpu_percent": metrics.get("cpu_percent", 0),
                        "memory_percent": metrics.get("memory", {}).get("percent", 0),
                        "uptime_hours": round(metrics.get("uptime_seconds", 0) / 3600, 1),
                        "agent_version": data.get("version", "1.0.0"),
                    }
                return {
                    "status": "error",
                    "code": res.status_code,
                    "latency_ms": latency_ms,
                }
        except Exception as e:
            latency_ms = round((time.perf_counter() - t0) * 1000, 1)
            return {
                "status": "offline",
                "error": str(e),
                "latency_ms": latency_ms,
            }


    def get_metrics(self) -> Dict[str, Any]:
        try:
            with httpx.Client(timeout=self.timeout) as client:
                res = client.get(f"{self.base_url}/api/agent/metrics", headers=self._headers())
                if res.status_code == 200:
                    return res.json()
                return {"error": f"HTTP {res.status_code}: {res.text}"}
        except Exception as e:
            return {"error": str(e)}

    def sync_interface(
        self,
        name: str,
        config_text: str,
        table_num: int = 101,
        fwmark: int = 1,
        mtu: int = 1200,
        x_subnet: int = 21,
        start: bool = True,
    ) -> Dict[str, Any]:
        payload = {
            "name": name,
            "config_text": config_text,
            "table_num": table_num,
            "fwmark": fwmark,
            "mtu": mtu,
            "x_subnet": x_subnet,
            "start": start,
        }
        try:
            with httpx.Client(timeout=self.timeout) as client:
                res = client.post(f"{self.base_url}/api/agent/interfaces/sync", json=payload, headers=self._headers())
                if res.status_code == 200:
                    return res.json()
                return {"status": "error", "detail": f"HTTP {res.status_code}: {res.text}"}
        except Exception as e:
            return {"status": "error", "detail": str(e)}

    def start_interface(self, name: str) -> Dict[str, Any]:
        try:
            with httpx.Client(timeout=self.timeout) as client:
                res = client.post(f"{self.base_url}/api/agent/interfaces/{name}/start", headers=self._headers())
                if res.status_code == 200:
                    return res.json()
                return {"status": "error", "detail": f"HTTP {res.status_code}: {res.text}"}
        except Exception as e:
            return {"status": "error", "detail": str(e)}

    def stop_interface(self, name: str) -> Dict[str, Any]:
        try:
            with httpx.Client(timeout=self.timeout) as client:
                res = client.post(f"{self.base_url}/api/agent/interfaces/{name}/stop", headers=self._headers())
                if res.status_code == 200:
                    return res.json()
                return {"status": "error", "detail": f"HTTP {res.status_code}: {res.text}"}
        except Exception as e:
            return {"status": "error", "detail": str(e)}

    def delete_interface(self, name: str) -> Dict[str, Any]:
        try:
            with httpx.Client(timeout=self.timeout) as client:
                res = client.delete(f"{self.base_url}/api/agent/interfaces/{name}", headers=self._headers())
                if res.status_code == 200:
                    return res.json()
                return {"status": "error", "detail": f"HTTP {res.status_code}: {res.text}"}
        except Exception as e:
            return {"status": "error", "detail": str(e)}

    def get_interface_stats(self, name: str) -> Dict[str, Any]:
        try:
            with httpx.Client(timeout=self.timeout) as client:
                res = client.get(f"{self.base_url}/api/agent/interfaces/{name}/stats", headers=self._headers())
                if res.status_code == 200:
                    return res.json()
                return {"name": name, "is_running": False, "error": f"HTTP {res.status_code}"}
        except Exception as e:
            return {"name": name, "is_running": False, "error": str(e)}

    def sync_peer(
        self,
        interface: str,
        public_key: str,
        allowed_ips: str,
        preshared_key: Optional[str] = None,
        is_enabled: bool = True,
    ) -> Dict[str, Any]:
        payload = {
            "interface": interface,
            "public_key": public_key,
            "allowed_ips": allowed_ips,
            "preshared_key": preshared_key,
            "is_enabled": is_enabled,
        }
        try:
            with httpx.Client(timeout=self.timeout) as client:
                res = client.post(f"{self.base_url}/api/agent/peers/sync", json=payload, headers=self._headers())
                if res.status_code == 200:
                    return res.json()
                return {"status": "error", "detail": f"HTTP {res.status_code}: {res.text}"}
        except Exception as e:
            return {"status": "error", "detail": str(e)}

    def remove_peer(self, interface: str, public_key: str) -> Dict[str, Any]:
        try:
            with httpx.Client(timeout=self.timeout) as client:
                res = client.delete(f"{self.base_url}/api/agent/peers/{interface}/{public_key}", headers=self._headers())
                if res.status_code == 200:
                    return res.json()
                return {"status": "error", "detail": f"HTTP {res.status_code}: {res.text}"}
        except Exception as e:
            return {"status": "error", "detail": str(e)}
