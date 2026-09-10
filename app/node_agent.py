"""
AmneziaWG Node Agent
Runs as a daemon on worker nodes (systemd service awg-node.service).
Provides authenticated REST API for Master panel to manage AWG interfaces, peers, and collect metrics.
"""

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import Depends, FastAPI, HTTPException, Header, Request, status
from pydantic import BaseModel
import uvicorn

CONFIG_PATH = Path("/opt/awg-node/config.json")
DEFAULT_AWG_DIR = Path("/etc/amnezia/amneziawg")

app = FastAPI(title="AmneziaWG Node Agent", version="1.0.0")


def load_agent_config() -> Dict[str, Any]:
    if CONFIG_PATH.exists():
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {
        "api_token": os.environ.get("NODE_API_TOKEN", "default-dev-token"),
        "port": int(os.environ.get("NODE_API_PORT", "8089")),
        "host": "0.0.0.0",
    }


config = load_agent_config()


def verify_token(authorization: Optional[str] = Header(None)) -> str:
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Authorization header",
        )
    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authorization format. Use 'Bearer <token>'",
        )
    token = parts[1]
    expected = config.get("api_token", "")
    if not expected or token != expected:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired node token",
        )
    return token


def run_cmd(args: List[str]) -> subprocess.CompletedProcess:
    return subprocess.run(args, capture_output=True, text=True)


# Models
class InterfaceSyncReq(BaseModel):
    name: str
    config_text: str
    table_num: int = 101
    fwmark: int = 1
    mtu: int = 1200
    x_subnet: int = 21
    start: bool = True


class PeerSyncReq(BaseModel):
    interface: str
    public_key: str
    allowed_ips: str
    preshared_key: Optional[str] = None
    is_enabled: bool = True


@app.get("/api/agent/health")
def health():
    return {"status": "ok", "version": "1.0.0", "timestamp": time.time()}


@app.get("/api/agent/metrics")
def get_metrics(_: str = Depends(verify_token)):
    # CPU
    cpu_percent = 0.0
    try:
        with open("/proc/loadavg", "r") as f:
            load = f.read().split()
            cpu_percent = round(float(load[0]) * 100 / max(os.cpu_count() or 1, 1), 1)
    except Exception:
        pass

    # RAM
    ram_total = 0
    ram_available = 0
    try:
        with open("/proc/meminfo", "r") as f:
            for line in f:
                parts = line.split(":")
                if parts[0] == "MemTotal":
                    ram_total = int(parts[1].strip().split()[0]) * 1024
                elif parts[0] == "MemAvailable":
                    ram_available = int(parts[1].strip().split()[0]) * 1024
    except Exception:
        pass
    ram_used = max(0, ram_total - ram_available)
    ram_percent = round((ram_used / ram_total * 100), 1) if ram_total > 0 else 0

    # Disk
    try:
        disk = shutil.disk_usage("/")
        disk_total = disk.total
        disk_used = disk.used
        disk_percent = round(disk.used / disk.total * 100, 1)
    except Exception:
        disk_total = 0
        disk_used = 0
        disk_percent = 0

    # Uptime
    uptime_sec = 0
    try:
        with open("/proc/uptime", "r") as f:
            uptime_sec = int(float(f.read().split()[0]))
    except Exception:
        pass

    # Interfaces
    interfaces = []
    if DEFAULT_AWG_DIR.exists():
        for item in DEFAULT_AWG_DIR.iterdir():
            if item.is_dir() and (item / f"{item.name}.conf").exists():
                name = item.name
                is_running = run_cmd(["ip", "link", "show", name]).returncode == 0
                interfaces.append({"name": name, "is_running": is_running})

    return {
        "cpu_percent": min(100.0, cpu_percent),
        "ram": {
            "total_bytes": ram_total,
            "used_bytes": ram_used,
            "percent": ram_percent,
        },
        "disk": {
            "total_bytes": disk_total,
            "used_bytes": disk_used,
            "percent": disk_percent,
        },
        "uptime_seconds": uptime_sec,
        "interfaces": interfaces,
    }


@app.post("/api/agent/interfaces/sync")
def sync_interface(req: InterfaceSyncReq, _: str = Depends(verify_token)):
    name = req.name
    conf_dir = DEFAULT_AWG_DIR / name
    conf_dir.mkdir(parents=True, exist_ok=True)
    conf_file = conf_dir / f"{name}.conf"
    symlink_file = DEFAULT_AWG_DIR / f"{name}.conf"

    # Write config
    with open(conf_file, "w", encoding="utf-8") as f:
        f.write(req.config_text.strip() + "\n")
    os.chmod(conf_file, 0o600)

    # Symlink
    if symlink_file.is_symlink() or symlink_file.exists():
        try:
            symlink_file.unlink()
        except Exception:
            pass
    try:
        symlink_file.symlink_to(conf_file)
    except Exception:
        # Fallback copy
        shutil.copy2(conf_file, symlink_file)

    # Enable ip_forward
    run_cmd(["sysctl", "-w", "net.ipv4.ip_forward=1"])

    # Apply TCPMSS clamping rule for this interface
    chk = run_cmd([
        "iptables", "-t", "mangle", "-C", "FORWARD", "-p", "tcp",
        "--tcp-flags", "SYN,RST", "SYN", "-o", name, "-j", "TCPMSS", "--clamp-mss-to-pmtu"
    ])
    if chk.returncode != 0:
        run_cmd([
            "iptables", "-t", "mangle", "-A", "FORWARD", "-p", "tcp",
            "--tcp-flags", "SYN,RST", "SYN", "-o", name, "-j", "TCPMSS", "--clamp-mss-to-pmtu"
        ])

    chk_in = run_cmd([
        "iptables", "-t", "mangle", "-C", "FORWARD", "-p", "tcp",
        "--tcp-flags", "SYN,RST", "SYN", "-i", name, "-j", "TCPMSS", "--clamp-mss-to-pmtu"
    ])
    if chk_in.returncode != 0:
        run_cmd([
            "iptables", "-t", "mangle", "-A", "FORWARD", "-p", "tcp",
            "--tcp-flags", "SYN,RST", "SYN", "-i", name, "-j", "TCPMSS", "--clamp-mss-to-pmtu"
        ])

    if req.start:
        link_chk = run_cmd(["ip", "link", "show", name])
        if link_chk.returncode == 0:
            sync_res = run_cmd(["awg", "syncconf", name, str(conf_file)])
            if sync_res.returncode != 0:
                run_cmd(["systemctl", "restart", f"awg-quick@{name}"])
        else:
            up_res = run_cmd(["systemctl", "start", f"awg-quick@{name}"])
            if up_res.returncode != 0:
                run_cmd(["awg-quick", "up", name])

    return {"status": "success", "message": f"Interface {name} synchronized"}


@app.post("/api/agent/interfaces/{name}/start")
def start_interface(name: str, _: str = Depends(verify_token)):
    res = run_cmd(["systemctl", "start", f"awg-quick@{name}"])
    if res.returncode != 0:
        res = run_cmd(["awg-quick", "up", name])
    if res.returncode != 0:
        raise HTTPException(status_code=500, detail=f"Failed to start {name}: {res.stderr}")
    return {"status": "success", "message": f"Interface {name} started"}


@app.post("/api/agent/interfaces/{name}/stop")
def stop_interface(name: str, _: str = Depends(verify_token)):
    res = run_cmd(["systemctl", "stop", f"awg-quick@{name}"])
    if res.returncode != 0:
        res = run_cmd(["awg-quick", "down", name])
    return {"status": "success", "message": f"Interface {name} stopped"}


@app.delete("/api/agent/interfaces/{name}")
def delete_interface(name: str, _: str = Depends(verify_token)):
    stop_interface(name, _)
    conf_dir = DEFAULT_AWG_DIR / name
    symlink_file = DEFAULT_AWG_DIR / f"{name}.conf"
    if symlink_file.is_symlink() or symlink_file.exists():
        try:
            symlink_file.unlink()
        except Exception:
            pass
    if conf_dir.exists():
        try:
            shutil.rmtree(conf_dir)
        except Exception:
            pass
    return {"status": "success", "message": f"Interface {name} removed"}


@app.get("/api/agent/interfaces/{name}/stats")
def get_interface_stats(name: str, _: str = Depends(verify_token)):
    link_chk = run_cmd(["ip", "link", "show", name])
    if link_chk.returncode != 0:
        return {
            "name": name,
            "is_running": False,
            "rx_bytes": 0,
            "tx_bytes": 0,
            "peers": {},
        }

    show_res = run_cmd(["awg", "show", name])
    if show_res.returncode != 0:
        show_res = run_cmd(["wg", "show", name])

    peers = {}
    current_peer = None
    rx_total = 0
    tx_total = 0

    for line in show_res.stdout.splitlines():
        line = line.strip()
        if line.startswith("peer:"):
            current_peer = line.split(":", 1)[1].strip()
            peers[current_peer] = {
                "public_key": current_peer,
                "endpoint": "",
                "allowed_ips": "",
                "latest_handshake": "",
                "transfer_raw": "",
            }
        elif current_peer and line.startswith("endpoint:"):
            peers[current_peer]["endpoint"] = line.split(":", 1)[1].strip()
        elif current_peer and line.startswith("allowed ips:"):
            peers[current_peer]["allowed_ips"] = line.split(":", 1)[1].strip()
        elif current_peer and line.startswith("latest handshake:"):
            peers[current_peer]["latest_handshake"] = line.split(":", 1)[1].strip()
        elif current_peer and line.startswith("transfer:"):
            peers[current_peer]["transfer_raw"] = line.split(":", 1)[1].strip()

    try:
        with open(f"/sys/class/net/{name}/statistics/rx_bytes", "r") as f:
            rx_total = int(f.read().strip())
        with open(f"/sys/class/net/{name}/statistics/tx_bytes", "r") as f:
            tx_total = int(f.read().strip())
    except Exception:
        pass

    return {
        "name": name,
        "is_running": True,
        "rx_bytes": rx_total,
        "tx_bytes": tx_total,
        "peer_count": len(peers),
        "peers": peers,
    }


@app.post("/api/agent/peers/sync")
def sync_peer(req: PeerSyncReq, _: str = Depends(verify_token)):
    interface = req.interface
    pubkey = req.public_key
    allowed_ips = req.allowed_ips

    link_chk = run_cmd(["ip", "link", "show", interface])
    if link_chk.returncode == 0:
        if req.is_enabled:
            cmd = ["awg", "set", interface, "peer", pubkey, "allowed-ips", allowed_ips]
            if req.preshared_key:
                with tempfile.NamedTemporaryFile("w", delete=False) as tf:
                    tf.write(req.preshared_key.strip())
                    tf_path = tf.name
                os.chmod(tf_path, 0o600)
                try:
                    cmd.extend(["preshared-key", tf_path])
                    run_cmd(cmd)
                finally:
                    try:
                        os.unlink(tf_path)
                    except Exception:
                        pass
            else:
                run_cmd(cmd)
        else:
            run_cmd(["awg", "set", interface, "peer", pubkey, "remove"])

    conf_file = DEFAULT_AWG_DIR / interface / f"{interface}.conf"
    if conf_file.exists():
        _update_peer_in_conf_file(
            conf_file=conf_file,
            pubkey=pubkey,
            allowed_ips=allowed_ips,
            preshared_key=req.preshared_key,
            is_enabled=req.is_enabled,
        )

    return {"status": "success", "message": f"Peer {pubkey[:8]} synced on {interface}"}


@app.delete("/api/agent/peers/{interface}/{public_key}")
def remove_peer(interface: str, public_key: str, _: str = Depends(verify_token)):
    link_chk = run_cmd(["ip", "link", "show", interface])
    if link_chk.returncode == 0:
        run_cmd(["awg", "set", interface, "peer", public_key, "remove"])

    conf_file = DEFAULT_AWG_DIR / interface / f"{interface}.conf"
    if conf_file.exists():
        _remove_peer_from_conf_file(conf_file, public_key)

    return {"status": "success", "message": f"Peer {public_key[:8]} removed from {interface}"}


def _update_peer_in_conf_file(conf_file: Path, pubkey: str, allowed_ips: str, preshared_key: Optional[str], is_enabled: bool):
    try:
        content = conf_file.read_text(encoding="utf-8")
    except Exception:
        return

    parts = re.split(r"(?=\[Peer\])", content)
    header = parts[0]
    peer_blocks = parts[1:]

    new_blocks = []
    found = False

    for b in peer_blocks:
        if pubkey in b:
            found = True
            if is_enabled:
                lines = ["[Peer]", f"PublicKey = {pubkey}", f"AllowedIPs = {allowed_ips}"]
                if preshared_key:
                    lines.append(f"PresharedKey = {preshared_key}")
                new_blocks.append("\n".join(lines) + "\n\n")
        else:
            new_blocks.append(b)

    if not found and is_enabled:
        lines = ["[Peer]", f"PublicKey = {pubkey}", f"AllowedIPs = {allowed_ips}"]
        if preshared_key:
            lines.append(f"PresharedKey = {preshared_key}")
        new_blocks.append("\n".join(lines) + "\n\n")

    full_text = header + "".join(new_blocks)
    conf_file.write_text(full_text.strip() + "\n", encoding="utf-8")


def _remove_peer_from_conf_file(conf_file: Path, pubkey: str):
    try:
        content = conf_file.read_text(encoding="utf-8")
    except Exception:
        return
    parts = re.split(r"(?=\[Peer\])", content)
    header = parts[0]
    peer_blocks = parts[1:]

    new_blocks = [b for b in peer_blocks if pubkey not in b]
    full_text = header + "".join(new_blocks)
    conf_file.write_text(full_text.strip() + "\n", encoding="utf-8")


if __name__ == "__main__":
    cfg = load_agent_config()
    uvicorn.run(app, host=cfg.get("host", "0.0.0.0"), port=cfg.get("port", 8089))
