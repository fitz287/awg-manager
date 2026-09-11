import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from app.config import AWG_DIR, IS_LINUX
from app.database import (
    get_connection_by_id,
    get_connection_by_name,
    get_peer_by_id,
    get_peers_by_connection,
    get_server_by_id,
    get_setting,
    get_user_by_id,
    update_connection_status,
)
from app.iptables_manager import format_wg_rules
from app.node_client import NodeClient


def get_interface_dir(name: str) -> Path:
    """Returns directory path: /etc/amnezia/amneziawg/{name}/"""
    return AWG_DIR / name


def get_interface_conf_file(name: str) -> Path:
    """Returns config file inside subdir: /etc/amnezia/amneziawg/{name}/{name}.conf"""
    return get_interface_dir(name) / f"{name}.conf"


def get_interface_symlink(name: str) -> Path:
    """Returns symlink path: /etc/amnezia/amneziawg/{name}.conf"""
    return AWG_DIR / f"{name}.conf"


def build_awg_params_block(params: Dict[str, Any]) -> List[str]:
    """Builds the AmneziaWG obfuscation parameter lines."""
    lines = []
    version = str(params.get("protocol_version", "1.0"))

    # Common parameters
    for key in ("Jc", "Jmin", "Jmax", "S1", "S2"):
        if key in params and params[key] is not None:
            lines.append(f"{key} = {params[key]}")

    # AWG 2.0 / 3.1 padding
    if version in ("2.0", "3.0", "3.1"):
        for key in ("S3", "S4"):
            if key in params and params[key] is not None:
                lines.append(f"{key} = {params[key]}")

    # Headers H1-H4
    for key in ("H1", "H2", "H3", "H4"):
        if key in params and params[key] is not None:
            lines.append(f"{key} = {params[key]}")

    # AWG 3.1 specific parameters
    if version in ("3.0", "3.1"):
        if "HeaderProtectionKey" in params and params["HeaderProtectionKey"]:
            lines.append(f"HeaderProtectionKey = {params['HeaderProtectionKey']}")
        if "ContentPaddingAddition" in params and params["ContentPaddingAddition"]:
            lines.append(f"ContentPaddingAddition = {params['ContentPaddingAddition']}")
        if "RandomTrailers" in params and params["RandomTrailers"]:
            rt_val = params['RandomTrailers']
            lines.append(f"RandomTrailers = {'on' if str(rt_val).lower() in ('1', 'true', 'on') else rt_val}")
        for key in ("RekeyAfterTime", "RekeyTimeout", "RejectAfterTime", "KeepaliveTimeout", "MaxHandshakeAttempts"):
            if key in params and params[key] is not None:
                lines.append(f"{key} = {params[key]}")

    # Optional AWG 2.0 signatures
    for i in range(1, 6):
        key = f"I{i}"
        if key in params and params[key]:
            lines.append(f"{key} = {params[key]}")

    return lines


def generate_server_config_text(conn_id: int) -> str:
    """Generates the full server .conf file content for a connection."""
    conn = get_connection_by_id(conn_id)
    if not conn:
        raise ValueError(f"Connection with id {conn_id} not found")

    name = conn["name"]
    x_subnet = conn["x_subnet"]
    listen_port = conn["listen_port"]
    server_private_key = conn["server_private_key"]
    xray_port = conn["xray_port"]
    table_num = conn["table_num"]
    fwmark = conn["fwmark"]
    params = conn["params"]
    mtu = get_setting("default_mtu", "1200")

    lines = [
        "# ====================================================",
        f"# AmneziaWG Server Config: {name} (Protocol {params.get('protocol_version', '1.0')})",
        f"# Subnet: 10.{x_subnet}.0.0/16, Port: {listen_port}",
        "# ====================================================",
        "[Interface]",
        f"Address = 10.{x_subnet}.0.1/16",
        f"ListenPort = {listen_port}",
        f"PrivateKey = {server_private_key}",
    ]
    if mtu:
        lines.append(f"MTU = {mtu}")

    # Obfuscation parameters
    param_lines = build_awg_params_block(params)
    if param_lines:
        lines.append("# --- Obfuscation Parameters ---")
        lines.extend(param_lines)

    # Xray TProxy Rules
    lines.append("")
    xray_rules = format_wg_rules(name, x_subnet, xray_port, table_num, fwmark)
    lines.append(xray_rules)

    # Peers
    peers = get_peers_by_connection(conn_id)
    if peers:
        lines.append("")
        lines.append("# ====================================================")
        lines.append(f"# Peers ({len(peers)} active)")
        lines.append("# ====================================================")
        for p in peers:
            user = get_user_by_id(p["user_id"])
            username = user["username"] if user else f"user_{p['user_id']}"
            lines.append("")
            lines.append(f"# Peer: {username} - {p['label']} (IP: {p['client_ip']})")
            lines.append("[Peer]")
            lines.append(f"PublicKey = {p['client_public_key']}")
            if p.get("preshared_key"):
                lines.append(f"PresharedKey = {p['preshared_key']}")
            lines.append(f"AllowedIPs = {p['client_ip']}/32")

    return "\n".join(lines) + "\n"


def write_server_config(conn_id: int) -> Path:
    """
    Writes the server configuration to:
    /etc/amnezia/amneziawg/{name}/{name}.conf
    and creates the symlink:
    /etc/amnezia/amneziawg/{name}.conf -> /etc/amnezia/amneziawg/{name}/{name}.conf
    """
    conn = get_connection_by_id(conn_id)
    if not conn:
        raise ValueError(f"Connection with id {conn_id} not found")

    name = conn["name"]
    content = generate_server_config_text(conn_id)

    # 1. Create subdirectory
    dir_path = get_interface_dir(name)
    dir_path.mkdir(parents=True, exist_ok=True)
    if IS_LINUX:
        try:
            os.chmod(dir_path, 0o700)
        except Exception:
            pass

    # 2. Write conf file inside subdir
    conf_file = get_interface_conf_file(name)
    with open(conf_file, "w", encoding="utf-8") as f:
        f.write(content)
    if IS_LINUX:
        try:
            os.chmod(conf_file, 0o600)
        except Exception:
            pass

    # 3. Create or update symlink
    symlink_file = get_interface_symlink(name)
    try:
        if symlink_file.is_symlink() or symlink_file.exists():
            symlink_file.unlink()
        symlink_file.symlink_to(conf_file)
    except (OSError, NotImplementedError) as e:
        # On Windows or systems without symlink permissions, fallback to hard link or copy
        if not symlink_file.exists():
            try:
                shutil.copyfile(conf_file, symlink_file)
            except Exception:
                pass

    return conf_file


def generate_client_config_text(peer_id: int) -> str:
    """Generates the client .conf file for a peer."""
    peer = get_peer_by_id(peer_id)
    if not peer:
        raise ValueError(f"Peer with id {peer_id} not found")

    conn = get_connection_by_id(peer["connection_id"])
    if not conn:
        raise ValueError(f"Connection with id {peer['connection_id']} not found")

    user = get_user_by_id(peer["user_id"])
    username = user["username"] if user else "User"

    server = get_server_by_id(conn.get("server_id", 1))
    server_host = server["host"] if server and server.get("host") else get_setting("server_host", "").strip()
    if not server_host:
        server_host = "YOUR_SERVER_IP"

    dns = get_setting("default_dns", "1.1.1.1, 8.8.8.8")
    mtu = get_setting("default_mtu", "1200")

    params = conn["params"]
    param_lines = build_awg_params_block(params)

    lines = [
        "# ====================================================",
        f"# AmneziaWG Client: {username} - {peer['label']}",
        f"# Protocol: AWG {params.get('protocol_version', '1.0')}",
        "# ====================================================",
        "[Interface]",
        f"PrivateKey = {peer['client_private_key']}",
        f"Address = {peer['client_ip']}/32",
        f"DNS = {dns}",
    ]
    if mtu:
        lines.append(f"MTU = {mtu}")

    if param_lines:
        lines.append("# --- Obfuscation Parameters ---")
        lines.extend(param_lines)

    lines.append("")
    lines.append("[Peer]")
    lines.append(f"PublicKey = {conn['server_public_key']}")
    if peer.get("preshared_key"):
        lines.append(f"PresharedKey = {peer['preshared_key']}")
    lines.append(f"Endpoint = {server_host}:{conn['listen_port']}")
    lines.append("AllowedIPs = 0.0.0.0/0")
    lines.append("PersistentKeepalive = 25")

    return "\n".join(lines) + "\n"


def run_system_cmd(cmd: List[str]) -> Tuple[bool, str]:
    """Runs a system command and returns (success, output)."""
    if not IS_LINUX:
        return True, f"[MOCK] Executed: {' '.join(cmd)}"

    try:
        res = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=15,
        )
        if res.returncode == 0:
            return True, res.stdout.strip()
        return False, res.stderr.strip() or res.stdout.strip()
    except Exception as e:
        return False, str(e)


def start_connection(conn_id: int) -> Tuple[bool, str]:
    """Starts the AmneziaWG interface using NodeClient or local awg-quick/systemctl."""
    conn = get_connection_by_id(conn_id)
    if not conn:
        return False, "Подключение не найдено"

    name = conn["name"]
    server = get_server_by_id(conn.get("server_id", 1))

    # Try node agent if server is configured
    if server and server.get("host"):
        client = NodeClient(server)
        conf_text = generate_server_config_text(conn_id)
        try:
            mtu_val = int(get_setting("default_mtu", "1200"))
        except Exception:
            mtu_val = 1200

        res = client.sync_interface(
            name=name,
            config_text=conf_text,
            table_num=conn.get("table_num", 101),
            fwmark=conn.get("fwmark", 1),
            mtu=mtu_val,
            x_subnet=conn.get("x_subnet", 21),
            start=True,
        )
        if res.get("status") == "success":
            update_connection_status(conn_id, True)
            return True, f"Интерфейс {name} успешно запущен на ноде {server['name']}"

    # Fallback to local config write & local execution
    write_server_config(conn_id)

    if IS_LINUX:
        check_ok, _ = run_system_cmd(["ip", "link", "show", name])
        if check_ok:
            update_connection_status(conn_id, True)
            return True, f"Интерфейс {name} уже запущен"

        ok, out = run_system_cmd(["systemctl", "start", f"awg-quick@{name}"])
        if not ok:
            ok, out = run_system_cmd(["awg-quick", "up", name])

        if ok:
            update_connection_status(conn_id, True)
            return True, f"Интерфейс {name} успешно запущен"
        else:
            return False, f"Ошибка запуска {name}: {out}"
    else:
        update_connection_status(conn_id, True)
        return True, f"[MOCK] Интерфейс {name} запущен"


def stop_connection(conn_id: int) -> Tuple[bool, str]:
    """Stops the AmneziaWG interface."""
    conn = get_connection_by_id(conn_id)
    if not conn:
        return False, "Подключение не найдено"

    name = conn["name"]
    server = get_server_by_id(conn.get("server_id", 1))

    if server and server.get("host"):
        client = NodeClient(server)
        res = client.stop_interface(name)
        if res.get("status") == "success":
            update_connection_status(conn_id, False)
            return True, f"Интерфейс {name} остановлен на ноде {server['name']}"

    if IS_LINUX:
        ok, out = run_system_cmd(["systemctl", "stop", f"awg-quick@{name}"])
        if not ok:
            ok, out = run_system_cmd(["awg-quick", "down", name])

        update_connection_status(conn_id, False)
        return True, f"Интерфейс {name} остановлен: {out}"
    else:
        update_connection_status(conn_id, False)
        return True, f"[MOCK] Интерфейс {name} остановлен"


def restart_connection(conn_id: int) -> Tuple[bool, str]:
    """Restarts the connection."""
    stop_connection(conn_id)
    return start_connection(conn_id)


def remove_connection_files(name: str, server_id: Optional[int] = None) -> None:
    """Removes the interface directory and symlink."""
    if server_id:
        server = get_server_by_id(server_id)
        if server:
            NodeClient(server).delete_interface(name)

    dir_path = get_interface_dir(name)
    symlink_path = get_interface_symlink(name)

    if symlink_path.is_symlink() or symlink_path.exists():
        try:
            symlink_path.unlink()
        except Exception:
            pass

    if dir_path.exists():
        try:
            shutil.rmtree(dir_path)
        except Exception:
            pass


def fmt_bytes(b: int) -> str:
    if b < 1024:
        return f"{b} B"
    elif b < 1024 * 1024:
        return f"{b / 1024:.1f} KB"
    elif b < 1024 * 1024 * 1024:
        return f"{b / (1024 * 1024):.1f} MB"
    return f"{b / (1024 * 1024 * 1024):.2f} GB"


def get_interface_live_status(conn_id: int) -> Dict[str, Any]:
    """Fetches real-time status of interface (handshake, bytes, active peers)."""
    conn = get_connection_by_id(conn_id)
    if not conn:
        return {"status": "unknown", "is_running": False}

    name = conn["name"]
    server = get_server_by_id(conn.get("server_id", 1))

    if server and server.get("host") and server.get("id") != 1:
        client = NodeClient(server)
        stats = client.get_interface_stats(name)
        if stats.get("is_running"):
            update_connection_status(conn_id, True)
            peer_count = stats.get("peer_count", 0)
            rx_bytes = stats.get("rx_bytes", 0)
            tx_bytes = stats.get("tx_bytes", 0)

            return {
                "status": "active",
                "is_running": True,
                "rx_bytes": fmt_bytes(rx_bytes),
                "tx_bytes": fmt_bytes(tx_bytes),
                "last_handshake": "Активен",
                "peers_connected": peer_count,
            }

    if not IS_LINUX:
        return {
            "status": "active" if conn["is_active"] else "stopped",
            "is_running": bool(conn["is_active"]),
            "rx_bytes": "12.4 MB" if conn["is_active"] else "0 B",
            "tx_bytes": "45.8 MB" if conn["is_active"] else "0 B",
            "last_handshake": "2 минуты назад" if conn["is_active"] else "—",
            "peers_connected": conn.get("peer_count", 0) if conn["is_active"] else 0,
        }

    # Check if local network interface exists
    ok, _ = run_system_cmd(["ip", "link", "show", name])
    if not ok:
        update_connection_status(conn_id, False)
        return {
            "status": "stopped",
            "is_running": False,
            "rx_bytes": "0 B",
            "tx_bytes": "0 B",
            "last_handshake": "—",
            "peers_connected": 0,
        }

    update_connection_status(conn_id, True)

    ok_awg, awg_out = run_system_cmd(["awg", "show", name])
    if not ok_awg:
        ok_awg, awg_out = run_system_cmd(["wg", "show", name])

    peers_connected = 0
    last_handshake = "—"

    if ok_awg and awg_out:
        for line in awg_out.splitlines():
            line = line.strip()
            if "latest handshake:" in line:
                peers_connected += 1
                last_handshake = line.split("latest handshake:")[-1].strip()

    return {
        "status": "active",
        "is_running": True,
        "rx_bytes": "Активен",
        "tx_bytes": "В норме",
        "last_handshake": last_handshake,
        "peers_connected": peers_connected,
        "raw_info": awg_out if ok_awg else "",
    }


def get_interface_detailed_status(conn_id: int) -> Dict[str, Any]:
    """
    Fetches comprehensive diagnostic status of an interface:
    - Interface running status, server, ports, subnet
    - Total Rx/Tx traffic
    - Real-time peers list with endpoints, handshakes, transfers, mapped to username/device
    - Obfuscation parameters
    - Full raw output of awg show
    """
    conn = get_connection_by_id(conn_id)
    if not conn:
        return {"status": "error", "detail": "Подключение не найдено"}

    name = conn["name"]
    server = get_server_by_id(conn.get("server_id", 1))
    server_name = server["name"] if server else "Основной сервер"
    server_host = server["host"] if server else "127.0.0.1"

    # Known peers from DB
    db_peers = get_peers_by_connection(conn_id)
    peer_db_map = {}
    for p in db_peers:
        u = get_user_by_id(p["user_id"])
        username = u["username"] if u else f"user_{p['user_id']}"
        peer_db_map[p["client_public_key"]] = {
            "id": p["id"],
            "user_id": p["user_id"],
            "username": username,
            "label": p["label"],
            "client_ip": p["client_ip"],
            "is_enabled": bool(p["is_enabled"]),
        }

    is_running = False
    raw_output = ""
    peers_dict = {}
    rx_bytes = 0
    tx_bytes = 0

    # 1. Check remote node
    if server and server.get("host") and server.get("id") != 1:
        client = NodeClient(server)
        stats = client.get_interface_stats(name)
        is_running = stats.get("is_running", False)
        rx_bytes = stats.get("rx_bytes", 0)
        tx_bytes = stats.get("tx_bytes", 0)
        for pub, pdata in stats.get("peers", {}).items():
            peers_dict[pub] = {
                "public_key": pub,
                "endpoint": pdata.get("endpoint", ""),
                "allowed_ips": pdata.get("allowed_ips", ""),
                "latest_handshake": pdata.get("latest_handshake", ""),
                "transfer": pdata.get("transfer_raw", ""),
            }
        raw_output = f"# Node: {server_name} ({server_host})\n# Interface: {name}\n# Running: {is_running}\n"
    else:
        # 2. Local / Master server
        if IS_LINUX:
            ok_link, _ = run_system_cmd(["ip", "link", "show", name])
            is_running = ok_link
            if ok_link:
                ok_awg, awg_out = run_system_cmd(["awg", "show", name])
                if not ok_awg:
                    ok_awg, awg_out = run_system_cmd(["wg", "show", name])

                if ok_awg and awg_out:
                    raw_output = awg_out
                    current_peer = None
                    for line in awg_out.splitlines():
                        sline = line.strip()
                        if sline.startswith("peer:"):
                            current_peer = sline.split(":", 1)[1].strip()
                            peers_dict[current_peer] = {
                                "public_key": current_peer,
                                "endpoint": "",
                                "allowed_ips": "",
                                "latest_handshake": "",
                                "transfer": "",
                            }
                        elif current_peer and sline.startswith("endpoint:"):
                            peers_dict[current_peer]["endpoint"] = sline.split(":", 1)[1].strip()
                        elif current_peer and sline.startswith("allowed ips:"):
                            peers_dict[current_peer]["allowed_ips"] = sline.split(":", 1)[1].strip()
                        elif current_peer and sline.startswith("latest handshake:"):
                            peers_dict[current_peer]["latest_handshake"] = sline.split(":", 1)[1].strip()
                        elif current_peer and sline.startswith("transfer:"):
                            peers_dict[current_peer]["transfer"] = sline.split(":", 1)[1].strip()

                try:
                    with open(f"/sys/class/net/{name}/statistics/rx_bytes", "r") as f:
                        rx_bytes = int(f.read().strip())
                    with open(f"/sys/class/net/{name}/statistics/tx_bytes", "r") as f:
                        tx_bytes = int(f.read().strip())
                except Exception:
                    pass
        else:
            # Mock mode for Windows development
            is_running = bool(conn["is_active"])
            raw_output = f"# Mock Interface Status (Windows Dev)\ninterface: {name}\n  listening port: {conn['listen_port']}\n"
            for p in db_peers:
                peers_dict[p["client_public_key"]] = {
                    "public_key": p["client_public_key"],
                    "endpoint": "88.201.151.83:53513" if p.get("client_ip", "").endswith(".3") else "",
                    "allowed_ips": f"{p['client_ip']}/32",
                    "latest_handshake": "1 минуту назад" if p.get("client_ip", "").endswith(".3") else "—",
                    "transfer": "12.5 KiB received, 16.2 KiB sent" if p.get("client_ip", "").endswith(".3") else "",
                }

    # Merge peers with DB info
    peers_list = []
    seen_keys = set()
    for pub, pdata in peers_dict.items():
        seen_keys.add(pub)
        db_info = peer_db_map.get(pub, {})
        has_handshake = bool(pdata["latest_handshake"] and pdata["latest_handshake"] != "—" and "не" not in pdata["latest_handshake"].lower())
        peers_list.append({
            "public_key": pub,
            "username": db_info.get("username", "Неизвестный"),
            "device_label": db_info.get("label", "Устройство"),
            "client_ip": db_info.get("client_ip", pdata.get("allowed_ips", "")),
            "endpoint": pdata.get("endpoint", "") or "—",
            "latest_handshake": pdata.get("latest_handshake", "") or "Нет связи",
            "has_handshake": has_handshake,
            "transfer": pdata.get("transfer", "") or "0 B",
            "is_enabled": db_info.get("is_enabled", True),
        })

    # Add any DB peers not currently in awg show output
    for pub, db_info in peer_db_map.items():
        if pub not in seen_keys:
            peers_list.append({
                "public_key": pub,
                "username": db_info.get("username", "Неизвестный"),
                "device_label": db_info.get("label", "Устройство"),
                "client_ip": db_info.get("client_ip", ""),
                "endpoint": "—",
                "latest_handshake": "Нет связи",
                "has_handshake": False,
                "transfer": "0 B",
                "is_enabled": db_info.get("is_enabled", True),
            })

    peers_list.sort(key=lambda x: (not x["has_handshake"], x["username"]))

    return {
        "status": "active" if is_running else "stopped",
        "is_running": is_running,
        "name": name,
        "listen_port": conn["listen_port"],
        "x_subnet": conn["x_subnet"],
        "protocol_version": conn.get("protocol_version", "1.0"),
        "server_id": conn.get("server_id", 1),
        "server_name": server_name,
        "server_host": server_host,
        "table_num": conn.get("table_num", 101),
        "fwmark": conn.get("fwmark", 1),
        "xray_port": conn.get("xray_port", 7010),
        "rx_bytes": fmt_bytes(rx_bytes) if rx_bytes else "0 B",
        "tx_bytes": fmt_bytes(tx_bytes) if tx_bytes else "0 B",
        "peer_count": len(peers_list),
        "active_peers_count": sum(1 for p in peers_list if p["has_handshake"]),
        "peers": peers_list,
        "params": conn.get("params", {}),
        "raw_output": raw_output.strip(),
    }


def sync_connection_peers(conn_id: int) -> Tuple[bool, str]:
    """
    Updates the config file and hot-reloads peers into the active interface
    without dropping the tunnel.
    """
    conn = get_connection_by_id(conn_id)
    if not conn:
        return False, "Подключение не найдено"

    server = get_server_by_id(conn.get("server_id", 1))
    if server and server.get("host"):
        client = NodeClient(server)
        conf_text = generate_server_config_text(conn_id)
        mtu = int(get_setting("default_mtu", "1200"))
        res = client.sync_interface(
            name=conn["name"],
            config_text=conf_text,
            table_num=conn.get("table_num", 101),
            fwmark=conn.get("fwmark", 1),
            mtu=mtu,
            x_subnet=conn.get("x_subnet", 21),
            start=bool(conn.get("is_active", 1)),
        )
        if res.get("status") == "success":
            return True, "Конфигурация синхронизирована с нодой"

    conf_path = write_server_config(conn_id)
    name = conn["name"]

    if IS_LINUX and conn["is_active"]:
        cmd = f"awg syncconf {name} <(awg-quick strip {conf_path}) 2>/dev/null || wg syncconf {name} <(wg-quick strip {conf_path}) 2>/dev/null || true"
        try:
            subprocess.run(["bash", "-c", cmd], timeout=5)
            return True, "Пиры синхронизированы на лету"
        except Exception as e:
            return False, f"Ошибка синхронизации: {e}"

    return True, "Конфигурация сохранена"


def sync_peer_to_node(peer_id: int) -> Tuple[bool, str]:
    """Hot-adds or updates peer on target node without restarting tunnel."""
    peer = get_peer_by_id(peer_id)
    if not peer:
        return False, "Пир не найден"
    conn = get_connection_by_id(peer["connection_id"])
    if not conn:
        return False, "Подключение не найдено"

    server = get_server_by_id(conn.get("server_id", 1))
    if server and server.get("host"):
        client = NodeClient(server)
        res = client.sync_peer(
            interface=conn["name"],
            public_key=peer["client_public_key"],
            allowed_ips=f"{peer['client_ip']}/32",
            preshared_key=peer.get("preshared_key"),
            is_enabled=bool(peer.get("is_enabled", 1)),
        )
        if res.get("status") == "success":
            return True, res.get("message", "Пир синхронизирован")

    return sync_connection_peers(conn["id"])


def remove_peer_from_node(peer_id: int) -> Tuple[bool, str]:
    """Removes peer from target node."""
    peer = get_peer_by_id(peer_id)
    if not peer:
        return False, "Пир не найден"
    conn = get_connection_by_id(peer["connection_id"])
    if not conn:
        return False, "Подключение не найдено"

    server = get_server_by_id(conn.get("server_id", 1))
    if server and server.get("host"):
        client = NodeClient(server)
        res = client.remove_peer(
            interface=conn["name"],
            public_key=peer["client_public_key"],
        )
        if res.get("status") == "success":
            return True, res.get("message", "Пир удален с ноды")

    return sync_connection_peers(conn["id"])

