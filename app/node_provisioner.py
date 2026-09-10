"""
AmneziaWG Node Provisioner
Handles automated SSH installation, configuration, and agent deployment on remote VPS nodes.
"""

import io
import json
import logging
import os
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, Optional

import paramiko

from app.database import (
    append_server_install_log,
    get_server_by_id,
    update_server_status,
    update_server_system_info,
)

logger = logging.getLogger("node_provisioner")


def run_ssh_command(
    ssh: paramiko.SSHClient,
    command: str,
    log_cb: Optional[Callable[[str], None]] = None,
    timeout: int = 300,
) -> int:
    """Executes a command over SSH and streams lines to log_cb."""
    if log_cb:
        log_cb(f"> {command}")

    stdin, stdout, stderr = ssh.exec_command(command, timeout=timeout)
    # Channel combined read
    channel = stdout.channel

    while not channel.exit_status_ready() or channel.recv_ready() or channel.recv_stderr_ready():
        if channel.recv_ready():
            chunk = channel.recv(4096).decode("utf-8", errors="replace")
            for line in chunk.splitlines():
                if log_cb and line.strip():
                    log_cb(f"  {line}")
        if channel.recv_stderr_ready():
            chunk_err = channel.recv_stderr(4096).decode("utf-8", errors="replace")
            for line in chunk_err.splitlines():
                if log_cb and line.strip():
                    log_cb(f"  [err] {line}")
        time.sleep(0.1)

    return channel.recv_exit_status()


def provision_node_task(server_id: int) -> None:
    """Worker function to provision a node over SSH."""
    server = get_server_by_id(server_id)
    if not server:
        logger.error(f"Server ID {server_id} not found for provisioning")
        return

    update_server_status(server_id, "installing")

    def log(msg: str):
        try:
            print(f"[Node {server_id}] {msg}")
        except Exception:
            pass
        logger.info(f"[Node {server_id}] {msg}")
        append_server_install_log(server_id, msg)

    log(f"=== Начало развёртывания ноды: {server['name']} ({server['host']}:{server['ssh_port']}) ===")

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        # 1. Connect
        log(f"Подключение по SSH к {server['host']}:{server['ssh_port']} под пользователем {server['ssh_user']}...")
        connect_kwargs = {
            "hostname": server["host"],
            "port": server["ssh_port"],
            "username": server["ssh_user"],
            "timeout": 15,
        }
        if server.get("ssh_password"):
            connect_kwargs["password"] = server["ssh_password"]
        elif server.get("ssh_key"):
            key_file = io.StringIO(server["ssh_key"])
            try:
                pkey = paramiko.RSAKey.from_private_key(key_file)
            except Exception:
                key_file.seek(0)
                pkey = paramiko.Ed25519Key.from_private_key(key_file)
            connect_kwargs["pkey"] = pkey

        ssh.connect(**connect_kwargs)
        log("✓ SSH соединение успешно установлено!")

        # 2. Check OS
        log("Определение операционной системы...")
        stdin, stdout, stderr = ssh.exec_command("cat /etc/os-release")
        os_info = stdout.read().decode("utf-8", errors="replace")
        log(f"Информация об ОС:\n{os_info.strip()}")

        # 3. Prerequisites
        log("Проверка и установка базовых пакетов (curl, python3, iptables, iproute2, dkms)...")
        prep_cmd = (
            "export DEBIAN_FRONTEND=noninteractive; "
            "apt-get update -q && "
            "apt-get install -y -q curl gnupg software-properties-common iptables iproute2 "
            "python3 python3-pip python3-venv qrencode dkms"
        )
        code = run_ssh_command(ssh, prep_cmd, log_cb=log, timeout=300)
        if code != 0:
            log("⚠ Предупреждение: apt-get вернул ненулевой код, продолжаем...")

        # 4. AmneziaWG
        log("Проверка наличия AmneziaWG в системе...")
        stdin, stdout, _ = ssh.exec_command("which awg")
        has_awg = stdout.read().decode().strip()
        if not has_awg:
            log("AmneziaWG не найден. Подключение репозитория ppa:amnezia/ppa и установка...")
            awg_install_cmd = (
                "export DEBIAN_FRONTEND=noninteractive; "
                "add-apt-repository -y ppa:amnezia/ppa && "
                "apt-get update -q && "
                "apt-get install -y -q amneziawg amneziawg-tools amneziawg-dkms"
            )
            code = run_ssh_command(ssh, awg_install_cmd, log_cb=log, timeout=300)
            if code != 0:
                raise RuntimeError(f"Ошибка установки AmneziaWG пакетов (код {code})")
        else:
            log(f"✓ AmneziaWG уже установлен: {has_awg}")

        # Ensure directory
        run_ssh_command(ssh, "mkdir -p /etc/amnezia/amneziawg", log_cb=log)

        # 5. Enable IP Forwarding
        log("Включение пересылки пакетов (IPv4 Forwarding)...")
        sysctl_cmd = (
            "echo 'net.ipv4.ip_forward = 1' > /etc/sysctl.d/99-amnezia.conf && "
            "sysctl -p /etc/sysctl.d/99-amnezia.conf"
        )
        run_ssh_command(ssh, sysctl_cmd, log_cb=log)

        # 6. Deploy Node Agent
        log("Развёртывание агента ноды в /opt/awg-node...")
        run_ssh_command(ssh, "mkdir -p /opt/awg-node", log_cb=log)

        # Virtualenv
        stdin, stdout, _ = ssh.exec_command("test -f /opt/awg-node/venv/bin/python && echo 1 || echo 0")
        has_venv = stdout.read().decode().strip() == "1"
        if not has_venv:
            log("Создание виртуального окружения Python /opt/awg-node/venv...")
            run_ssh_command(ssh, "python3 -m venv /opt/awg-node/venv", log_cb=log)

        log("Установка зависимостей агента (fastapi, uvicorn, pydantic, httpx)...")
        pip_cmd = "/opt/awg-node/venv/bin/pip install --upgrade pip fastapi uvicorn pydantic httpx"
        run_ssh_command(ssh, pip_cmd, log_cb=log, timeout=180)

        # Upload agent script and config via SFTP
        log("Загрузка файлов агента...")
        sftp = ssh.open_sftp()

        # Read local node_agent.py
        local_agent_path = Path(__file__).parent / "node_agent.py"
        with open(local_agent_path, "r", encoding="utf-8") as f:
            agent_code = f.read()

        agent_remote = sftp.file("/opt/awg-node/agent.py", "w")
        agent_remote.write(agent_code)
        agent_remote.close()

        # Write config.json
        agent_cfg = {
            "api_token": server["api_token"],
            "port": server["api_port"],
            "host": "0.0.0.0",
        }
        cfg_remote = sftp.file("/opt/awg-node/config.json", "w")
        cfg_remote.write(json.dumps(agent_cfg, indent=2))
        cfg_remote.close()

        # Create systemd service
        service_unit = f"""[Unit]
Description=AmneziaWG Node Agent
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/awg-node
ExecStart=/opt/awg-node/venv/bin/python3 /opt/awg-node/agent.py
Restart=always
RestartSec=5
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
"""
        svc_remote = sftp.file("/etc/systemd/system/awg-node.service", "w")
        svc_remote.write(service_unit)
        svc_remote.close()
        sftp.close()

        log("Перезапуск и включение сервиса awg-node.service...")
        run_ssh_command(ssh, "systemctl daemon-reload && systemctl enable --now awg-node.service && systemctl restart awg-node.service", log_cb=log)

        # 7. Healthcheck
        log(f"Проверка отклика агента на порту {server['api_port']}...")
        time.sleep(2)
        hc_cmd = f"curl -s http://127.0.0.1:{server['api_port']}/api/agent/health"
        stdin, stdout, _ = ssh.exec_command(hc_cmd)
        hc_res = stdout.read().decode().strip()
        log(f"Ответ healthcheck: {hc_res}")

        if "ok" in hc_res:
            log("✓ Агент ноды успешно запущен и работает корректно!")
            log(f"=== Развёртывание ноды {server['name']} завершено успешно! ===")
            update_server_status(server_id, "online")
        else:
            log("⚠ Агент не ответил ожидаемым статусом, проверьте логи systemctl status awg-node")
            update_server_status(server_id, "error")

    except Exception as e:
        log(f"❌ Ошибка развёртывания ноды: {e}")
        logger.exception("Provisioning failed")
        update_server_status(server_id, "error")
    finally:
        try:
            ssh.close()
        except Exception:
            pass


def start_provisioning(server_id: int) -> threading.Thread:
    """Spawns provisioning in a background thread."""
    t = threading.Thread(target=provision_node_task, args=(server_id,), daemon=True)
    t.start()
    return t
