import os
import re
import shutil
import asyncio
import logging
import tempfile
from typing import Dict, List, Optional, Any, Tuple
from app.core.config import settings
from app.services.key_generator import get_public_key_from_private

logger = logging.getLogger(__name__)

AWG_OBFUSCATION_KEYS = [
    "Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4", "I1",
    "HeaderProtectionKey", "ContentPaddingAddition", "RekeyAfterTime",
    "RekeyTimeout", "RejectAfterTime", "KeepaliveTimeout", "MaxHandshakeAttempts",
    "RandomTrailers", "DisableCookies"
]

class AWGInterfaceConfig:
    def __init__(self, name: str, filepath: str):
        self.name = name
        self.filepath = filepath
        self.address: str = ""
        self.listen_port: int = 51820
        self.private_key: str = ""
        self.public_key: str = ""
        self.protocol_version: str = "v2.0"
        self.obfuscation_params: Dict[str, str] = {}
        self.post_up: List[str] = []
        self.post_down: List[str] = []
        self.raw_content: str = ""

class AWGService:
    def __init__(self, config_dir: Optional[str] = None):
        self.config_dir = config_dir or settings.AWG_CONFIG_DIR
        self._ensure_config_dir()

    def _ensure_config_dir(self):
        if not os.path.exists(self.config_dir):
            try:
                os.makedirs(self.config_dir, exist_ok=True)
            except Exception as e:
                logger.warning(f"Could not create config dir {self.config_dir}: {e}")

    def list_interface_files(self) -> List[str]:
        """
        Lists all .conf files in the AWG config directory.
        """
        if not os.path.exists(self.config_dir):
            return []
        files = []
        for f in os.listdir(self.config_dir):
            if f.endswith(".conf"):
                files.append(f)
        return sorted(files)

    def parse_interface_config(self, iface_name: str) -> Optional[AWGInterfaceConfig]:
        """
        Parses an AWG server interface configuration file (e.g. /etc/amnezia/amneziawg/awg1.conf).
        """
        clean_name = iface_name.replace(".conf", "")
        filepath = os.path.join(self.config_dir, f"{clean_name}.conf")
        if not os.path.exists(filepath):
            return None

        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()

        cfg = AWGInterfaceConfig(clean_name, filepath)
        cfg.raw_content = content

        in_interface = False
        for line in content.splitlines():
            line_str = line.strip()
            if not line_str or line_str.startswith("#"):
                continue

            if line_str.lower() == "[interface]":
                in_interface = True
                continue
            elif line_str.startswith("["):
                in_interface = False
                continue

            if in_interface and "=" in line_str:
                key, val = [x.strip() for x in line_str.split("=", 1)]
                key_lower = key.lower()

                if key_lower == "address":
                    cfg.address = val
                elif key_lower == "listenport":
                    try:
                        cfg.listen_port = int(val)
                    except ValueError:
                        pass
                elif key_lower == "privatekey":
                    cfg.private_key = val
                    try:
                        cfg.public_key = get_public_key_from_private(val)
                    except Exception as e:
                        logger.error(f"Failed to derive public key for {clean_name}: {e}")
                elif key_lower == "postup":
                    cfg.post_up.append(val)
                elif key_lower == "postdown":
                    cfg.post_down.append(val)
                else:
                    for obf_key in AWG_OBFUSCATION_KEYS:
                        if key.lower() == obf_key.lower():
                            cfg.obfuscation_params[obf_key] = val
                            break

        if "HeaderProtectionKey" in cfg.obfuscation_params or "ContentPaddingAddition" in cfg.obfuscation_params:
            cfg.protocol_version = "v3.1"
        else:
            cfg.protocol_version = "v2.0"

        return cfg

    async def get_interface_status(self, iface_name: str) -> Dict[str, Any]:
        """
        Checks if the interface is UP/DOWN and queries traffic and peers using `awg show <iface> dump`.
        """
        clean_name = iface_name.replace(".conf", "")
        status = {
            "name": clean_name,
            "is_active": False,
            "peers_count": 0,
            "peers_online": 0,
            "total_rx": 0,
            "total_tx": 0,
            "peers_data": {}
        }

        # Check if interface exists in ip link
        if shutil.which("ip"):
            try:
                proc = await asyncio.create_subprocess_exec(
                    "ip", "link", "show", clean_name,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, _ = await proc.communicate()
                if proc.returncode == 0:
                    status["is_active"] = True
            except (FileNotFoundError, Exception) as e:
                logger.debug(f"ip command failed: {e}")
        else:
            # Fallback for systems without 'ip' (e.g. dev machines)
            status["is_active"] = True

        # Try running `awg show <iface> dump` or `wg show <iface> dump`
        awg_cmd = "awg" if shutil.which("awg") else ("wg" if shutil.which("wg") else None)
        if awg_cmd and status["is_active"]:
            try:
                proc = await asyncio.create_subprocess_exec(
                    awg_cmd, "show", clean_name, "dump",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, _ = await proc.communicate()
                if proc.returncode == 0:
                    lines = stdout.decode().splitlines()
                    # First line is interface info: private-key, public-key, listen-port, fwmark
                    # Remaining lines are peers:
                    # public-key, preshared-key, endpoint, allowed-ips, latest-handshake, rx-bytes, tx-bytes, persistent-keepalive
                    for line in lines[1:]:
                        parts = line.strip().split("\t")
                        if len(parts) >= 7:
                            pub = parts[0]
                            endpoint = parts[2]
                            allowed_ips = parts[3]
                            try:
                                handshake = int(parts[4])
                                rx = int(parts[5])
                                tx = int(parts[6])
                            except ValueError:
                                handshake, rx, tx = 0, 0, 0

                            status["peers_count"] += 1
                            status["total_rx"] += rx
                            status["total_tx"] += tx

                            # If handshake occurred in last 3 minutes (180s), consider online
                            import time
                            is_online = (time.time() - handshake) < 180 and handshake > 0
                            if is_online:
                                status["peers_online"] += 1

                            status["peers_data"][pub] = {
                                "endpoint": endpoint,
                                "allowed_ips": allowed_ips,
                                "latest_handshake": handshake,
                                "rx_bytes": rx,
                                "tx_bytes": tx,
                                "is_online": is_online
                            }
            except Exception as e:
                logger.error(f"Error querying awg dump for {clean_name}: {e}")

        return status

    async def start_interface(self, iface_name: str) -> Tuple[bool, str]:
        """
        Starts the interface using `awg-quick up <iface>`.
        """
        clean_name = iface_name.replace(".conf", "")
        cmd = "awg-quick" if shutil.which("awg-quick") else ("wg-quick" if shutil.which("wg-quick") else None)
        if not cmd:
            return False, "Neither awg-quick nor wg-quick is installed on the system."

        proc = await asyncio.create_subprocess_exec(
            cmd, "up", clean_name,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await proc.communicate()
        if proc.returncode == 0:
            return True, f"Interface {clean_name} started successfully."
        else:
            return False, stderr.decode() or stdout.decode() or f"Failed with exit code {proc.returncode}"

    async def stop_interface(self, iface_name: str) -> Tuple[bool, str]:
        """
        Stops the interface using `awg-quick down <iface>`.
        """
        clean_name = iface_name.replace(".conf", "")
        cmd = "awg-quick" if shutil.which("awg-quick") else ("wg-quick" if shutil.which("wg-quick") else None)
        if not cmd:
            return False, "Neither awg-quick nor wg-quick is installed on the system."

        proc = await asyncio.create_subprocess_exec(
            cmd, "down", clean_name,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await proc.communicate()
        if proc.returncode == 0:
            return True, f"Interface {clean_name} stopped successfully."
        else:
            return False, stderr.decode() or stdout.decode() or f"Failed with exit code {proc.returncode}"

    def generate_client_config(
        self,
        iface_name: str,
        client_private_key: str,
        device_ip: str,
        server_public_ip: str,
        preshared_key: Optional[str] = None,
        custom_dns: Optional[str] = None
    ) -> str:
        """
        Generates client .conf content mirroring obfuscation settings from the server interface.
        """
        cfg = self.parse_interface_config(iface_name)
        if not cfg:
            raise ValueError(f"Interface configuration {iface_name} not found.")

        # Client DNS: preference order: custom_dns -> settings.DEFAULT_DNS -> interface gateway IP
        dns_ip = custom_dns or settings.DEFAULT_DNS
        if not dns_ip:
            # Extract server IP from interface address (e.g. '10.12.0.1/16' -> '10.12.0.1')
            dns_ip = cfg.address.split('/')[0].strip() or "1.1.1.1"

        lines = ["[Interface]"]
        lines.append(f"Address = {device_ip}/32")
        lines.append(f"PrivateKey = {client_private_key}")
        lines.append(f"DNS = {dns_ip}")

        # Mirror obfuscation parameters in Interface section
        for k, v in cfg.obfuscation_params.items():
            lines.append(f"{k} = {v}")

        lines.append("")
        lines.append("[Peer]")
        lines.append(f"PublicKey = {cfg.public_key}")
        if preshared_key and preshared_key.strip():
            lines.append(f"PresharedKey = {preshared_key.strip()}")
        lines.append(f"Endpoint = {server_public_ip}:{cfg.listen_port}")
        lines.append("AllowedIPs = 0.0.0.0/0, ::/0")
        lines.append("PersistentKeepalive = 25")
        lines.append("")

        return "\n".join(lines)

    async def add_peer(
        self,
        iface_name: str,
        public_key: str,
        device_ip: str,
        preshared_key: Optional[str] = None,
        user_comment: Optional[str] = None
    ):
        """
        Persists peer to /etc/amnezia/amneziawg/<iface>.conf and applies live via `awg set`.
        """
        clean_name = iface_name.replace(".conf", "")
        filepath = os.path.join(self.config_dir, f"{clean_name}.conf")
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Config file {filepath} does not exist.")

        # 1. Append peer to config file
        peer_block = ["\n"]
        if user_comment:
            peer_block.append(f"# Peer: {user_comment}\n")
        peer_block.append("[Peer]\n")
        peer_block.append(f"PublicKey = {public_key}\n")
        if preshared_key and preshared_key.strip():
            peer_block.append(f"PresharedKey = {preshared_key.strip()}\n")
        peer_block.append(f"AllowedIPs = {device_ip}/32\n")

        with open(filepath, "a", encoding="utf-8") as f:
            f.writelines(peer_block)

        # 2. Live hot-reload into running interface
        awg_cmd = "awg" if shutil.which("awg") else ("wg" if shutil.which("wg") else None)
        if awg_cmd:
            args = [awg_cmd, "set", clean_name, "peer", public_key, "allowed-ips", f"{device_ip}/32"]
            temp_psk_path = None
            if preshared_key and preshared_key.strip():
                with tempfile.NamedTemporaryFile("w", delete=False) as tf:
                    tf.write(preshared_key.strip())
                    temp_psk_path = tf.name
                args.extend(["preshared-key", temp_psk_path])

            try:
                proc = await asyncio.create_subprocess_exec(
                    *args,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                _, stderr = await proc.communicate()
                if proc.returncode != 0:
                    logger.warning(f"awg set returned code {proc.returncode}: {stderr.decode()}")
            except Exception as e:
                logger.warning(f"Failed to hot-add peer via awg set: {e}")
            finally:
                if temp_psk_path and os.path.exists(temp_psk_path):
                    os.remove(temp_psk_path)

    async def remove_peer(self, iface_name: str, public_key: str):
        """
        Removes peer from config file and live kernel interface.
        """
        clean_name = iface_name.replace(".conf", "")
        filepath = os.path.join(self.config_dir, f"{clean_name}.conf")
        if not os.path.exists(filepath):
            return

        # 1. Remove from config file
        with open(filepath, "r", encoding="utf-8") as f:
            lines = f.readlines()

        new_lines = []
        skip_peer = False
        i = 0
        while i < len(lines):
            line = lines[i]
            # Check for comment right before [Peer]
            if line.strip().startswith("# Peer:") and i + 1 < len(lines) and lines[i+1].strip().lower() == "[peer]":
                # Look ahead to see if this is the target peer
                j = i + 1
                is_target = False
                while j < len(lines) and not (lines[j].strip().startswith("[") and lines[j].strip().lower() != "[peer]"):
                    if lines[j].strip().startswith("PublicKey") and public_key in lines[j]:
                        is_target = True
                        break
                    if lines[j].strip().lower() == "[peer]" and j > i + 1:
                        break
                    j += 1
                if is_target:
                    # Skip comment and peer block
                    i += 1
                    while i < len(lines):
                        if lines[i].strip().startswith("[") and lines[i].strip().lower() != "[peer]":
                            break
                        if lines[i].strip().lower() == "[peer]":
                            break
                        i += 1
                    continue

            if line.strip().lower() == "[peer]":
                # Check if this peer block has our public key
                j = i + 1
                is_target = False
                while j < len(lines):
                    if lines[j].strip().startswith("["):
                        break
                    if lines[j].strip().startswith("PublicKey") and public_key in lines[j]:
                        is_target = True
                        break
                    j += 1

                if is_target:
                    # Skip until next section
                    i = j
                    while i < len(lines) and not lines[i].strip().startswith("["):
                        i += 1
                    continue

            new_lines.append(line)
            i += 1

        with open(filepath, "w", encoding="utf-8") as f:
            f.writelines(new_lines)

        # 2. Live remove from running interface
        awg_cmd = "awg" if shutil.which("awg") else ("wg" if shutil.which("wg") else None)
        if awg_cmd:
            try:
                proc = await asyncio.create_subprocess_exec(
                    awg_cmd, "set", clean_name, "peer", public_key, "remove",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                await proc.communicate()
            except Exception as e:
                logger.warning(f"Failed to hot-remove peer via awg set: {e}")

awg_service = AWGService()
