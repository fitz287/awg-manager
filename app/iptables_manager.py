from typing import List, Tuple


def generate_xray_rules(
    interface_name: str,
    x_subnet: int,
    xray_port: int,
    table: int,
    mark: int,
) -> Tuple[List[str], List[str]]:
    """
    Generates exact PostUp and PostDown commands for Xray TProxy routing.
    Matches user's exact specification:
    # --- Таблица {table} для Xray (порт {xray_port}, метка {mark}) ---
    """
    post_up = [
        f"ip rule add fwmark {mark} table {table} || true",
        f"ip route add local 0.0.0.0/0 dev lo table {table} || true",
        f"iptables -t mangle -N XRAY_TPROXY_{mark} || true",
        f"iptables -t mangle -A XRAY_TPROXY_{mark} -d 10.{x_subnet}.0.0/24 -j RETURN",
        f"iptables -t mangle -A XRAY_TPROXY_{mark} -p tcp -j TPROXY --on-port {xray_port} --tproxy-mark {mark}/{mark}",
        f"iptables -t mangle -A XRAY_TPROXY_{mark} -p udp -j TPROXY --on-port {xray_port} --tproxy-mark {mark}/{mark}",
        f"iptables -t mangle -A PREROUTING -i {interface_name} -j XRAY_TPROXY_{mark} || true",
        f"iptables -t mangle -A POSTROUTING -p tcp --tcp-flags SYN,RST SYN -o {interface_name} -j TCPMSS --clamp-mss-to-pmtu || true",
    ]

    post_down = [
        f"iptables -t mangle -D POSTROUTING -p tcp --tcp-flags SYN,RST SYN -o {interface_name} -j TCPMSS --clamp-mss-to-pmtu || true",
        f"iptables -t mangle -D PREROUTING -i {interface_name} -j XRAY_TPROXY_{mark} || true",
        f"iptables -t mangle -F XRAY_TPROXY_{mark} || true",
        f"iptables -t mangle -X XRAY_TPROXY_{mark} || true",
        f"ip route del local 0.0.0.0/0 dev lo table {table} || true",
        f"ip rule del fwmark {mark} table {table} || true",
    ]

    return post_up, post_down


def format_wg_rules(
    interface_name: str,
    x_subnet: int,
    xray_port: int,
    table: int,
    mark: int,
) -> str:
    """Formats PostUp and PostDown lines as config string with comment."""
    post_up, post_down = generate_xray_rules(
        interface_name, x_subnet, xray_port, table, mark
    )

    lines = [f"# --- Таблица {table} для Xray (порт {xray_port}, метка {mark}) ---"]
    for cmd in post_up:
        lines.append(f"PostUp = {cmd}")
    for cmd in post_down:
        lines.append(f"PostDown = {cmd}")

    return "\n".join(lines)
