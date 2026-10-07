import base64
import os
import random
import secrets
from typing import Dict, Any, Tuple

try:
    from cryptography.hazmat.primitives.asymmetric import x25519
    from cryptography.hazmat.primitives import serialization
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False


def generate_keypair() -> Tuple[str, str]:
    """
    Generates a Curve25519 (WireGuard / AmneziaWG) keypair.
    Returns (private_key_b64, public_key_b64).
    """
    if HAS_CRYPTO:
        private_key = x25519.X25519PrivateKey.generate()
        private_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        public_bytes = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return (
            base64.b64encode(private_bytes).decode("utf-8"),
            base64.b64encode(public_bytes).decode("utf-8"),
        )
    else:
        # Fallback if cryptography not installed yet: random 32 bytes
        # Note: public key won't be mathematically derived without curve25519
        priv = secrets.token_bytes(32)
        pub = secrets.token_bytes(32)
        return (
            base64.b64encode(priv).decode("utf-8"),
            base64.b64encode(pub).decode("utf-8"),
        )


def generate_preshared_key() -> str:
    """Generates a 32-byte pre-shared key (base64 encoded)."""
    return base64.b64encode(secrets.token_bytes(32)).decode("utf-8")


def generate_header_protection_key() -> str:
    """
    Generates a 32-byte key for AWG 3.1 Header Protection (ChaCha20).
    Base64 encoded string.
    """
    return base64.b64encode(secrets.token_bytes(32)).decode("utf-8")


def generate_unique_headers(count: int = 4) -> list[int]:
    """
    Generates varied, unique 32-bit positive integers for H1..H4.
    Produces realistic values across different orders of magnitude
    (e.g., 563962, 4501776, 62264800, 765952538).
    """
    magnitudes = [
        (100_000, 999_999),          # 6-digit: e.g. 563962
        (1_000_000, 9_999_999),       # 7-digit: e.g. 4501776
        (10_000_000, 99_999_999),     # 8-digit: e.g. 62264800
        (100_000_000, 1_800_000_000), # 9-digit: e.g. 765952538
    ]
    random.shuffle(magnitudes)
    headers = []
    used = set()
    for i in range(count):
        low, high = magnitudes[i % len(magnitudes)]
        val = random.randint(low, high)
        while val in used:
            val = random.randint(low, high)
        used.add(val)
        headers.append(val)
    return headers


def generate_unique_s_params() -> Tuple[int, int, int, int]:
    """
    Generates distinct, varied junk sizes for S1..S4.
    S1, S2, S3 typically in range 25..110 bytes.
    S4 (data packet padding) in range 12..45 bytes (satisfies ChaCha20 nonce requirement >= 12).
    All 4 values are distinct.
    """
    s4 = random.randint(12, 45)
    pool = set()
    while len(pool) < 3:
        val = random.randint(25, 110)
        if val != s4:
            pool.add(val)
    s_list = list(pool)
    random.shuffle(s_list)
    return s_list[0], s_list[1], s_list[2], s4


def generate_awg_h_ranges() -> Tuple[str, str, str, str]:
    """
    Generates 4 disjoint non-overlapping uint32 ranges as in bivlked amneziawg-installer.
    Algorithm: 8 random numbers sorted into 4 pairs with >= 1000 span and strictly non-overlapping.
    """
    for _ in range(50):
        nums = sorted(secrets.randbelow(1_900_000_000) + 100_000 for _ in range(8))
        if (
            nums[0] >= 5
            and nums[1] - nums[0] >= 1000
            and nums[3] - nums[2] >= 1000
            and nums[5] - nums[4] >= 1000
            and nums[7] - nums[6] >= 1000
            and nums[2] > nums[1]
            and nums[4] > nums[3]
            and nums[6] > nums[5]
        ):
            return (
                f"{nums[0]}-{nums[1]}",
                f"{nums[2]}-{nums[3]}",
                f"{nums[4]}-{nums[5]}",
                f"{nums[6]}-{nums[7]}",
            )
    return (
        "1776002204-1856261239",
        "2131483220-2139616315",
        "2145540006-2146234083",
        "2146328963-2146998719",
    )


def generate_cps_dns_i1() -> str:
    """
    Generates DNS-shaped CPS concealment string for I1 conforming to bivlked amneziawg-installer:
    Mimics Apple iCloud DNS query response pattern for active probing bypass.
    """
    return "<r 2><b 0x858000010001000000000669636c6f756403636f6d0000010001c00c000100010000105a00044d583737>"


def generate_bivlked_mobile_params(protocol_version: str) -> Dict[str, Any]:
    """
    Generates AmneziaWG obfuscation parameters corresponding to
    bivlked/amneziawg-installer with --mobile flag:
    - Jc = 3 (fixed: Tele2, Yota, Megafon, MTS >95% pass rate)
    - Jmin = 30..50
    - Jmax = Jmin + 20..80 (narrow junk window avoids DPI fragmentation & drop)
    - S1 = 15..150
    - S2 = 15..150 (ensuring S1 + 56 != S2)
    - S3 = 12..55 (for 3.1) or 8..55 (for 2.0) (ensuring S2 + 28 != S3)
    - S4 = 12..27 (for 3.1) or 4..27 (for 2.0)
    - H1..H4: 1, 2, 3, 4 for AWG 3.1; 4 non-overlapping ranges for AWG 2.0
    - I1: DNS-shaped CPS packet
    - AWG 3.1: HeaderProtectionKey, ContentPaddingAddition 32-128, RandomTrailers on, safe timers
    """
    version = protocol_version.strip().lower()
    jc = 3
    jmin = random.randint(30, 50)
    jmax = jmin + random.randint(20, 80)

    s1 = random.randint(15, 150)
    s2 = random.randint(15, 150)
    while s1 + 56 == s2:
        s2 = random.randint(15, 150)

    is_v3 = version in ("3.1", "3.0", "awg 3.1", "awg 3.0", "v3", "3")
    is_v2 = version in ("2.0", "awg 2.0", "v2", "2")

    s3_min = 12 if is_v3 else 8
    s4_min = 12 if is_v3 else 4

    s3 = random.randint(s3_min, 55)
    while s2 + 28 == s3:
        s3 = random.randint(s3_min, 55)

    s4 = random.randint(s4_min, 27)

    params: Dict[str, Any] = {
        "Jc": jc,
        "Jmin": jmin,
        "Jmax": jmax,
        "S1": s1,
        "S2": s2,
    }

    if is_v3:
        params["protocol_version"] = "3.1"
        params["S3"] = s3
        params["S4"] = s4
        params["H1"] = 1
        params["H2"] = 2
        params["H3"] = 3
        params["H4"] = 4
        params["HeaderProtectionKey"] = generate_header_protection_key()
        cpa_min = random.randint(32, 48)
        cpa_max = random.randint(70, 128)
        params["ContentPaddingAddition"] = f"{cpa_min}-{cpa_max}"
        params["RandomTrailers"] = 1
        params["RekeyAfterTime"] = "100-120"
        params["RekeyTimeout"] = "3-7"
        params["RejectAfterTime"] = "150-180"
        params["KeepaliveTimeout"] = "5-15"
        params["MaxHandshakeAttempts"] = "15-20"
        params["I1"] = generate_cps_dns_i1()
    elif is_v2:
        params["protocol_version"] = "2.0"
        params["S3"] = s3
        params["S4"] = s4
        h1, h2, h3, h4 = generate_awg_h_ranges()
        params["H1"] = h1
        params["H2"] = h2
        params["H3"] = h3
        params["H4"] = h4
        params["I1"] = generate_cps_dns_i1()
    else:
        params["protocol_version"] = "1.0"
        h = generate_unique_headers(4)
        params["H1"] = h[0]
        params["H2"] = h[1]
        params["H3"] = h[2]
        params["H4"] = h[3]

    return params


def generate_awg_params(protocol_version: str, preset: str = "default") -> Dict[str, Any]:
    """
    Generates protocol-specific parameters for AWG 1.0, 2.0, 3.1
    with realistic, complex obfuscation parameters.
    Supports preset='default' or preset='mobile' (as in bivlked amneziawg-installer --mobile).
    """
    if str(preset).strip().lower() == "mobile":
        return generate_bivlked_mobile_params(protocol_version)

    version = protocol_version.strip().lower()

    if version in ("1.0", "awg 1.0", "v1", "1"):
        h = generate_unique_headers(4)
        s1, s2, _, _ = generate_unique_s_params()
        return {
            "protocol_version": "1.0",
            "Jc": random.randint(3, 6),
            "Jmin": random.randint(40, 60),
            "Jmax": random.randint(850, 1100),
            "S1": s1,
            "S2": s2,
            "H1": h[0],
            "H2": h[1],
            "H3": h[2],
            "H4": h[3],
        }

    elif version in ("2.0", "awg 2.0", "v2", "2"):
        s1, s2, s3, s4 = generate_unique_s_params()
        h1, h2, h3, h4 = generate_awg_h_ranges()
        return {
            "protocol_version": "2.0",
            "Jc": random.randint(3, 6),
            "Jmin": random.randint(40, 60),
            "Jmax": random.randint(850, 1100),
            "S1": s1,
            "S2": s2,
            "S3": s3,
            "S4": s4,
            "H1": h1,
            "H2": h2,
            "H3": h3,
            "H4": h4,
            "I1": generate_cps_dns_i1(),
        }

    elif version in ("3.1", "3.0", "awg 3.1", "awg 3.0", "v3", "3"):
        s1, s2, s3, s4 = generate_unique_s_params()
        h = generate_unique_headers(4)
        hpk = generate_header_protection_key()
        pad_min = random.randint(10, 25)
        pad_max = random.randint(60, 110)
        return {
            "protocol_version": "3.1",
            "HeaderProtectionKey": hpk,
            "ContentPaddingAddition": f"{pad_min}-{pad_max}",
            "RandomTrailers": 1,
            "RekeyAfterTime": "100-120",
            "RekeyTimeout": "3-7",
            "RejectAfterTime": "150-180",
            "KeepaliveTimeout": "5-15",
            "MaxHandshakeAttempts": "15-20",
            "Jc": random.randint(4, 6),
            "Jmin": random.randint(40, 60),
            "Jmax": random.randint(850, 1100),
            "S1": s1,
            "S2": s2,
            "S3": s3,
            "S4": s4,
            "H1": h[0],
            "H2": h[1],
            "H3": h[2],
            "H4": h[3],
            "I1": generate_cps_dns_i1(),
        }

    else:
        # Default fallback to 1.0
        return generate_awg_params("1.0", preset=preset)


def encode_amnezia_vpn_url(vpn_dict: Dict[str, Any]) -> str:
    """
    Encodes an Amnezia VPN container JSON config into a vpn:// URL
    using Qt qCompress (4-byte big-endian uncompressed length + zlib deflate)
    and URL-safe Base64 without trailing padding.
    """
    import json
    import struct
    import zlib

    json_bytes = json.dumps(vpn_dict, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    compressed = zlib.compress(json_bytes, 8)
    header = struct.pack(">I", len(json_bytes))
    data = header + compressed
    b64 = base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")
    return f"vpn://{b64}"


def decode_amnezia_vpn_url(vpn_url: str) -> Dict[str, Any]:
    """Decodes a vpn:// URL back into its container JSON dictionary."""
    import json
    import zlib

    raw_b64 = vpn_url.strip()
    if raw_b64.startswith("vpn://"):
        raw_b64 = raw_b64[6:]
    pad = len(raw_b64) % 4
    if pad:
        raw_b64 += "=" * (4 - pad)
    data = base64.urlsafe_b64decode(raw_b64)
    # First 4 bytes are uncompressed length, remainder is zlib deflate
    decompressed = zlib.decompress(data[4:])
    return json.loads(decompressed.decode("utf-8"))


