import os
import base64
from typing import Tuple
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization

def generate_key_pair() -> Tuple[str, str]:
    """
    Generates a standard WireGuard/AmneziaWG Curve25519 key pair (private_key, public_key)
    in base64 format.
    """
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()

    priv_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )
    pub_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

    priv_b64 = base64.b64encode(priv_bytes).decode("utf-8")
    pub_b64 = base64.b64encode(pub_bytes).decode("utf-8")

    return priv_b64, pub_b64

def generate_preshared_key() -> str:
    """
    Generates a 32-byte preshared key in base64 format.
    """
    random_bytes = os.urandom(32)
    return base64.b64encode(random_bytes).decode("utf-8")

def get_public_key_from_private(private_key_b64: str) -> str:
    """
    Derives public key from a given base64-encoded private key.
    """
    priv_bytes = base64.b64decode(private_key_b64)
    private_key = x25519.X25519PrivateKey.from_private_bytes(priv_bytes)
    public_key = private_key.public_key()
    pub_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    return base64.b64encode(pub_bytes).decode("utf-8")
