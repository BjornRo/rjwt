from datetime import timedelta
from typing import Any
from enum import Enum, auto

class HashAlgorithms(Enum):
    SHA256 = auto()
    SHA384 = auto()
    ES256 = auto()
    ES384 = auto()

class HMAC:
    def __init__(self, key: bytes) -> None:...
    def sign(self, timedelta: timedelta, custom_claims: dict[str, Any] | None = None) -> str:...
    def verify(self, token_str: str) -> None | dict[str, Any]:...

class ECDSA:
    def __init__(self, priv_pem: bytes, pub_pem: bytes, algorithm_type: HashAlgorithms) -> None:...
    def encode(self, timedelta: timedelta, custom_claims: dict[str, Any] | None = None) -> str:...
    def decode(self, token_str: str) -> None | dict[str, Any]:...