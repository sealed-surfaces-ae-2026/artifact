"""Deterministic encoding, framing, hashing, and derivation."""

from __future__ import annotations

import hashlib
import json
from typing import Any


def encode(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def pae(*pieces: bytes) -> bytes:
    out = bytearray(b"SS-PAE1")
    out.extend(len(pieces).to_bytes(4, "big"))
    for piece in pieces:
        out.extend(len(piece).to_bytes(8, "big"))
        out.extend(piece)
    return bytes(out)


def digest_bytes(domain: str, payload: bytes) -> dict[str, str]:
    return {"algorithm": "sha256", "value": hashlib.sha256(pae(domain.encode(), payload)).hexdigest()}


def digest_value(domain: str, value: Any) -> dict[str, str]:
    return digest_bytes(domain, encode(value))


def sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def derive(seed: int, label: str, length: int = 32) -> bytes:
    material = pae(b"sealed-surfaces/rq3-real/derive/v1", str(seed).encode(), label.encode())
    output = bytearray()
    counter = 0
    while len(output) < length:
        output.extend(hashlib.sha256(material + counter.to_bytes(4, "big")).digest())
        counter += 1
    return bytes(output[:length])
