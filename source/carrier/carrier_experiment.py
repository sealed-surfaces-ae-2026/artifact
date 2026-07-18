from __future__ import annotations

import argparse
import csv
import hashlib
import importlib.metadata
import io
import json
import math
import platform
import statistics
import struct
import sys
import time
import zlib
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

import cv2
import numpy as np
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from PIL import Image
from reedsolo import RSCodec, ReedSolomonError
import qrcode.base
import qrcode.constants
import zxingcpp


SEED = 20260718
CAPTURE_PX = 1600
FIELD_MM = 200.0
PX_PER_MM = CAPTURE_PX / FIELD_MM
EQUAL_AREA_BOX_PX = 1200
EQUAL_MODULE_PX = 4
MIN_EQUAL_AREA_MODULE_PX = 2
DECODE_BUDGET_MS = 2000.0
CUSTOM_DATA_BYTES = 96
MOSAIC_K = 6
MOSAIC_N = 9
RECTIFIED_MODULE_PX = 5

PAYLOADS = {"small": 512, "medium": 1536, "large": 4096}
QR_EC = {"qr_L": "L", "qr_M": "M", "qr_Q": "Q", "qr_H": "H"}
ARM_ORDER = ["qr_L", "qr_M", "qr_Q", "qr_H", "data_matrix", "aztec", "custom_grid", "mosaic_outer_rs"]


@dataclass
class Carrier:
    arm: str
    logical: np.ndarray
    scan_size: int
    envelope: bytes
    native_ecc: str
    protected_redundancy_ratio: float
    structure_data_independent: bool
    meta: dict[str, Any] = field(default_factory=dict)

    @property
    def logical_size(self) -> int:
        return int(self.logical.shape[0])


@dataclass
class DecodeResult:
    output: bytes | None = None
    structure_recovered: bool = False
    data_recovered: bool = False
    diagnostic_accuracy: float | None = None
    localization_ms: float = 0.0
    symbol_decode_ms: float = 0.0
    ecc_ms: float = 0.0
    notes: list[str] = field(default_factory=list)


def deterministic_payload(size: int, label: str) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < size:
        out.extend(hashlib.sha512(f"sealed-surfaces:{label}:{counter}".encode()).digest())
        counter += 1
    return bytes(out[:size])


def fixed_private_key() -> Ed25519PrivateKey:
    seed = hashlib.sha256(b"sealed-surfaces appendix-a spike key 2026-07-18").digest()
    return Ed25519PrivateKey.from_private_bytes(seed)


PRIVATE_KEY = fixed_private_key()
PUBLIC_KEY = PRIVATE_KEY.public_key()


def sign_envelope(payload: bytes) -> bytes:
    body = struct.pack(">4sI", b"SEV1", len(payload)) + payload
    return body + PRIVATE_KEY.sign(body)


def authenticate_envelope(envelope: bytes | None) -> tuple[bool, bytes | None]:
    if envelope is None or len(envelope) < 8 + 64:
        return False, None
    body, signature = envelope[:-64], envelope[-64:]
    try:
        magic, payload_len = struct.unpack(">4sI", body[:8])
        if magic != b"SEV1" or payload_len != len(body) - 8:
            return False, None
        PUBLIC_KEY.verify(signature, body)
        return True, body[8:]
    except (ValueError, InvalidSignature, struct.error):
        return False, None


def zxing_matrix(data: bytes, fmt: Any, ec_level: Any | None = None) -> tuple[np.ndarray, str]:
    kwargs: dict[str, Any] = {}
    if ec_level is not None:
        kwargs["ec_level"] = ec_level
    barcode = zxingcpp.create_barcode(data, fmt, **kwargs)
    image = zxingcpp.write_barcode_to_image(barcode, scale=1, add_quiet_zones=True)
    arr = np.asarray(image)
    if arr.ndim == 3:
        arr = arr[:, :, 0]
    matrix = arr < 128
    check = zxingcpp.read_barcode(arr, formats=fmt, text_mode=zxingcpp.TextMode.Plain)
    native = check.ec_level if check is not None else "library-default"
    return matrix.astype(np.uint8), native


def wrap_registered(content: np.ndarray) -> tuple[np.ndarray, int, int, int]:
    """Square-pad content, then add separator, connected registration frame, quiet zone."""
    h, w = content.shape
    side = max(h, w)
    frame, separator, quiet = 2, 2, 4
    scan_size = side + 2 * (frame + separator)
    full_size = scan_size + 2 * quiet
    full = np.zeros((full_size, full_size), dtype=np.uint8)
    frame_lo = quiet
    frame_hi = quiet + scan_size
    full[frame_lo:frame_lo + frame, frame_lo:frame_hi] = 1
    full[frame_hi - frame:frame_hi, frame_lo:frame_hi] = 1
    full[frame_lo:frame_hi, frame_lo:frame_lo + frame] = 1
    full[frame_lo:frame_hi, frame_hi - frame:frame_hi] = 1
    content_y = quiet + frame + separator + (side - h) // 2
    content_x = quiet + frame + separator + (side - w) // 2
    full[content_y:content_y + h, content_x:content_x + w] = content
    scan_content_y = content_y - quiet
    scan_content_x = content_x - quiet
    return full, scan_size, scan_content_y, scan_content_x


def build_standard(arm: str, envelope: bytes) -> Carrier:
    if arm in QR_EC:
        content, native = zxing_matrix(envelope, zxingcpp.BarcodeFormat.QRCode, QR_EC[arm])
        ecc = f"QR-{QR_EC[arm]} (decoder reports {native})"
    elif arm == "data_matrix":
        content, native = zxing_matrix(envelope, zxingcpp.BarcodeFormat.DataMatrix)
        ecc = f"Data Matrix ECC200 ({native or 'fixed'})"
    elif arm == "aztec":
        content, native = zxing_matrix(envelope, zxingcpp.BarcodeFormat.Aztec, 23)
        ecc = f"Aztec requested 23% ({native})"
    else:
        raise ValueError(arm)
    logical, scan_size, cy, cx = wrap_registered(content)
    return Carrier(
        arm=arm,
        logical=logical,
        scan_size=scan_size,
        envelope=envelope,
        native_ecc=ecc,
        protected_redundancy_ratio=float("nan"),
        structure_data_independent=False,
        meta={"content_rect": [cy, cx, content.shape[0], content.shape[1]]},
    )


def bytes_to_bits(data: bytes) -> np.ndarray:
    return np.unpackbits(np.frombuffer(data, dtype=np.uint8), bitorder="big")


def build_custom(envelope: bytes) -> Carrier:
    # Combine the baseline's outer erasure ratio with its native QR-M
    # codeword redundancy, then match that total coding ratio here.
    baseline_reference = build_mosaic(envelope)
    target_ratio = baseline_reference.protected_redundancy_ratio
    parity_bytes = round(CUSTOM_DATA_BYTES * target_ratio)
    if CUSTOM_DATA_BYTES + parity_bytes > 255:
        raise ValueError("matched custom RS block exceeds GF(256) codeword limit")
    header = struct.pack(">4sI32s", b"CG01", len(envelope), hashlib.sha256(envelope).digest())
    raw = header + envelope
    chunks = math.ceil(len(raw) / CUSTOM_DATA_BYTES)
    padded = raw + bytes(chunks * CUSTOM_DATA_BYTES - len(raw))
    rsc = RSCodec(parity_bytes)
    blocks = [bytes(rsc.encode(padded[i:i + CUSTOM_DATA_BYTES])) for i in range(0, len(padded), CUSTOM_DATA_BYTES)]
    codeword = b"".join(blocks)
    bits = bytes_to_bits(codeword)
    side = math.ceil(math.sqrt(len(bits)))
    core = np.zeros((side + 2, side + 2), dtype=np.uint8)
    core[0, :] = np.arange(side + 2) % 2
    core[:, 0] = np.arange(side + 2) % 2
    core[-1, :] = 1
    core[:, -1] = 1
    padded_bits = np.zeros(side * side, dtype=np.uint8)
    padded_bits[:len(bits)] = bits
    core[1:1 + side, 1:1 + side] = padded_bits.reshape(side, side)
    logical, scan_size, cy, cx = wrap_registered(core)
    parity = chunks * parity_bytes
    return Carrier(
        arm="custom_grid",
        logical=logical,
        scan_size=scan_size,
        envelope=envelope,
        native_ecc=f"RS({CUSTOM_DATA_BYTES + parity_bytes},{CUSTOM_DATA_BYTES}) per block",
        protected_redundancy_ratio=parity / (chunks * CUSTOM_DATA_BYTES),
        structure_data_independent=True,
        meta={
            "data_origin": [cy + 1, cx + 1],
            "data_side": side,
            "bit_length": len(codeword) * 8,
            "codeword": codeword,
            "chunks": chunks,
            "data_bytes_per_block": CUSTOM_DATA_BYTES,
            "parity_bytes_per_block": parity_bytes,
            "matched_baseline_coding_ratio": target_ratio,
        },
    )


MANIFEST_STRUCT = struct.Struct(">4s32sIHHHHH")
FRAGMENT_STRUCT = struct.Struct(">4sHBBH")


def build_mosaic(envelope: bytes) -> Carrier:
    k, n = MOSAIC_K, MOSAIC_N
    shard_size = math.ceil(len(envelope) / k)
    padded = envelope + bytes(k * shard_size - len(envelope))
    data_shards = [padded[i * shard_size:(i + 1) * shard_size] for i in range(k)]
    rows = cols = 3
    manifest_body = MANIFEST_STRUCT.pack(
        b"SMF1", hashlib.sha256(envelope).digest(), len(envelope), k, n, shard_size, rows, cols
    )
    manifest = manifest_body + PRIVATE_KEY.sign(manifest_body)
    rsc = RSCodec(n - k)
    all_shards = [bytearray(shard_size) for _ in range(n)]
    for pos in range(shard_size):
        stripe = bytes(data_shards[i][pos] for i in range(k))
        encoded = rsc.encode(stripe)
        for i in range(n):
            all_shards[i][pos] = encoded[i]
    fragments: list[bytes] = []
    tiles: list[np.ndarray] = []
    native_levels: list[str] = []
    for i, shard in enumerate(all_shards):
        row, col = divmod(i, cols)
        body = FRAGMENT_STRUCT.pack(b"SFR1", i, row, col, len(manifest)) + manifest + bytes(shard)
        fragment = body + struct.pack(">I", zlib.crc32(body))
        tile, native = zxing_matrix(fragment, zxingcpp.BarcodeFormat.QRCode, "M")
        fragments.append(fragment)
        tiles.append(tile)
        native_levels.append(native)
    tile_version = (tiles[0].shape[0] - 25) // 4
    qr_blocks = qrcode.base.rs_blocks(tile_version, qrcode.constants.ERROR_CORRECT_M)
    qr_total_codewords = sum(block.total_count for block in qr_blocks)
    qr_data_codewords = sum(block.data_count for block in qr_blocks)
    inner_codeword_ratio = qr_total_codewords / qr_data_codewords
    combined_coding_redundancy = (n / k) * inner_codeword_ratio - 1.0
    tile_h = max(x.shape[0] for x in tiles)
    tile_w = max(x.shape[1] for x in tiles)
    gap = 4
    mosaic = np.zeros((rows * tile_h + (rows - 1) * gap, cols * tile_w + (cols - 1) * gap), dtype=np.uint8)
    local_rects = []
    for i, tile in enumerate(tiles):
        row, col = divmod(i, cols)
        y = row * (tile_h + gap) + (tile_h - tile.shape[0]) // 2
        x = col * (tile_w + gap) + (tile_w - tile.shape[1]) // 2
        mosaic[y:y + tile.shape[0], x:x + tile.shape[1]] = tile
        local_rects.append([y, x, tile.shape[0], tile.shape[1]])
    logical, scan_size, cy, cx = wrap_registered(mosaic)
    rects = [[cy + y, cx + x, h, w] for y, x, h, w in local_rects]
    return Carrier(
        arm="mosaic_outer_rs",
        logical=logical,
        scan_size=scan_size,
        envelope=envelope,
        native_ecc=f"QR-M inner ({'/'.join(sorted(set(native_levels)))}) + RS({n},{k}) outer",
        protected_redundancy_ratio=combined_coding_redundancy,
        structure_data_independent=True,
        meta={
            "k": k,
            "n": n,
            "shard_size": shard_size,
            "rows": rows,
            "cols": cols,
            "manifest": manifest,
            "fragments": fragments,
            "tile_rects": rects,
            "outer_redundancy_ratio": (n - k) / k,
            "qr_inner_redundancy_ratio": inner_codeword_ratio - 1.0,
            "combined_coding_redundancy_ratio": combined_coding_redundancy,
        },
    )


def build_carrier(arm: str, envelope: bytes) -> Carrier:
    if arm == "custom_grid":
        return build_custom(envelope)
    if arm == "mosaic_outer_rs":
        return build_mosaic(envelope)
    return build_standard(arm, envelope)


def render_capture(carrier: Carrier, experiment: str) -> tuple[np.ndarray | None, dict[str, Any]]:
    n = carrier.logical_size
    if experiment == "equal_area":
        module_px = EQUAL_AREA_BOX_PX // n
        geometry_ok = module_px >= MIN_EQUAL_AREA_MODULE_PX
        allocated_box_px = EQUAL_AREA_BOX_PX
        actual_px = EQUAL_AREA_BOX_PX if geometry_ok else 0
    elif experiment == "equal_module":
        module_px = EQUAL_MODULE_PX
        geometry_ok = n * module_px <= CAPTURE_PX
        allocated_box_px = n * module_px
        actual_px = n * module_px if geometry_ok else 0
    else:
        raise ValueError(experiment)
    allocated_area_mm2 = (allocated_box_px / PX_PER_MM) ** 2 if geometry_ok else 0.0
    symbol_area_mm2 = (actual_px / PX_PER_MM) ** 2 if geometry_ok else 0.0
    info = {
        "geometry_ok": geometry_ok,
        "module_px": module_px,
        "min_module_mm": module_px / PX_PER_MM if geometry_ok else 0.0,
        "allocated_area_mm2": allocated_area_mm2,
        "symbol_area_mm2": symbol_area_mm2,
        "artifact_px": actual_px,
    }
    if not geometry_ok:
        return None, info
    raster = np.where(carrier.logical != 0, 0, 255).astype(np.uint8)
    raster = cv2.resize(raster, (actual_px, actual_px), interpolation=cv2.INTER_NEAREST)
    rgb = cv2.cvtColor(raster, cv2.COLOR_GRAY2RGB)
    canvas = np.full((CAPTURE_PX, CAPTURE_PX, 3), 255, dtype=np.uint8)
    y = (CAPTURE_PX - actual_px) // 2
    x = (CAPTURE_PX - actual_px) // 2
    canvas[y:y + actual_px, x:x + actual_px] = rgb
    return canvas, info


def jpeg_roundtrip(image: np.ndarray, quality: int) -> np.ndarray:
    buf = io.BytesIO()
    Image.fromarray(image).save(buf, format="JPEG", quality=quality, subsampling=2)
    buf.seek(0)
    return np.asarray(Image.open(buf).convert("RGB"))


def channel_specs() -> list[tuple[str, str, dict[str, Any]]]:
    specs: list[tuple[str, str, dict[str, Any]]] = [("identity", "identity", {})]
    specs += [("jpeg", f"jpeg_q{q}", {"quality": q}) for q in (95, 80, 65, 50, 30)]
    specs += [("scale", f"scale_{p}", {"percent": p}) for p in (100, 75, 50, 25)]
    for angle in (0, 15, 30):
        for light, factor in (("dark", 0.62), ("normal", 1.0), ("bright", 1.35)):
            specs.append(("photo_recompress", f"photo_a{angle}_{light}_q50", {"angle": angle, "light": factor}))
    specs += [("grayscale", "grayscale", {})]
    specs += [
        ("colorspace_gamma", "gamma_070", {"gamma": 0.70}),
        ("colorspace_gamma", "gamma_140", {"gamma": 1.40}),
        ("colorspace_gamma", "warm_tint", {"tint": (1.08, 1.0, 0.86)}),
        ("colorspace_gamma", "cool_tint", {"tint": (0.86, 1.0, 1.08)}),
    ]
    return specs


def apply_channel(image: np.ndarray, family: str, params: dict[str, Any], seed: int) -> np.ndarray:
    if family == "identity":
        return image.copy()
    if family == "jpeg":
        return jpeg_roundtrip(image, params["quality"])
    if family == "scale":
        p = params["percent"] / 100.0
        if p == 1.0:
            return image.copy()
        small = cv2.resize(image, None, fx=p, fy=p, interpolation=cv2.INTER_AREA)
        return cv2.resize(small, (CAPTURE_PX, CAPTURE_PX), interpolation=cv2.INTER_LANCZOS4)
    if family == "grayscale":
        gray = cv2.cvtColor(image, cv2.COLOR_RGB2GRAY)
        return cv2.cvtColor(gray, cv2.COLOR_GRAY2RGB)
    if family == "colorspace_gamma":
        arr = image.astype(np.float32) / 255.0
        if "gamma" in params:
            arr = np.power(arr, params["gamma"])
        if "tint" in params:
            arr *= np.asarray(params["tint"], dtype=np.float32)[None, None, :]
        return np.clip(arr * 255.0, 0, 255).astype(np.uint8)
    if family == "photo_recompress":
        rng = np.random.default_rng(seed)
        h = w = CAPTURE_PX
        angle = params["angle"]
        inset = int(math.sin(math.radians(angle)) * 0.22 * w)
        jitter = rng.integers(-18, 19, size=(4, 2)).astype(np.float32)
        src = np.float32([[0, 0], [w - 1, 0], [w - 1, h - 1], [0, h - 1]])
        dst = np.float32([
            [70 + inset, 65], [w - 75, 35], [w - 40, h - 70], [55 + inset // 3, h - 35]
        ]) + jitter
        warped = cv2.warpPerspective(image, cv2.getPerspectiveTransform(src, dst), (w, h), borderValue=(238, 238, 232))
        arr = warped.astype(np.float32) / 255.0
        yy, xx = np.mgrid[-1:1:complex(h), -1:1:complex(w)]
        vignette = np.clip(1.0 - 0.20 * (xx * xx + yy * yy), 0.65, 1.0)
        arr *= params["light"] * vignette[:, :, None]
        arr = (arr - 0.5) * 1.05 + 0.5
        sigma = 0.55 + angle / 55.0
        arr = cv2.GaussianBlur(np.clip(arr, 0, 1), (0, 0), sigmaX=sigma)
        noise = rng.normal(0.0, 0.008 + angle / 6000.0, arr.shape).astype(np.float32)
        arr = np.clip(arr + noise, 0, 1)
        return jpeg_roundtrip((arr * 255).astype(np.uint8), 50)
    raise ValueError(family)


def order_quad(points: np.ndarray) -> np.ndarray:
    pts = points.reshape(4, 2).astype(np.float32)
    sums = pts.sum(axis=1)
    diffs = np.diff(pts, axis=1).reshape(-1)
    return np.float32([pts[np.argmin(sums)], pts[np.argmin(diffs)], pts[np.argmax(sums)], pts[np.argmax(diffs)]])


def rectify_registered(image: np.ndarray, scan_size: int) -> tuple[np.ndarray | None, float, str]:
    started = time.perf_counter()
    gray = cv2.cvtColor(image, cv2.COLOR_RGB2GRAY)
    blurred = cv2.GaussianBlur(gray, (3, 3), 0)
    _, binary = cv2.threshold(blurred, 0, 255, cv2.THRESH_BINARY_INV + cv2.THRESH_OTSU)
    contours, _ = cv2.findContours(binary, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
    contours = sorted(contours, key=cv2.contourArea, reverse=True)
    note = ""
    quad = None
    for contour in contours[:20]:
        if cv2.contourArea(contour) < 5000:
            continue
        perimeter = cv2.arcLength(contour, True)
        approx = cv2.approxPolyDP(contour, 0.025 * perimeter, True)
        if len(approx) == 4 and cv2.isContourConvex(approx):
            quad = order_quad(approx)
            break
    if quad is None and contours:
        rect = cv2.minAreaRect(contours[0])
        quad = order_quad(cv2.boxPoints(rect))
        note = "localization_min_area_fallback"
    if quad is None:
        return None, (time.perf_counter() - started) * 1000, "registration_frame_not_found"
    out_px = scan_size * RECTIFIED_MODULE_PX
    dst = np.float32([[0, 0], [out_px - 1, 0], [out_px - 1, out_px - 1], [0, out_px - 1]])
    warped = cv2.warpPerspective(gray, cv2.getPerspectiveTransform(quad, dst), (out_px, out_px), borderValue=255)
    return warped, (time.perf_counter() - started) * 1000, note


def read_symbol(image: np.ndarray, fmt: Any) -> bytes | None:
    results = zxingcpp.read_barcodes(
        image,
        formats=fmt,
        try_rotate=True,
        try_downscale=True,
        try_invert=True,
        text_mode=zxingcpp.TextMode.Plain,
        return_errors=True,
    )
    for result in results:
        if result.valid:
            return bytes(result.bytes)
    return None


def f1_sets(actual: set[int], predicted: set[int]) -> float:
    if not actual and not predicted:
        return 1.0
    if not actual or not predicted:
        return 0.0
    tp = len(actual & predicted)
    return 2.0 * tp / (len(actual) + len(predicted))


def decode_standard(carrier: Carrier, image: np.ndarray) -> DecodeResult:
    result = DecodeResult()
    rectified, result.localization_ms, note = rectify_registered(image, carrier.scan_size)
    if note:
        result.notes.append(note)
    if rectified is None:
        return result
    result.structure_recovered = True
    cy, cx, h, w = carrier.meta["content_rect"]
    crop = rectified[
        cy * RECTIFIED_MODULE_PX:(cy + h) * RECTIFIED_MODULE_PX,
        cx * RECTIFIED_MODULE_PX:(cx + w) * RECTIFIED_MODULE_PX,
    ]
    fmt = zxingcpp.BarcodeFormat.QRCode if carrier.arm.startswith("qr_") else (
        zxingcpp.BarcodeFormat.DataMatrix if carrier.arm == "data_matrix" else zxingcpp.BarcodeFormat.Aztec
    )
    started = time.perf_counter()
    result.output = read_symbol(crop, fmt)
    result.symbol_decode_ms = (time.perf_counter() - started) * 1000
    result.data_recovered = result.output is not None
    return result


def decode_custom(carrier: Carrier, image: np.ndarray) -> DecodeResult:
    result = DecodeResult()
    rectified, result.localization_ms, note = rectify_registered(image, carrier.scan_size)
    if note:
        result.notes.append(note)
    if rectified is None:
        return result
    result.structure_recovered = True
    started = time.perf_counter()
    y, x = carrier.meta["data_origin"]
    side = carrier.meta["data_side"]
    centers = (np.arange(side) * RECTIFIED_MODULE_PX + RECTIFIED_MODULE_PX // 2)
    patch = rectified[
        y * RECTIFIED_MODULE_PX:(y + side) * RECTIFIED_MODULE_PX,
        x * RECTIFIED_MODULE_PX:(x + side) * RECTIFIED_MODULE_PX,
    ]
    sampled = patch[np.ix_(centers, centers)] < 128
    bit_length = carrier.meta["bit_length"]
    sampled_bytes = np.packbits(sampled.reshape(-1)[:bit_length], bitorder="big").tobytes()
    result.symbol_decode_ms = (time.perf_counter() - started) * 1000
    original_codeword: bytes = carrier.meta["codeword"]
    data_bytes = carrier.meta["data_bytes_per_block"]
    parity_bytes = carrier.meta["parity_bytes_per_block"]
    block_size = data_bytes + parity_bytes
    actual_errors: set[int] = set()
    for i, (got, expected) in enumerate(zip(sampled_bytes, original_codeword)):
        if got != expected:
            actual_errors.add(i)
    predicted_errors: set[int] = set()
    decoded_parts: list[bytes] = []
    ecc_start = time.perf_counter()
    rsc = RSCodec(parity_bytes)
    failed = False
    for offset in range(0, len(sampled_bytes), block_size):
        block = sampled_bytes[offset:offset + block_size]
        try:
            decoded, _corrected, errata = rsc.decode(block)
            decoded_parts.append(bytes(decoded))
            predicted_errors.update(offset + int(pos) for pos in errata)
        except ReedSolomonError:
            failed = True
            predicted_errors.update(range(offset, min(offset + block_size, len(sampled_bytes))))
    result.ecc_ms = (time.perf_counter() - ecc_start) * 1000
    result.diagnostic_accuracy = f1_sets(actual_errors, predicted_errors)
    if failed:
        result.notes.append("one_or_more_rs_blocks_uncorrectable")
        return result
    raw = b"".join(decoded_parts)
    try:
        magic, length, digest = struct.unpack(">4sI32s", raw[:40])
        candidate = raw[40:40 + length]
        if magic != b"CG01" or hashlib.sha256(candidate).digest() != digest:
            result.notes.append("custom_header_or_digest_invalid")
            return result
        result.output = candidate
        result.data_recovered = True
    except struct.error:
        result.notes.append("custom_header_truncated")
    return result


def parse_fragment(fragment: bytes) -> tuple[int, int, int, bytes, bytes] | None:
    if len(fragment) < FRAGMENT_STRUCT.size + MANIFEST_STRUCT.size + 64 + 4:
        return None
    body, crc_bytes = fragment[:-4], fragment[-4:]
    if zlib.crc32(body) != struct.unpack(">I", crc_bytes)[0]:
        return None
    try:
        magic, index, row, col, manifest_len = FRAGMENT_STRUCT.unpack(body[:FRAGMENT_STRUCT.size])
        if magic != b"SFR1":
            return None
        manifest = body[FRAGMENT_STRUCT.size:FRAGMENT_STRUCT.size + manifest_len]
        shard = body[FRAGMENT_STRUCT.size + manifest_len:]
        manifest_body, signature = manifest[:-64], manifest[-64:]
        PUBLIC_KEY.verify(signature, manifest_body)
        mmagic, _digest, _length, _k, _n, shard_size, _rows, _cols = MANIFEST_STRUCT.unpack(manifest_body)
        if mmagic != b"SMF1" or len(shard) != shard_size:
            return None
        return index, row, col, manifest, shard
    except (struct.error, InvalidSignature, ValueError):
        return None


def decode_mosaic(carrier: Carrier, image: np.ndarray) -> DecodeResult:
    result = DecodeResult()
    rectified, result.localization_ms, note = rectify_registered(image, carrier.scan_size)
    if note:
        result.notes.append(note)
    if rectified is None:
        return result
    result.structure_recovered = True
    decode_started = time.perf_counter()
    recovered: dict[int, bytes] = {}
    predicted_damaged: set[int] = set()
    actual_damaged: set[int] = set()
    chosen_manifest: bytes | None = None
    for expected_index, (y, x, h, w) in enumerate(carrier.meta["tile_rects"]):
        crop = rectified[
            y * RECTIFIED_MODULE_PX:(y + h) * RECTIFIED_MODULE_PX,
            x * RECTIFIED_MODULE_PX:(x + w) * RECTIFIED_MODULE_PX,
        ]
        decoded = read_symbol(crop, zxingcpp.BarcodeFormat.QRCode)
        if decoded != carrier.meta["fragments"][expected_index]:
            actual_damaged.add(expected_index)
        parsed = parse_fragment(decoded) if decoded is not None else None
        if parsed is None:
            predicted_damaged.add(expected_index)
            continue
        index, row, col, manifest, shard = parsed
        expected_row, expected_col = divmod(expected_index, carrier.meta["cols"])
        if index != expected_index or row != expected_row or col != expected_col:
            predicted_damaged.add(expected_index)
            continue
        if chosen_manifest is None:
            chosen_manifest = manifest
        if manifest != chosen_manifest:
            predicted_damaged.add(expected_index)
            continue
        recovered[index] = shard
    result.symbol_decode_ms = (time.perf_counter() - decode_started) * 1000
    result.diagnostic_accuracy = f1_sets(actual_damaged, predicted_damaged)
    if chosen_manifest is None or len(recovered) < carrier.meta["k"]:
        result.notes.append(f"outer_rs_insufficient_fragments:{len(recovered)}/{carrier.meta['k']}")
        return result
    ecc_started = time.perf_counter()
    try:
        body = chosen_manifest[:-64]
        magic, digest, length, k, n, shard_size, rows, cols = MANIFEST_STRUCT.unpack(body)
        if (magic, k, n, shard_size, rows, cols) != (
            b"SMF1", carrier.meta["k"], carrier.meta["n"], carrier.meta["shard_size"], carrier.meta["rows"], carrier.meta["cols"]
        ):
            raise ReedSolomonError("manifest parameters do not match physical profile")
        missing = [i for i in range(n) if i not in recovered]
        rsc = RSCodec(n - k)
        data = bytearray()
        for pos in range(shard_size):
            stripe = bytes(recovered[i][pos] if i in recovered else 0 for i in range(n))
            decoded, _corrected, _errata = rsc.decode(stripe, erase_pos=missing)
            data.extend(decoded)
        # Stripes decode column-wise; transpose k x shard_size back into shard order.
        stripe_major = bytes(data)
        rebuilt = bytearray(k * shard_size)
        for pos in range(shard_size):
            for shard_index in range(k):
                rebuilt[shard_index * shard_size + pos] = stripe_major[pos * k + shard_index]
        candidate = bytes(rebuilt[:length])
        if hashlib.sha256(candidate).digest() != digest:
            result.output = candidate
            result.notes.append("manifest_payload_digest_mismatch")
        else:
            result.output = candidate
        result.data_recovered = True
    except (ReedSolomonError, struct.error, ValueError) as exc:
        result.notes.append(f"outer_rs_failure:{type(exc).__name__}")
    result.ecc_ms = (time.perf_counter() - ecc_started) * 1000
    return result


def decode_carrier(carrier: Carrier, image: np.ndarray) -> DecodeResult:
    if carrier.arm == "custom_grid":
        return decode_custom(carrier, image)
    if carrier.arm == "mosaic_outer_rs":
        return decode_mosaic(carrier, image)
    return decode_standard(carrier, image)


def channel_seed(condition: str, repetition: int) -> int:
    digest = hashlib.sha256(f"{SEED}:{condition}:{repetition}".encode()).digest()
    return int.from_bytes(digest[:8], "big")


def trial_row(
    carrier: Carrier | None,
    arm: str,
    experiment: str,
    regime: str,
    payload: bytes,
    envelope: bytes,
    family: str,
    condition: str,
    repetition: int,
    canonical: np.ndarray | None,
    render_info: dict[str, Any],
    build_error: str,
) -> dict[str, Any]:
    seed = channel_seed(condition, repetition)
    base = {
        "experiment": experiment,
        "arm": arm,
        "payload_regime": regime,
        "payload_bytes": len(payload),
        "envelope_bytes": len(envelope),
        "channel_family": family,
        "condition": condition,
        "repetition": repetition,
        "seed": seed,
        "capacity_ok": int(carrier is not None),
        "geometry_ok": int(render_info.get("geometry_ok", False)),
        "build_error": build_error,
        "native_ecc": carrier.native_ecc if carrier else "",
        "protected_redundancy_ratio": carrier.protected_redundancy_ratio if carrier else "",
        "logical_width_modules": carrier.logical_size if carrier else 0,
        "logical_height_modules": carrier.logical_size if carrier else 0,
        "module_px": render_info.get("module_px", 0),
        "min_module_mm": render_info.get("min_module_mm", 0.0),
        "allocated_area_mm2": render_info.get("allocated_area_mm2", 0.0),
        "symbol_area_mm2": render_info.get("symbol_area_mm2", 0.0),
        "effective_capacity_bytes_per_mm2": (
            len(payload) / render_info["allocated_area_mm2"] if render_info.get("allocated_area_mm2", 0) else 0.0
        ),
        "capture_width_px": CAPTURE_PX,
        "capture_height_px": CAPTURE_PX,
        "decode_budget_ms": DECODE_BUDGET_MS,
        "structure_data_independent": int(carrier.structure_data_independent) if carrier else 0,
        "exact_recover": 0,
        "robust_recover": 0,
        "decoder_wrong_output": 0,
        "authenticated_false_acceptance": 0,
        "substitution_replay": "n/a",
        "structure_recovered": 0,
        "data_recovered": 0,
        "diagnostic_accuracy": "",
        "localization_ms": 0.0,
        "symbol_decode_ms": 0.0,
        "ecc_ms": 0.0,
        "authentication_ms": 0.0,
        "total_decode_ms": 0.0,
        "decode_within_budget": 0,
        "output_bytes": 0,
        "notes": "",
    }
    if carrier is None or canonical is None or not render_info.get("geometry_ok"):
        base["notes"] = "capacity_failure" if carrier is None else "geometry_failure"
        return base
    params = next(p for f, c, p in channel_specs() if f == family and c == condition)
    received = apply_channel(canonical, family, params, seed)
    started = time.perf_counter()
    decoded = decode_carrier(carrier, received)
    pre_auth_ms = (time.perf_counter() - started) * 1000
    auth_started = time.perf_counter()
    authenticated, _ = authenticate_envelope(decoded.output)
    auth_ms = (time.perf_counter() - auth_started) * 1000
    total_ms = pre_auth_ms + auth_ms
    within_budget = total_ms <= DECODE_BUDGET_MS
    robust = decoded.output == envelope and within_budget
    wrong = decoded.output is not None and decoded.output != envelope
    false_accept = wrong and authenticated
    normalized_equal = np.array_equal(received, canonical)
    base.update({
        "exact_recover": int(robust and normalized_equal),
        "robust_recover": int(robust),
        "decoder_wrong_output": int(wrong),
        "authenticated_false_acceptance": int(false_accept),
        "structure_recovered": int(decoded.structure_recovered),
        "data_recovered": int(decoded.data_recovered),
        "diagnostic_accuracy": "" if decoded.diagnostic_accuracy is None else decoded.diagnostic_accuracy,
        "localization_ms": decoded.localization_ms,
        "symbol_decode_ms": decoded.symbol_decode_ms,
        "ecc_ms": decoded.ecc_ms,
        "authentication_ms": auth_ms,
        "total_decode_ms": total_ms,
        "decode_within_budget": int(within_budget),
        "output_bytes": len(decoded.output) if decoded.output is not None else 0,
        "notes": ";".join(decoded.notes + ([] if within_budget else ["decode_budget_exceeded"])),
    })
    return base


def mean_numeric(rows: list[dict[str, Any]], key: str) -> float | None:
    values = [float(r[key]) for r in rows if r.get(key, "") not in ("", None)]
    return statistics.fmean(values) if values else None


def write_csv(path: Path, rows: list[dict[str, Any]], fields: list[str] | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if fields is None:
        fields = list(rows[0]) if rows else []
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def aggregate(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[Any, ...], list[dict[str, Any]]] = defaultdict(list)
    keys = ("experiment", "arm", "payload_regime", "channel_family", "condition")
    for row in rows:
        grouped[tuple(row[k] for k in keys)].append(row)
    out = []
    for group_key, group in sorted(grouped.items()):
        record = dict(zip(keys, group_key))
        record.update({
            "trials": len(group),
            "capacity_success_rate": mean_numeric(group, "capacity_ok"),
            "geometry_success_rate": mean_numeric(group, "geometry_ok"),
            "exact_recover_rate": mean_numeric(group, "exact_recover"),
            "robust_recover_rate": mean_numeric(group, "robust_recover"),
            "decoder_wrong_output_rate": mean_numeric(group, "decoder_wrong_output"),
            "authenticated_false_acceptance_rate": mean_numeric(group, "authenticated_false_acceptance"),
            "substitution_replay": "n/a",
            "structure_recovery_rate": mean_numeric(group, "structure_recovered"),
            "data_recovery_rate": mean_numeric(group, "data_recovered"),
            "diagnostic_accuracy_mean": mean_numeric(group, "diagnostic_accuracy"),
            "localization_ms_mean": mean_numeric(group, "localization_ms"),
            "symbol_decode_ms_mean": mean_numeric(group, "symbol_decode_ms"),
            "ecc_ms_mean": mean_numeric(group, "ecc_ms"),
            "authentication_ms_mean": mean_numeric(group, "authentication_ms"),
            "total_decode_ms_mean": mean_numeric(group, "total_decode_ms"),
        })
        out.append(record)
    return out


def decision_stats(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    subset = [r for r in rows if r["payload_regime"] == "large" and r["channel_family"] == "photo_recompress" and r["arm"] in ("custom_grid", "mosaic_outer_rs")]
    records = []
    for experiment in ("equal_area", "equal_module", "pooled"):
        source = subset if experiment == "pooled" else [r for r in subset if r["experiment"] == experiment]
        for arm in ("custom_grid", "mosaic_outer_rs"):
            arm_rows = [r for r in source if r["arm"] == arm]
            records.append({
                "experiment": experiment,
                "arm": arm,
                "trials": len(arm_rows),
                "robust_recover_rate": mean_numeric(arm_rows, "robust_recover"),
                "decoder_wrong_output_rate": mean_numeric(arm_rows, "decoder_wrong_output"),
                "authenticated_false_acceptance_rate": mean_numeric(arm_rows, "authenticated_false_acceptance"),
                "diagnostic_accuracy_mean": mean_numeric(arm_rows, "diagnostic_accuracy"),
            })
    return records


def decide(records: list[dict[str, Any]]) -> tuple[str, str]:
    pooled = {r["arm"]: r for r in records if r["experiment"] == "pooled"}
    custom, baseline = pooled["custom_grid"], pooled["mosaic_outer_rs"]
    advantages = []
    if custom["robust_recover_rate"] > baseline["robust_recover_rate"]:
        advantages.append("robust_recover")
    if custom["authenticated_false_acceptance_rate"] < baseline["authenticated_false_acceptance_rate"]:
        advantages.append("authenticated_false_acceptance")
    if custom["diagnostic_accuracy_mean"] is not None and baseline["diagnostic_accuracy_mean"] is not None and custom["diagnostic_accuracy_mean"] > baseline["diagnostic_accuracy_mean"]:
        advantages.append("diagnostic_accuracy")
    verdict = "SUPPORTED" if advantages else "REJECTED"
    reason = ", ".join(advantages) if advantages else "no pre-registered metric showed a strict custom-grid advantage"
    return verdict, reason


def fmt_rate(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.3f}"


def write_measurements(
    path: Path,
    rows: list[dict[str, Any]],
    summaries: list[dict[str, Any]],
    decisions: list[dict[str, Any]],
    capacity_rows: list[dict[str, Any]],
    verdict: str,
    reason: str,
    repetitions: int,
) -> None:
    decision_map = {(r["experiment"], r["arm"]): r for r in decisions}
    lines = [
        "# Appendix-A comparison spike measurements",
        "",
        f"**H1 VERDICT: {verdict}.** {reason}.",
        "",
        "The decision rule was frozen in `PROTOCOL.md` before the final measurement run. The exact reproduction commands are:",
        "",
        f"```powershell\npython -m venv .venv\n.\\.venv\\Scripts\\python.exe -m pip install -r requirements.txt\n.\\.venv\\Scripts\\python.exe appendix_a_spike.py --repetitions {repetitions} --output results\n```",
        "",
        "## Decision subset: large payload, simulated photo plus JPEG recompression",
        "",
        "| fairness mode | arm | trials | robustRecover | decoder wrong-output | authenticated false acceptance | diagnostic F1 |",
        "|---|---|---:|---:|---:|---:|---:|",
    ]
    for experiment in ("equal_area", "equal_module", "pooled"):
        for arm in ("custom_grid", "mosaic_outer_rs"):
            r = decision_map[(experiment, arm)]
            lines.append(
                f"| {experiment} | {arm} | {r['trials']} | {fmt_rate(r['robust_recover_rate'])} | "
                f"{fmt_rate(r['decoder_wrong_output_rate'])} | {fmt_rate(r['authenticated_false_acceptance_rate'])} | "
                f"{fmt_rate(r['diagnostic_accuracy_mean'])} |"
            )
    lines += [
        "",
        "Authenticated-false-acceptance and decoder wrong-output are distinct. Replay/substitution is `n/a` for this carrier-only channel matrix and was not counted as either.",
        "",
        "## Fairness controls",
        "",
        "- Every arm used the same payload bytes and identical Ed25519-signed envelope.",
        "- The mosaic used six data plus three parity fragments (0.500 outer redundancy) with QR-M inner ECC. Its total coding redundancy is `(1 + outer) x (1 + inner) - 1`; the custom RS parity was matched per payload to that combined version-specific ratio (about 1.38 parity/data). Framing and signed-manifest/index overhead are reported through physical area rather than mislabeled as parity.",
        "- Equal-area used a 1200 x 1200 px allocation in a 1600 x 1600 px, 200 x 200 mm capture. Equal-module used 4 px (0.5 mm) per module in the same capture.",
        f"- All decodes used the same {DECODE_BUDGET_MS:.0f} ms end-to-end budget.",
        "- Each condition used arm-independent deterministic noise seeds.",
        "",
        "The two experiments cannot simultaneously have identical outer area and identical module size when logical dimensions differ. Following Appendix A.3, equal-area fixes the physical allocation and minimum module lower bound; equal-module fixes module size and lets physical area vary.",
        "",
        "## Capacity and physical footprint",
        "",
        "`capacity.csv` contains every arm/payload/fairness configuration. Capacity failures are scored as recovery failures for every channel; they are not replaced by mosaics. Selected large-payload rows:",
        "",
        "| experiment | arm | capacity | geometry | logical modules | module px | allocated mm² | effective B/mm² |",
        "|---|---|---:|---:|---:|---:|---:|---:|",
    ]
    for r in capacity_rows:
        if r["payload_regime"] == "large":
            lines.append(
                f"| {r['experiment']} | {r['arm']} | {r['capacity_ok']} | {r['geometry_ok']} | "
                f"{r['logical_width_modules']} | {r['module_px']} | {float(r['allocated_area_mm2']):.1f} | "
                f"{float(r['effective_capacity_bytes_per_mm2']):.4f} |"
            )
    lines += [
        "",
        "## Exact/robust boundary",
        "",
        "The table below aggregates all payloads and both fairness modes. `exactRecover` additionally requires normalized raster identity; `robustRecover` only requires byte-exact envelope recovery.",
        "",
        "| arm | channel family | exact rate | robust rate |",
        "|---|---|---:|---:|",
    ]
    family_groups: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        family_groups[(row["arm"], row["channel_family"])].append(row)
    for arm in ARM_ORDER:
        for family in ("identity", "jpeg", "scale", "photo_recompress", "grayscale", "colorspace_gamma"):
            group = family_groups.get((arm, family), [])
            lines.append(f"| {arm} | {family} | {fmt_rate(mean_numeric(group, 'exact_recover'))} | {fmt_rate(mean_numeric(group, 'robust_recover'))} |")
    lines += [
        "",
        "## Diagnostics, structure, and latency",
        "",
        "The custom diagnostic is RS-byte errata versus sampled byte discrepancies. The mosaic diagnostic is failed/invalid fragment positions versus fragments that no longer decode to their original bound bytes. Standard single symbols do not expose correction locations through ZXing, so their diagnostic is null rather than invented. Structure and data recovery are separate columns in `raw_trials.csv` and `condition_summary.csv`; all staged latencies are in `staged_latency.csv`.",
        "",
        "## Implementation notes and limitations",
        "",
        "- `pylibdmtx` could not load `libdmtx-64.dll` on this Windows host. Data Matrix encoding/decoding uses the working ZXing-C++ 3.1.0 ECC200 implementation. The same ZXing build handles QR and Aztec, which avoids a cross-library decoder advantage.",
        "- Two audit pilots are preserved but excluded: `results_unmatched_pilot/` omitted QR-M inner ECC from total-redundancy matching, and `results_underfilled_equal_area_pilot/` left unequal unused margins. Only `results/` supplies the verdict.",
        "- The mosaic is not a weak all-fragments-required baseline. It binds fragment index and physical row/column, repeats a signed manifest in every symbol, uses QR-M inner ECC, and reconstructs any six of nine fragments with outer Reed-Solomon erasures.",
        "- This is a deterministic simulated channel spike, not a claim about real camera populations. A physical-print/camera replication is still required before publication.",
        "- An observed zero authenticated-false-acceptance count is empirical only; the security argument comes from Ed25519 unforgeability, not from the sample size.",
        "",
        "## Artifacts",
        "",
        "- `raw_trials.csv`: one observation per arm/payload/fairness/channel/repetition.",
        "- `condition_summary.csv`: per-condition rates and staged latency means.",
        "- `capacity.csv`: physical footprint, module size, capacity, and redundancy metadata.",
        "- `decision_subset.csv`: the pre-registered H1 comparison only.",
        "- `staged_latency.csv`: latency columns in long-form-friendly rows.",
        "- `environment.json`: runtime and package versions, seed, and controls.",
        "",
        f"H1 VERDICT: {verdict} — custom robust={fmt_rate(decision_map[('pooled', 'custom_grid')]['robust_recover_rate'])}, baseline robust={fmt_rate(decision_map[('pooled', 'mosaic_outer_rs')]['robust_recover_rate'])}; custom auth-false-accept={fmt_rate(decision_map[('pooled', 'custom_grid')]['authenticated_false_acceptance_rate'])}, baseline auth-false-accept={fmt_rate(decision_map[('pooled', 'mosaic_outer_rs')]['authenticated_false_acceptance_rate'])}; custom diagnostic={fmt_rate(decision_map[('pooled', 'custom_grid')]['diagnostic_accuracy_mean'])}, baseline diagnostic={fmt_rate(decision_map[('pooled', 'mosaic_outer_rs')]['diagnostic_accuracy_mean'])}."
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def environment_record(repetitions: int) -> dict[str, Any]:
    packages = {}
    for name in ("Pillow", "numpy", "opencv-python-headless", "reedsolo", "cryptography", "zxing-cpp", "pylibdmtx", "qrcode", "aztec-code-generator"):
        try:
            packages[name] = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            packages[name] = "not installed"
    return {
        "run_note": "deterministic run; wall clock intentionally omitted",
        "platform": platform.platform(),
        "python": sys.version,
        "packages": packages,
        "seed": SEED,
        "repetitions": repetitions,
        "capture_px": [CAPTURE_PX, CAPTURE_PX],
        "field_mm": [FIELD_MM, FIELD_MM],
        "equal_area_box_px": EQUAL_AREA_BOX_PX,
        "equal_module_px": EQUAL_MODULE_PX,
        "decode_budget_ms": DECODE_BUDGET_MS,
        "data_matrix_substitution": "pylibdmtx installed but libdmtx-64.dll unavailable; ZXing-C++ ECC200 used",
        "preregistered_protocol": "../PROTOCOL.md",
    }


def run(args: argparse.Namespace) -> int:
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    all_rows: list[dict[str, Any]] = []
    capacity_rows: list[dict[str, Any]] = []
    specs = channel_specs()
    for regime, payload_size in PAYLOADS.items():
        payload = deterministic_payload(payload_size, regime)
        envelope = sign_envelope(payload)
        built: dict[str, Carrier | None] = {}
        errors: dict[str, str] = {}
        for arm in ARM_ORDER:
            try:
                built[arm] = build_carrier(arm, envelope)
                errors[arm] = ""
            except Exception as exc:  # capacity limits are part of the measurement
                built[arm] = None
                errors[arm] = f"{type(exc).__name__}: {exc}"
        for experiment in ("equal_area", "equal_module"):
            for arm in ARM_ORDER:
                carrier = built[arm]
                if carrier is None:
                    canonical, render_info = None, {"geometry_ok": False, "module_px": 0}
                else:
                    canonical, render_info = render_capture(carrier, experiment)
                capacity_rows.append({
                    "experiment": experiment,
                    "arm": arm,
                    "payload_regime": regime,
                    "payload_bytes": len(payload),
                    "envelope_bytes": len(envelope),
                    "capacity_ok": int(carrier is not None),
                    "geometry_ok": int(render_info.get("geometry_ok", False)),
                    "build_error": errors[arm],
                    "native_ecc": carrier.native_ecc if carrier else "",
                    "protected_redundancy_ratio": carrier.protected_redundancy_ratio if carrier else "",
                    "logical_width_modules": carrier.logical_size if carrier else 0,
                    "logical_height_modules": carrier.logical_size if carrier else 0,
                    "module_px": render_info.get("module_px", 0),
                    "min_module_mm": render_info.get("min_module_mm", 0.0),
                    "allocated_area_mm2": render_info.get("allocated_area_mm2", 0.0),
                    "symbol_area_mm2": render_info.get("symbol_area_mm2", 0.0),
                    "effective_capacity_bytes_per_mm2": len(payload) / render_info["allocated_area_mm2"] if render_info.get("allocated_area_mm2", 0) else 0.0,
                })
                for family, condition, _params in specs:
                    for repetition in range(args.repetitions):
                        row = trial_row(
                            carrier, arm, experiment, regime, payload, envelope, family, condition,
                            repetition, canonical, render_info, errors[arm]
                        )
                        all_rows.append(row)
                print(f"completed {regime:6s} {experiment:12s} {arm:18s}", flush=True)
    summaries = aggregate(all_rows)
    decisions = decision_stats(all_rows)
    verdict, reason = decide(decisions)
    write_csv(output / "raw_trials.csv", all_rows)
    write_csv(output / "condition_summary.csv", summaries)
    write_csv(output / "capacity.csv", capacity_rows)
    write_csv(output / "decision_subset.csv", decisions)
    latency_fields = [
        "experiment", "arm", "payload_regime", "channel_family", "condition", "repetition",
        "localization_ms", "symbol_decode_ms", "ecc_ms", "authentication_ms", "total_decode_ms", "decode_within_budget"
    ]
    write_csv(output / "staged_latency.csv", all_rows, latency_fields)
    (output / "environment.json").write_text(json.dumps(environment_record(args.repetitions), indent=2), encoding="utf-8")
    write_measurements(output / "MEASUREMENTS.md", all_rows, summaries, decisions, capacity_rows, verdict, reason, args.repetitions)
    (output / "H1_VERDICT.txt").write_text(
        next(line for line in (output / "MEASUREMENTS.md").read_text(encoding="utf-8").splitlines() if line.startswith("H1 VERDICT:")) + "\n",
        encoding="utf-8",
    )
    print(f"H1 VERDICT: {verdict} ({reason})")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Appendix-A carrier comparison spike")
    parser.add_argument("--repetitions", type=int, default=3)
    parser.add_argument("--output", default="results")
    args = parser.parse_args()
    if args.repetitions < 1:
        parser.error("--repetitions must be positive")
    return run(args)


if __name__ == "__main__":
    raise SystemExit(main())
