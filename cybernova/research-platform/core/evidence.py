"""Offline evidence utilities; never transmit or persist raw response bodies.

These helpers are safeguards, not a comprehensive PII DLP solution.
Owners must inspect redacted artifacts before any export or model exposure.
"""
from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
import re
from urllib.parse import urlsplit

SAFE_RESPONSE_HEADERS = frozenset({
    "date", "content-type", "content-length", "server", "cache-control",
    "strict-transport-security", "content-security-policy", "x-frame-options",
    "x-content-type-options", "referrer-policy", "permissions-policy", "vary",
})


def sha256_hex(data: bytes) -> str:
    if not isinstance(data, bytes):
        raise TypeError("evidence data must be bytes")
    return sha256(data).hexdigest()


def redact_headers(headers: dict) -> dict:
    """Return ONLY allowed response header keys; drop every other header."""
    if not isinstance(headers, dict):
        raise TypeError("headers must be a dict")
    clean = {}
    for key, value in headers.items():
        name = str(key).strip().lower()
        if name in SAFE_RESPONSE_HEADERS:
            clean[name] = re.sub(r"[\r\n\x00-\x1f]", " ", str(value))[:300]
    return clean


def redact_text(text: str) -> str:
    """Best-effort masking for display. Do not rely on this for sensitive dumps."""
    if not isinstance(text, str):
        raise TypeError("text must be a string")
    output = text
    # Long JWT-like tokens, authorization bearer, key=value and emails.
    output = re.sub(r"(?i)\b(bearer)\s+\S+", r"\1 [REDACTED]", output)
    output = re.sub(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*\b",
                    "[JWT_REDACTED]", output)
    output = re.sub(r"(?i)\b(password|passwd|api[_-]?key|token|secret)\s*[:=]\s*[^\s,;]+",
                    r"\1=[REDACTED]", output)
    output = re.sub(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
                    "[EMAIL_REDACTED]", output)
    return output


def safe_target_label(url: str) -> str:
    """Reduce target identifiers to origin+path; never retain query or credentials."""
    parts = urlsplit(url)
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        raise ValueError("invalid URL")
    host = parts.hostname.lower()
    return f"{parts.scheme}://{host}{parts.path or '/'}"


def evidence_metadata(*, run_id: str, tool_name: str, target_url: str,
                      raw_bytes: bytes, response_headers: dict,
                      content_class: str = "restricted") -> dict:
    """Return a metadata-only record with raw bytes hashed but not stored."""
    if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,95}", run_id):
        raise ValueError("invalid run_id")
    if not re.fullmatch(r"[a-z][a-z0-9_]{0,95}", tool_name):
        raise ValueError("invalid tool_name")
    digest = sha256_hex(raw_bytes)
    return {
        "schema_version": "1.0",
        "run_id": run_id,
        "tool_name": tool_name,
        "target": safe_target_label(target_url),
        "captured_at_utc": datetime.now(timezone.utc).isoformat(),
        "sha256": digest,
        "bytes_hashed": len(raw_bytes),
        "response_headers": redact_headers(response_headers),
        "redacted": True,
        "content_class": content_class,
        "raw_payload_saved": False,
    }
