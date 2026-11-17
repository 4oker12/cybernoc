"""Cybernova MCP Events: persisted subscriptions and signed, SSRF-guarded webhooks.

A dedicated cybernova user owns the state; the MCP stdio process acts as an RPC
bridge only. No model/API key, arbitrary shell execution, or GitHub write token.
"""
from __future__ import annotations

import base64
from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import hashlib
import hmac
import http.client
import ipaddress
import json
import os
from pathlib import Path
import secrets
import socket
import ssl
import sys
import time
from urllib.parse import urlsplit

WORK = Path(os.environ.get("CYBERNOVA_UPDATER_WORK", "/workspace/cybernova-updater"))
STORE = WORK / "events"
STATE = STORE / "subscriptions.json"
REPORTS = WORK / "reports"
EVENT = "cybernova.deployment.completed"
OWNER = "cybernova-single-user-tunnel"
MAX_TTL_MS = 7 * 86400 * 1000
DEFAULT_TTL_MS = 86400 * 1000
MAX_BODY = 256 * 1024
MAX_REPORT = 20000
MAX_ATTEMPTS = 5

class CallbackError(ValueError):
    pass

def timestamp(t=None):
    return datetime.fromtimestamp(time.time() if t is None else t, timezone.utc).isoformat().replace("+00:00", "Z")

def event_catalog():
    return {"events": [{
        "name": EVENT,
        "description": "Cybernova agent deployment success or failure on the authorized Vast instance.",
        "delivery": ["webhook"],
        "inputSchema": {
            "type": "object",
            "properties": {"status": {"type": "string", "enum": ["any", "success", "failed"]}},
            "additionalProperties": False,
        },
        "payloadSchema": {
            "type": "object",
            "properties": {
                "commit": {"type": "string", "pattern": "^[0-9a-f]{40}$"},
                "status": {"type": "string", "enum": ["success", "failed"]},
                "report": {"type": "string"},
                "source": {"type": "string"},
            },
            "required": ["commit", "status", "report", "source"],
            "additionalProperties": False,
        }
    }]}

def _secret(value):
    if not isinstance(value, str) or not value.startswith("whsec_"):
        raise ValueError("Signing secret must start with whsec_")
    try:
        raw = base64.b64decode(value[6:], validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise ValueError("Signing secret is not valid base64") from exc
    if not 24 <= len(raw) <= 64:
        raise ValueError("Signing key must decode to 24-64 bytes")
    return raw

def _arguments(args):
    if not isinstance(args, dict) or set(args) - {"status"}:
        raise ValueError("Invalid event filter")
    if args.get("status", "any") not in ("any", "success", "failed"):
        raise ValueError("Invalid status filter")
    return {"status": args.get("status", "any")}

def _callback_parts(url):
    if not isinstance(url, str) or len(url) > 2048:
        raise CallbackError("Invalid callback URL")
    try:
        p = urlsplit(url)
        hostname = p.hostname
        port = p.port
    except (ValueError, AttributeError) as exc:
        raise CallbackError("Invalid callback URL") from exc
    if (p.scheme != "https" or not hostname or p.username or p.password or p.fragment or
        (port not in (None, 443)) or len(hostname) > 253):
        raise CallbackError("Callback must be an HTTPS URL on port 443")
    if (hostname.lower() in ("localhost", "localhost.localdomain") or
        hostname.lower().endswith((".local", ".internal", ".localhost"))):
        raise CallbackError("Local callback host forbidden")
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        pass
    else:
        raise CallbackError("Callback must use a public DNS hostname")
    path = p.path or "/"
    if p.query:
        path += "?" + p.query
    return hostname, path

def _resolve_public(host):
    addresses = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    if not addresses:
        raise CallbackError("Callback hostname has no addresses")
    for family, socktype, proto, _, sockaddr in addresses:
        addr = ipaddress.ip_address(sockaddr[0])
        if not addr.is_global:
            raise CallbackError("Callback resolves to a non-public address")
    return addresses

class _PinnedHTTPS(http.client.HTTPSConnection):
    def __init__(self, host, addresses, timeout=8):
        super().__init__(host, port=443, timeout=timeout, context=ssl.create_default_context())
        self._addresses = addresses

    def connect(self):
        last_exc = None
        for family, socktype, proto, _, sockaddr in self._addresses:
            raw = socket.socket(family, socktype, proto)
            raw.settimeout(self.timeout)
            try:
                raw.connect(sockaddr)
                self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
                return
            except (OSError, ssl.SSLError) as exc:
                last_exc = exc
                raw.close()
        raise CallbackError("Unable to establish trusted TLS callback") from last_exc

def _post_json(url, body, headers):
    host, path = _callback_parts(url)
    addresses = _resolve_public(host)  # re-resolve and validate on every connection
    conn = _PinnedHTTPS(host, addresses)
    try:
        conn.request("POST", path, body=body, headers={**headers, "Host": host})
        response = conn.getresponse()
        data = response.read(4097)
        if len(data) > 4096:
            raise CallbackError("Callback response too large")
        return response.status, data
    finally:
        conn.close()

def signed_headers(secret, sub_id, event_id, body, signed_at=None):
    key = _secret(secret)
    ts = str(int(time.time() if signed_at is None else signed_at))
    message = event_id.encode() + b"." + ts.encode() + b"." + body
    signature = base64.b64encode(hmac.new(key, message, hashlib.sha256).digest()).decode()
    return {
        "Content-Type": "application/json",
        "webhook-id": event_id,
        "webhook-timestamp": ts,
        "webhook-signature": "v1," + signature,
        "X-MCP-Subscription-Id": sub_id,
    }

def _json_bytes(data):
    b = json.dumps(data, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    if len(b) > MAX_BODY:
        raise ValueError("Event exceeds size limit")
    return b

def verify_callback(url, secret, sub_id):
    challenge = secrets.token_urlsafe(24)
    event_id = "msg_verification_" + secrets.token_hex(12)
    body = _json_bytes({"type": "verification", "challenge": challenge})
    headers = signed_headers(secret, sub_id, event_id, body)
    status, reply = _post_json(url, body, headers)
    if not 200 <= status < 300:
        raise CallbackError("Callback challenge rejected")
    try:
        echoed = json.loads(reply).get("challenge")
    except (ValueError, AttributeError):
        echoed = None
    if not isinstance(echoed, str) or not hmac.compare_digest(challenge, echoed):
        raise CallbackError("Callback challenge mismatch")

@contextmanager
def _locked():
    STORE.mkdir(parents=True, exist_ok=True, mode=0o700)
    if STORE.is_symlink():
        raise RuntimeError("Unsafe subscriptions directory")
    f = STORE / ".lock"
    with f.open("a+") as fh:
        os.chmod(f, 0o600)
        fcntl.flock(fh, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(fh, fcntl.LOCK_UN)

def _read():
    if not STATE.exists():
        return {"subscriptions": {}, "deliveries": {}}
    if STATE.is_symlink() or STATE.stat().st_size > 2_000_000:
        raise RuntimeError("Unsafe subscriptions state")
    value = json.loads(STATE.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise RuntimeError("Bad subscriptions state")
    value.setdefault("subscriptions", {})
    value.setdefault("deliveries", {})
    return value

def _write(value):
    target = STORE / (".subscriptions." + secrets.token_hex(8))
    with target.open("x", encoding="utf-8") as fh:
        json.dump(value, fh, sort_keys=True, ensure_ascii=False)
        fh.flush()
        os.fsync(fh.fileno())
    target.chmod(0o600)
    os.replace(target, STATE)

def subscription_id(name, args, url):
    identity = json.dumps([OWNER, name, args, url], separators=(",", ":"), sort_keys=True)
    return "sub_" + hashlib.sha256(identity.encode()).hexdigest()[:32]

def subscribe(params, verifier=verify_callback):
    if params.get("name") != EVENT:
        raise ValueError("Unknown event")
    args = _arguments(params.get("arguments", {}))
    delivery = params.get("delivery")
    if not isinstance(delivery, dict) or delivery.get("mode") != "webhook":
        raise ValueError("Webhook delivery required")
    url = delivery.get("url")
    secret = delivery.get("secret")
    _callback_parts(url)
    _secret(secret)
    ttl = params.get("ttlMs", DEFAULT_TTL_MS)
    if ttl is None:
        ttl = MAX_TTL_MS  # a finite lease; no indefinite subscription
    if type(ttl) is not int or not 60_000 <= ttl <= MAX_TTL_MS:
        raise ValueError("Invalid subscription lifetime")
    sub = subscription_id(EVENT, args, url)
    verifier(url, secret, sub)
    expiry = time.time() + ttl / 1000
    with _locked():
        db = _read()
        existing = db["subscriptions"].get(sub)
        db["subscriptions"][sub] = {
            "id": sub, "name": EVENT, "arguments": args,
            "url": url, "secret": secret, "owner": OWNER,
            "created_at": existing.get("created_at", time.time()) if existing else time.time(),
            "expires_at": expiry,
        }
        _write(db)
    return {"id": sub, "refreshBefore": timestamp(expiry), "cursor": None, "truncated": False}

def unsubscribe(params):
    if params.get("name") != EVENT:
        raise ValueError("Unknown event")
    args = _arguments(params.get("arguments", {}))
    delivery = params.get("delivery")
    if not isinstance(delivery, dict) or delivery.get("mode") != "webhook":
        raise ValueError("Webhook delivery required")
    url = delivery.get("url")
    _callback_parts(url)
    sub = subscription_id(EVENT, args, url)
    with _locked():
        db = _read()
        db["subscriptions"].pop(sub, None)
        _write(db)
    return {}

def _reports():
    if not REPORTS.exists():
        return []
    results = []
    for p in REPORTS.glob("*.json"):
        if p.is_symlink() or p.stat().st_size > MAX_REPORT or len(p.name) > 140:
            continue
        try:
            obj = json.loads(p.read_text(encoding="utf-8"))
            sha, status, occurred = obj.get("commit"), obj.get("status"), obj.get("timestamp")
            if (not isinstance(sha, str) or len(sha) != 40 or
                any(x not in "0123456789abcdef" for x in sha) or
                status not in ("success", "failed") or not isinstance(occurred, (int, float))):
                continue
            results.append((p.name, sha, status, occurred))
        except (OSError, ValueError, TypeError):
            continue
    return sorted(results, key=lambda x: (x[3], x[0]))

def delivery_event(report, sub):
    filename, commit, status, occurred = report
    ev_id = "evt_" + hashlib.sha256((sub["id"] + "\n" + filename).encode()).hexdigest()[:40]
    return {
        "eventId": ev_id,
        "name": EVENT,
        "timestamp": timestamp(occurred),
        "data": {"commit": commit, "status": status,
                 "report": filename, "source": "cybernova-vast-updater"},
        "cursor": None,
    }

def poll_once(sender=_post_json, now=None):
    current = time.time() if now is None else now
    reports = _reports()
    with _locked():
        db = _read()
        subscriptions = list(db["subscriptions"].values())
        ledger = dict(db["deliveries"])
    attempted = accepted = 0
    for sub in subscriptions:
        if sub.get("owner") != OWNER or sub.get("expires_at", 0) <= current:
            continue
        for report in reports:
            if report[3] < sub.get("created_at", current):
                continue  # never replay older reports into a new subscription
            if sub["arguments"]["status"] not in ("any", report[2]):
                continue
            event = delivery_event(report, sub)
            eid = event["eventId"]
            entry = ledger.get(eid, {})
            if (entry.get("accepted") or entry.get("attempts", 0) >= MAX_ATTEMPTS or
                entry.get("next_attempt_at", 0) > current):
                continue
            attempted += 1
            body = _json_bytes(event)
            success = False
            status_code = None
            try:
                status_code, _ = sender(sub["url"], body,
                                        signed_headers(sub["secret"], sub["id"], eid, body))
                success = 200 <= status_code < 300
            except (OSError, ValueError, TimeoutError, http.client.HTTPException):
                pass
            attempts = entry.get("attempts", 0) + 1
            entry = {"attempts": attempts, "accepted": success,
                     "http_status": status_code,
                     "next_attempt_at": current + min(900, 30 * (2 ** (attempts - 1)))}
            if status_code in (410, 413):
                entry["attempts"] = MAX_ATTEMPTS
            ledger[eid] = entry
            accepted += int(success)
    with _locked():
        db = _read()
        # Write only records belonging to currently-active subscription identities.
        db["deliveries"].update(ledger)
        if len(db["deliveries"]) > 4000:
            db["deliveries"] = dict(list(db["deliveries"].items())[-4000:])
        _write(db)
    return {"ok": True, "attempted": attempted, "accepted": accepted}

def main():
    if os.geteuid() == 0:
        raise PermissionError("Events must run as non-root cybernova user")
    command = sys.argv[1] if len(sys.argv) > 1 else ""
    if command == "poll":
        STORE.mkdir(mode=0o700, parents=True, exist_ok=True)
        with (STORE / ".worker.lock").open("a+") as worker_lock:
            try:
                fcntl.flock(worker_lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise RuntimeError("Another Cybernova event worker is already running") from None
            while True:
                try:
                    poll_once()
                except Exception as exc:
                    print(json.dumps({"event_worker_error": type(exc).__name__}), flush=True)
                time.sleep(30)
    else:
        params = json.load(sys.stdin)
        if command == "list":
            result = event_catalog()
        elif command == "subscribe":
            result = subscribe(params)
        elif command == "unsubscribe":
            result = unsubscribe(params)
        elif command == "poll-once":
            result = poll_once()
        else:
            raise ValueError("Unknown event command")
        print(json.dumps(result, ensure_ascii=False))

if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(json.dumps({"error": type(exc).__name__, "message": str(exc)[:180]}))
        sys.exit(1)
