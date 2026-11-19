"""Official OpenAI Sign in with ChatGPT for Cybernova's single-user localhost UI.

OAuth Authorization Code + PKCE, verified OpenID Connect ID token, server-only
credentials, token refresh. Never reuse ChatGPT web cookies or internal APIs.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
from threading import RLock
import time
from urllib import error, parse, request
from uuid import uuid4

import jwt

ISSUER = "https://auth.openai.com"
AUTH = ISSUER + "/api/accounts/authorize"
TOKEN = ISSUER + "/api/accounts/oauth/token"
REVOKE = ISSUER + "/api/accounts/oauth/revoke"
JWKS = ISSUER + "/.well-known/jwks.json"
RESOURCE = "https://api.openai.com/v1"
SCOPES = "openid profile email offline_access resource.invoke chatgpt.tokens.use.direct"
OAUTH_TTL = 600
MODEL_NAME = re.compile(r"^[A-Za-z0-9_.:/+-]{1,160}$")


class SIWCError(ValueError):
    pass


def _post(url: str, fields: dict) -> dict:
    body = parse.urlencode(fields).encode()
    req = request.Request(url, data=body, method="POST",
                          headers={"Content-Type": "application/x-www-form-urlencoded",
                                   "Accept": "application/json"})
    try:
        with request.build_opener(request.ProxyHandler({})).open(req, timeout=20) as r:
            raw = r.read(1_000_001)
    except error.HTTPError as e:
        raise SIWCError("oauth_http_" + str(e.code)) from None
    except (OSError, TimeoutError):
        raise SIWCError("oauth_unavailable") from None
    if url == REVOKE and not raw:
        return {"ok": True}
    if len(raw) > 1_000_000:
        raise SIWCError("oauth_reply_too_large")
    try:
        value = json.loads(raw)
    except ValueError:
        raise SIWCError("oauth_reply_invalid") from None
    if not isinstance(value, dict):
        raise SIWCError("oauth_reply_invalid")
    return value


def _verify(token: str, client_id: str, nonce: str) -> dict:
    try:
        key = jwt.PyJWKClient(JWKS, cache_keys=True).get_signing_key_from_jwt(token).key
        claims = jwt.decode(token, key, algorithms=["RS256"], issuer=ISSUER,
                            audience=client_id, leeway=5,
                            options={"require": ["sub", "exp", "iat", "nonce"]})
    except (jwt.PyJWTError, ValueError, OSError):
        raise SIWCError("id_token_invalid") from None
    if not isinstance(claims.get("sub"), str) or not claims["sub"] or (
        not secrets.compare_digest(str(claims.get("nonce", "")), nonce)
    ):
        raise SIWCError("id_token_identity_or_nonce_invalid")
    return claims


class Connection:
    def __init__(self, directory: Path | None = None):
        self.directory = Path(directory or os.environ.get(
            "CYBERNOVA_SIWC_DIR", str(Path.home() / ".local/share/cybernova/siwc")))
        self.lock = RLock()
        self.pending = None

    def _directory(self):
        if self.directory.is_symlink():
            raise SIWCError("credential_directory_symlink")
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        if os.name != "nt":
            self.directory.chmod(0o700)

    def _load(self) -> dict | None:
        path = self.directory / "connection.json"
        if not path.exists():
            return None
        if path.is_symlink():
            raise SIWCError("credential_symlink")
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            raise SIWCError("credential_store_invalid") from None
        if not isinstance(data, dict) or not isinstance(data.get("client_id"), str):
            raise SIWCError("credential_store_invalid")
        return data

    def _write(self, path: Path, data: bytes):
        self._directory()
        if path.is_symlink():
            raise SIWCError("credential_symlink")
        temp = path.with_name(path.name + "." + secrets.token_hex(8))
        try:
            with os.fdopen(os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            os.replace(temp, path)
        finally:
            temp.unlink(missing_ok=True)

    def _save(self, data: dict):
        self._write(self.directory / "connection.json",
                    json.dumps(data, ensure_ascii=False).encode("utf-8"))

    def _host(self) -> str:
        path = self.directory / "host-id.txt"
        if path.exists():
            if path.is_symlink():
                raise SIWCError("host_id_symlink")
            value = path.read_text(encoding="utf-8").strip()
            if not value.startswith("urn:uuid:"):
                raise SIWCError("host_id_invalid")
            return value
        host = "urn:uuid:" + str(uuid4())
        self._write(path, host.encode())
        return host

    def status(self) -> dict:
        with self.lock:
            record = self._load()
            return {"connected": bool(record),
                    "plan_usage": bool(record and "chatgpt.tokens.use.direct" in record.get("scopes", [])),
                    "email": record.get("email", "") if record else "",
                    "callback_port": int(os.environ.get("CYBERNOVA_SIWC_CALLBACK_PORT", "18794")),
                    "mode": "official_chatgpt_oauth"}

    def start(self) -> dict:
        with self.lock:
            port = int(os.environ.get("CYBERNOVA_SIWC_CALLBACK_PORT", "18794"))
            if port not in (18794, 18795):
                raise SIWCError("callback_port_invalid")
            previous = self._load()
            client = previous["client_id"] if previous else "dynamic_agent_client"
            verifier = secrets.token_urlsafe(48)
            challenge = base64.urlsafe_b64encode(
                hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
            state, nonce = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
            redirect = "http://127.0.0.1:" + str(port) + "/auth/callback"
            self.pending = {"state": state, "nonce": nonce, "verifier": verifier,
                            "redirect": redirect, "client": client, "at": time.monotonic()}
            options = {
                "client_id": client, "response_type": "code", "redirect_uri": redirect,
                "resource": RESOURCE, "scope": SCOPES, "state": state, "nonce": nonce,
                "code_challenge": challenge, "code_challenge_method": "S256",
                "ext_agent_host_id": self._host(),
            }
            if not previous:
                options["agent_name_hint"] = "Cybernova"
            return {"authorization_url": AUTH + "?" + parse.urlencode(options),
                    "callback_uri": redirect}

    def finish(self, params: dict) -> dict:
        with self.lock:
            pending, self.pending = self.pending, None  # always consume exactly once
            if not pending or time.monotonic() - pending["at"] > OAUTH_TTL or (
                not isinstance(params.get("state"), str) or
                not secrets.compare_digest(pending["state"], params["state"])
            ):
                raise SIWCError("oauth_state_invalid_or_expired")
            if params.get("error"):
                raise SIWCError("oauth_declined")
            code = params.get("code")
            client = params.get("client_id") or pending["client"]
            if not isinstance(code, str) or not 10 <= len(code) <= 4096 or (
                not isinstance(client, str) or len(client) > 200 or
                not client.startswith("oaiapp_")
            ):
                raise SIWCError("oauth_code_or_client_missing")
            if pending["client"] != "dynamic_agent_client" and client != pending["client"]:
                raise SIWCError("oauth_client_mismatch")
            result = _post(TOKEN, {"grant_type": "authorization_code", "client_id": client,
                                   "code": code, "code_verifier": pending["verifier"],
                                   "redirect_uri": pending["redirect"], "resource": RESOURCE})
            id_token = result.get("id_token")
            if not isinstance(id_token, str) or not id_token:
                raise SIWCError("id_token_missing")
            identity = _verify(id_token, client, pending["nonce"])
            previous = self._load()
            if previous and previous["client_id"] == client and previous.get("subject") != identity["sub"]:
                raise SIWCError("account_identity_changed")
            scopes = str(result.get("scope", "")).split()
            access, refresh = result.get("access_token"), result.get("refresh_token")
            if "chatgpt.tokens.use.direct" in scopes and not (
                isinstance(access, str) and access and
                isinstance(refresh, str) and refresh
            ):
                raise SIWCError("plan_credentials_missing")
            expiry = result.get("expires_in", 3600)
            if not isinstance(expiry, int) or not 1 <= expiry <= 86400:
                raise SIWCError("oauth_expiry_invalid")
            self._save({
                "client_id": client, "subject": identity["sub"],
                "email": identity.get("email", "") if identity.get("email_verified") is True else "",
                "id_token": id_token, "access_token": access or "",
                "refresh_token": refresh or "", "scopes": scopes,
                "expires_at": int(time.time()) + expiry, "host_id": self._host(),
            })
            return self.status()

    def access(self) -> str:
        # Lock serializes refresh-token rotation in this single-user runtime.
        with self.lock:
            info = self._load()
            if not info or "chatgpt.tokens.use.direct" not in info.get("scopes", []):
                raise SIWCError("chatgpt_plan_usage_not_authorized")
            if info.get("expires_at", 0) > time.time() + 90:
                return info["access_token"]
            if not info.get("refresh_token"):
                raise SIWCError("chatgpt_reauthorization_required")
            fresh = _post(TOKEN, {"grant_type": "refresh_token",
                                  "client_id": info["client_id"],
                                  "refresh_token": info["refresh_token"], "resource": RESOURCE})
            scopes = str(fresh.get("scope", "")).split()
            if "chatgpt.tokens.use.direct" not in scopes or not all(
                isinstance(fresh.get(k), str) and fresh[k]
                for k in ("access_token", "refresh_token")
            ):
                raise SIWCError("chatgpt_permission_or_refresh_invalid")
            info.update({"access_token": fresh["access_token"],
                         "refresh_token": fresh["refresh_token"], "scopes": scopes,
                         "expires_at": int(time.time()) + int(fresh.get("expires_in", 3600))})
            self._save(info)
            return info["access_token"]

    def disconnect(self) -> dict:
        with self.lock:
            info = self._load()
            self.pending = None
            revoked = False
            if info and info.get("refresh_token"):
                try:
                    _post(REVOKE, {"token": info["refresh_token"],
                                   "token_type_hint": "refresh_token",
                                   "client_id": info["client_id"]})
                    revoked = True
                except SIWCError:
                    pass
            path = self.directory / "connection.json"
            if path.is_symlink():
                raise SIWCError("credential_symlink")
            path.unlink(missing_ok=True)
            return {"connected": False, "remote_revoked": revoked,
                    "remote_revocation_warning": not revoked}


connection = Connection()
