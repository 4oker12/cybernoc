"""Ephemeral, session-bound owner input broker; secrets never enter model history."""
from __future__ import annotations
import re
import secrets
import threading
import time
from urllib.parse import urlsplit

try:
    from .account_vault import account_vault, AccountVaultError
except ImportError:
    from account_vault import account_vault, AccountVaultError


class OwnerInputError(ValueError):
    pass


class OwnerInputBroker:
    MAX_ACTIVE = 24
    TTL_SECONDS = 300

    def __init__(self):
        self._lock = threading.RLock()
        self._requests = {}
        self._by_session = {}

    @staticmethod
    def _session(value):
        if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_:-]{16,120}", value):
            raise OwnerInputError("owner_input_session_invalid")
        return value

    @staticmethod
    def _clean(value, name, limit):
        if not isinstance(value, str) or not value.strip() or len(value) > limit or "\x00" in value:
            raise OwnerInputError("owner_input_" + name + "_invalid")
        return value.strip()

    def request_and_wait(
        self, session_id, purpose, input_type, field_label, timeout=300, *,
        expected_origin="", offer_vault_save=False, service="", username="", account_label="",
    ):
        session_id = self._session(session_id)
        purpose = self._clean(purpose, "purpose", 240)
        field_label = self._clean(field_label, "field_label", 120)
        if input_type not in {"otp", "password", "contact"}:
            raise OwnerInputError("owner_input_type_invalid")
        if not isinstance(offer_vault_save, bool):
            raise OwnerInputError("owner_input_vault_option_invalid")
        if expected_origin:
            try:
                parsed = urlsplit(expected_origin)
                if (parsed.scheme != "https" or not parsed.hostname or parsed.username
                        or parsed.password or parsed.path not in {"", "/"}
                        or parsed.query or parsed.fragment):
                    raise ValueError
                expected_origin = "https://" + parsed.hostname.lower()
                if parsed.port not in (None, 443):
                    raise ValueError
            except (ValueError, TypeError):
                raise OwnerInputError("owner_input_origin_invalid") from None
        if offer_vault_save:
            if input_type != "password" or not expected_origin:
                raise OwnerInputError("owner_input_vault_save_not_available")
            service = self._clean(service, "service", 120)
            username = self._clean(username, "username", 254)
            account_label = account_label.strip() if isinstance(account_label, str) else ""
            if len(account_label) > 120 or "\x00" in account_label:
                raise OwnerInputError("owner_input_account_label_invalid")
        with self._lock:
            self._expire_locked()
            if session_id in self._by_session:
                raise OwnerInputError("owner_input_already_pending")
            if len(self._requests) >= self.MAX_ACTIVE:
                raise OwnerInputError("owner_input_capacity_reached")
            request_id = "oin_" + secrets.token_urlsafe(18)
            item = {
                "request_id": request_id, "session_id": session_id,
                "purpose": purpose, "input_type": input_type,
                "field_label": field_label, "created_at": time.monotonic(),
                "expected_origin": expected_origin,
                "offer_vault_save": offer_vault_save, "service": service,
                "username": username, "account_label": account_label,
                "vault_record_id": None,
                "event": threading.Event(), "status": "pending", "value": None,
            }
            self._requests[request_id] = item
            self._by_session[session_id] = request_id
        signalled = item["event"].wait(max(1, min(int(timeout), self.TTL_SECONDS)))
        with self._lock:
            current = self._requests.get(request_id)
            if not signalled or current is None or current["status"] != "submitted":
                if current is not None:
                    self._drop_locked(request_id)
                return {"ok": False, "status": "owner_input_cancelled_or_expired"}
            result = {"ok": True, "status": "owner_input_ready",
                      "request_id": request_id, "input_type": input_type,
                      "field_label": field_label}
            if current.get("vault_record_id"):
                result["vault_record_id"] = current["vault_record_id"]
            return result

    def pending(self, session_id):
        session_id = self._session(session_id)
        with self._lock:
            self._expire_locked()
            request_id = self._by_session.get(session_id)
            item = self._requests.get(request_id) if request_id else None
            if item is None or item["status"] != "pending":
                return None
            return {"request_id": item["request_id"], "purpose": item["purpose"],
                    "input_type": item["input_type"], "field_label": item["field_label"],
                    "vault_save_available": bool(item["offer_vault_save"]),
                    "account_label": item["account_label"]}

    def submit(self, session_id, request_id, value, save_to_vault=False):
        session_id = self._session(session_id)
        if not isinstance(save_to_vault, bool):
            raise OwnerInputError("owner_input_vault_option_invalid")
        if not isinstance(request_id, str) or not re.fullmatch(r"oin_[A-Za-z0-9_-]{16,64}", request_id):
            raise OwnerInputError("owner_input_request_invalid")
        if not isinstance(value, str) or not value or len(value) > 512 or "\x00" in value:
            raise OwnerInputError("owner_input_value_invalid")
        with self._lock:
            self._expire_locked()
            item = self._requests.get(request_id)
            if item is None or item["session_id"] != session_id or item["status"] != "pending":
                raise OwnerInputError("owner_input_request_not_active")
            kind = item["input_type"]
            if kind == "otp" and not re.fullmatch(r"\d{4,8}", value.strip()):
                raise OwnerInputError("owner_input_otp_format_invalid")
            if kind == "password" and not 8 <= len(value) <= 256:
                raise OwnerInputError("owner_input_password_length_invalid")
            if kind == "contact" and len(value.strip()) < 3:
                raise OwnerInputError("owner_input_contact_invalid")
            if save_to_vault:
                if kind != "password" or not item.get("offer_vault_save"):
                    raise OwnerInputError("owner_input_vault_save_not_available")
                try:
                    record = account_vault().store_password(
                        item["service"], item["username"], value,
                        item["expected_origin"], item["account_label"],
                    )
                    item["vault_record_id"] = record["record_id"]
                except AccountVaultError:
                    raise OwnerInputError("owner_input_vault_store_failed") from None
            item["value"] = value
            item["status"] = "submitted"
            item["event"].set()
        return {"ok": True, "accepted": True}

    def consume(self, session_id, request_id):
        session_id = self._session(session_id)
        if not isinstance(request_id, str):
            raise OwnerInputError("owner_input_request_invalid")
        with self._lock:
            self._expire_locked()
            item = self._requests.get(request_id)
            if item is None or item["session_id"] != session_id or item["status"] != "submitted":
                raise OwnerInputError("owner_input_not_ready_or_already_used")
            value, kind, expected_origin = (
                item["value"], item["input_type"], item.get("expected_origin", "")
            )
            self._drop_locked(request_id)
        if not isinstance(value, str):
            raise OwnerInputError("owner_input_value_missing")
        return kind, value, expected_origin

    def cancel(self, session_id, request_id):
        session_id = self._session(session_id)
        with self._lock:
            item = self._requests.get(request_id)
            if item is None or item["session_id"] != session_id:
                return {"ok": True, "cancelled": False}
            item["status"] = "cancelled"
            item["value"] = None
            item["event"].set()
            self._drop_locked(request_id)
        return {"ok": True, "cancelled": True}

    def _drop_locked(self, request_id):
        item = self._requests.pop(request_id, None)
        if item is not None and self._by_session.get(item["session_id"]) == request_id:
            self._by_session.pop(item["session_id"], None)
        if item is not None:
            item["value"] = None

    def _expire_locked(self):
        now = time.monotonic()
        for request_id, item in list(self._requests.items()):
            if now - item["created_at"] > self.TTL_SECONDS:
                item["status"] = "expired"
                item["value"] = None
                item["event"].set()
                self._drop_locked(request_id)


owner_input_broker = OwnerInputBroker()
