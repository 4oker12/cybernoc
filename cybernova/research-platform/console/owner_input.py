"""Ephemeral, session-bound owner input broker; secrets never enter model history."""
from __future__ import annotations
import re
import secrets
import threading
import time
from datetime import datetime
from urllib.parse import urlsplit

try:
    from .account_vault import account_vault, AccountVaultError
except ImportError:
    from account_vault import account_vault, AccountVaultError


class OwnerInputError(ValueError):
    pass



_PAYMENT_FIELD_KEYS = frozenset({
    "card_number", "expiry", "expiry_month", "expiry_year", "cvv",
    "cardholder_name", "billing_postal_code",
})
_PAYMENT_REQUIRED_KEYS = frozenset({"card_number", "expiry_month", "expiry_year", "cvv"})


def _normalize_payment_card(value, payment_fields):
    if not isinstance(value, dict):
        raise OwnerInputError("payment_card_payload_invalid")
    expected = set(_PAYMENT_REQUIRED_KEYS)
    if "cardholder_name" in payment_fields:
        expected.add("cardholder_name")
    if "billing_postal_code" in payment_fields:
        expected.add("billing_postal_code")
    if set(value) != expected:
        raise OwnerInputError("payment_card_fields_invalid")
    if any(not isinstance(item, str) for item in value.values()):
        raise OwnerInputError("payment_card_fields_invalid")

    number = re.sub(r"[ -]", "", value["card_number"])
    if not re.fullmatch(r"\d{12,19}", number):
        raise OwnerInputError("payment_card_number_invalid")
    checksum = 0
    for index, digit in enumerate(reversed(number)):
        n = int(digit)
        if index % 2:
            n *= 2
            if n > 9:
                n -= 9
        checksum += n
    if checksum % 10:
        raise OwnerInputError("payment_card_number_checksum_invalid")

    month = value["expiry_month"].strip()
    year = value["expiry_year"].strip()
    if not re.fullmatch(r"(?:0[1-9]|1[0-2])", month):
        raise OwnerInputError("payment_card_expiry_month_invalid")
    if not re.fullmatch(r"(?:\d{2}|\d{4})", year):
        raise OwnerInputError("payment_card_expiry_year_invalid")
    year_full = int(year) if len(year) == 4 else 2000 + int(year)
    now = datetime.now()
    if year_full < now.year or (year_full == now.year and int(month) < now.month):
        raise OwnerInputError("payment_card_expired")

    cvv = value["cvv"].strip()
    if not re.fullmatch(r"\d{3,4}", cvv):
        raise OwnerInputError("payment_card_security_code_invalid")

    normalized = {
        "card_number": number,
        "expiry_month": month,
        "expiry_year": year,
        "cvv": cvv,
    }
    if "cardholder_name" in expected:
        name = value["cardholder_name"].strip()
        if not 2 <= len(name) <= 80 or "\x00" in name:
            raise OwnerInputError("payment_cardholder_name_invalid")
        normalized["cardholder_name"] = name
    if "billing_postal_code" in expected:
        postal = value["billing_postal_code"].strip()
        if not 2 <= len(postal) <= 20 or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9 -]*", postal):
            raise OwnerInputError("payment_billing_postal_code_invalid")
        normalized["billing_postal_code"] = postal
    return normalized


def _wipe_mapping(value):
    if isinstance(value, dict):
        for key in list(value):
            value[key] = ""
        value.clear()


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
        payment_fields=None, payment_field_hosts=None, action_origin="", action_button="",
    ):
        session_id = self._session(session_id)
        purpose = self._clean(purpose, "purpose", 240)
        field_label = self._clean(field_label, "field_label", 120)
        if input_type not in {"otp", "password", "contact", "payment_card", "payment_confirmation"}:
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
        if input_type in {"payment_card", "payment_confirmation"} and not expected_origin:
            raise OwnerInputError("owner_input_origin_required")
        if input_type != "payment_card":
            payment_fields = []
            payment_field_hosts = {}
        if input_type != "payment_confirmation":
            action_origin = ""
            action_button = ""
        if input_type == "payment_card":
            if offer_vault_save:
                raise OwnerInputError("payment_card_never_saved")
            if not isinstance(payment_fields, (list, tuple)) or not payment_fields:
                raise OwnerInputError("payment_form_fields_invalid")
            payment_fields = list(dict.fromkeys(payment_fields))
            if (any(field not in _PAYMENT_FIELD_KEYS for field in payment_fields)
                    or "card_number" not in payment_fields or "cvv" not in payment_fields
                    or not ("expiry" in payment_fields or
                            {"expiry_month", "expiry_year"}.issubset(payment_fields))):
                raise OwnerInputError("payment_form_fields_invalid")
            if not isinstance(payment_field_hosts, dict) or set(payment_field_hosts) != set(payment_fields):
                raise OwnerInputError("payment_form_hosts_invalid")
            clean_hosts = {}
            for field, host in payment_field_hosts.items():
                if not isinstance(host, str) or not re.fullmatch(r"[a-z0-9.-]{1,253}", host.lower()):
                    raise OwnerInputError("payment_form_hosts_invalid")
                clean_hosts[field] = host.lower().rstrip(".")
            payment_field_hosts = clean_hosts
        elif input_type == "payment_confirmation":
            if offer_vault_save:
                raise OwnerInputError("payment_confirmation_invalid")
            action_button = self._clean(action_button, "action_button", 180)
            try:
                parsed_action = urlsplit(action_origin)
                if (parsed_action.scheme != "https" or not parsed_action.hostname
                        or parsed_action.username or parsed_action.password
                        or parsed_action.port not in (None, 443)
                        or parsed_action.path not in {"", "/"}
                        or parsed_action.query or parsed_action.fragment):
                    raise ValueError
                action_origin = "https://" + parsed_action.hostname.lower()
            except (ValueError, TypeError):
                raise OwnerInputError("payment_action_origin_invalid") from None
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
                "payment_fields": payment_fields,
                "payment_field_hosts": payment_field_hosts,
                "payment_frame_hosts": sorted({
                    host for host in payment_field_hosts.values()
                    if host != urlsplit(expected_origin).hostname.lower()
                }),
                "approved_frame_hosts": [],
                "action_origin": action_origin, "action_button": action_button,
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
                    "account_label": item["account_label"],
                    "payment_fields": list(item["payment_fields"]),
                    "payment_frame_hosts": list(item["payment_frame_hosts"]),
                    "payment_field_hosts": dict(item["payment_field_hosts"]),
                    "action_origin": item["action_origin"],
                    "action_button": item["action_button"]}

    def submit(
        self, session_id, request_id, value=None, save_to_vault=False, *,
        payment_card=None, approved_frame_hosts=None, decision=None,
    ):
        session_id = self._session(session_id)
        if not isinstance(save_to_vault, bool):
            raise OwnerInputError("owner_input_vault_option_invalid")
        if not isinstance(request_id, str) or not re.fullmatch(r"oin_[A-Za-z0-9_-]{16,64}", request_id):
            raise OwnerInputError("owner_input_request_invalid")
        with self._lock:
            self._expire_locked()
            item = self._requests.get(request_id)
            if item is None or item["session_id"] != session_id or item["status"] != "pending":
                raise OwnerInputError("owner_input_request_not_active")
            kind = item["input_type"]
            if kind == "payment_card":
                if value is not None or decision is not None or save_to_vault:
                    raise OwnerInputError("payment_card_payload_invalid")
                normalized = _normalize_payment_card(payment_card, item["payment_fields"])
                if not isinstance(approved_frame_hosts, list) or any(
                    not isinstance(host, str) for host in approved_frame_hosts
                ):
                    raise OwnerInputError("payment_frame_approval_invalid")
                approved = list(dict.fromkeys(host.lower().rstrip(".") for host in approved_frame_hosts))
                if any(host not in item["payment_frame_hosts"] for host in approved):
                    raise OwnerInputError("payment_frame_approval_invalid")
                required_external = set(item["payment_frame_hosts"])
                if not required_external.issubset(set(approved)):
                    raise OwnerInputError("payment_frame_host_approval_required")
                item["approved_frame_hosts"] = approved
                item["value"] = normalized
            elif kind == "payment_confirmation":
                if (type(decision) is not bool or value is not None
                        or payment_card is not None or save_to_vault
                        or approved_frame_hosts not in (None, [])):
                    raise OwnerInputError("payment_confirmation_payload_invalid")
                item["value"] = decision
            else:
                if payment_card is not None or decision is not None or approved_frame_hosts not in (None, []):
                    raise OwnerInputError("owner_input_payload_invalid")
                if not isinstance(value, str) or not value or len(value) > 512 or "\x00" in value:
                    raise OwnerInputError("owner_input_value_invalid")
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
                    except Exception:
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

    def consume_payment_card(self, session_id, request_id):
        session_id = self._session(session_id)
        with self._lock:
            self._expire_locked()
            item = self._requests.get(request_id)
            if (item is None or item["session_id"] != session_id
                    or item["status"] != "submitted" or item["input_type"] != "payment_card"):
                raise OwnerInputError("payment_card_not_ready_or_already_used")
            value = item["value"]
            expected_origin = item["expected_origin"]
            field_hosts = dict(item["payment_field_hosts"])
            approved_hosts = list(item["approved_frame_hosts"])
            self._drop_locked(request_id, clear_value=False)
        if not isinstance(value, dict):
            raise OwnerInputError("payment_card_value_missing")
        return value, expected_origin, field_hosts, approved_hosts

    def consume_payment_confirmation(self, session_id, request_id):
        session_id = self._session(session_id)
        with self._lock:
            self._expire_locked()
            item = self._requests.get(request_id)
            if (item is None or item["session_id"] != session_id
                    or item["status"] != "submitted"
                    or item["input_type"] != "payment_confirmation"):
                raise OwnerInputError("payment_confirmation_not_ready_or_already_used")
            decision = item["value"]
            expected_origin = item["expected_origin"]
            action_origin = item["action_origin"]
            action_button = item["action_button"]
            self._drop_locked(request_id)
        if type(decision) is not bool:
            raise OwnerInputError("payment_confirmation_value_missing")
        return decision, expected_origin, action_origin, action_button

    def cancel(self, session_id, request_id):
        session_id = self._session(session_id)
        with self._lock:
            item = self._requests.get(request_id)
            if item is None or item["session_id"] != session_id:
                return {"ok": True, "cancelled": False}
            item["status"] = "cancelled"
            _wipe_mapping(item.get("value"))
            item["event"].set()
            self._drop_locked(request_id)
        return {"ok": True, "cancelled": True}

    def _drop_locked(self, request_id, *, clear_value=True):
        item = self._requests.pop(request_id, None)
        if item is not None and self._by_session.get(item["session_id"]) == request_id:
            self._by_session.pop(item["session_id"], None)
        if item is not None:
            if clear_value:
                _wipe_mapping(item.get("value"))
            item["value"] = None

    def _expire_locked(self):
        now = time.monotonic()
        for request_id, item in list(self._requests.items()):
            if now - item["created_at"] > self.TTL_SECONDS:
                item["status"] = "expired"
                _wipe_mapping(item.get("value"))
                item["event"].set()
                self._drop_locked(request_id)


owner_input_broker = OwnerInputBroker()
