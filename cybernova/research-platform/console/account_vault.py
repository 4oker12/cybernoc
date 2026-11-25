"""Encrypted local account-password vault.

Only ciphertext is stored in SQLite. On Windows the vault master key is
wrapped with the current user's DPAPI; on POSIX it is a 0600 key file.
Secrets are returned only to in-process browser-fill code, never to model tools.
"""
from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
from functools import lru_cache
import os
from pathlib import Path
import re
import secrets
import sqlite3
from threading import RLock
from urllib.parse import urlsplit

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    AESGCM = None

try:
    from .communication import _db_path
except ImportError:
    from communication import _db_path

RAW_MAGIC = b"CNAVRAW1\x00"
DPAPI_MAGIC = b"CNAVDP1\x00"
RECORD_ID = re.compile(r"^av_[A-Za-z0-9_-]{16,80}$")


class AccountVaultError(RuntimeError):
    pass


def _utc() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def _clean(value: str, field: str, limit: int) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > limit:
        raise AccountVaultError("invalid_" + field)
    if "\x00" in value:
        raise AccountVaultError("nul_not_allowed")
    return value.strip()


def _origin(value: str) -> str:
    if not isinstance(value, str) or len(value) > 2048:
        raise AccountVaultError("invalid_service_origin")
    try:
        parsed = urlsplit(value)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError
        host = parsed.hostname.lower().rstrip(".")
        if not re.fullmatch(r"[a-z0-9.-]{1,253}", host):
            raise ValueError
        port = parsed.port
        if port not in (None, 443):
            raise ValueError
        return "https://" + host
    except (ValueError, TypeError):
        raise AccountVaultError("invalid_service_origin") from None


def _key_path() -> Path:
    configured = os.environ.get("CYBERNOVA_ACCOUNT_VAULT_KEY_FILE")
    if configured:
        return Path(configured).expanduser()
    return _db_path().expanduser().with_name("account-vault.key")


def _protect_key(key: bytes) -> bytes:
    if os.name != "nt":
        return RAW_MAGIC + key
    try:
        import win32crypt
        _description, protected = win32crypt.CryptProtectData(
            key, "Cybernova account vault", None, None, None, 0,
        )
        return DPAPI_MAGIC + protected
    except Exception:
        raise AccountVaultError("windows_dpapi_key_protection_failed") from None


def _unprotect_key(blob: bytes) -> bytes:
    if os.name != "nt":
        if not blob.startswith(RAW_MAGIC):
            raise AccountVaultError("vault_key_format_invalid")
        key = blob[len(RAW_MAGIC):]
    else:
        if not blob.startswith(DPAPI_MAGIC):
            raise AccountVaultError("vault_key_not_protected_for_current_windows_user")
        try:
            import win32crypt
            _description, key = win32crypt.CryptUnprotectData(
                blob[len(DPAPI_MAGIC):], None, None, None, 0,
            )
        except Exception:
            raise AccountVaultError("windows_dpapi_key_unprotection_failed") from None
    if len(key) != 32:
        raise AccountVaultError("vault_key_length_invalid")
    return key


class AccountVault:
    """AES-256-GCM encrypted passwords with origin-bound browser retrieval."""

    def __init__(self, db_path: str | Path | None = None,
                 key_path: str | Path | None = None):
        if AESGCM is None:
            raise AccountVaultError("cryptography_required")
        self.path = (Path(db_path) if db_path is not None else _db_path()).expanduser().absolute()
        self.key_path = (Path(key_path) if key_path is not None else _key_path()).expanduser().absolute()
        if self.path.is_symlink() or self.key_path.is_symlink():
            raise AccountVaultError("vault_symlink_forbidden")
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.key_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if os.name != "nt":
            self.path.parent.chmod(0o700)
            self.key_path.parent.chmod(0o700)
        self._lock = RLock()
        self._key = self._load_or_create_key()
        self._setup()

    def _load_or_create_key(self) -> bytes:
        if self.key_path.exists():
            if self.key_path.is_symlink() or not self.key_path.is_file():
                raise AccountVaultError("vault_key_file_invalid")
            if os.name != "nt" and self.key_path.stat().st_mode & 0o077:
                raise AccountVaultError("vault_key_permissions_too_open")
            return _unprotect_key(self.key_path.read_bytes())
        key = secrets.token_bytes(32)
        blob = _protect_key(key)
        try:
            fd = os.open(self.key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            return self._load_or_create_key()
        try:
            with os.fdopen(fd, "wb") as output:
                output.write(blob)
                output.flush()
                os.fsync(output.fileno())
        except Exception:
            self.key_path.unlink(missing_ok=True)
            raise
        if os.name != "nt":
            self.key_path.chmod(0o600)
        return key

    @contextmanager
    def _connection(self):
        db = sqlite3.connect(str(self.path), timeout=10, isolation_level=None)
        try:
            db.row_factory = sqlite3.Row
            db.execute("PRAGMA foreign_keys=ON")
            db.execute("PRAGMA busy_timeout=10000")
            with db:
                yield db
        finally:
            db.close()

    def _setup(self):
        with self._lock, self._connection() as db:
            db.executescript("""
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS account_vault_entries (
                    record_id TEXT PRIMARY KEY,
                    service TEXT NOT NULL,
                    account_label TEXT NOT NULL DEFAULT '',
                    username TEXT NOT NULL,
                    origin TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'pending'
                      CHECK(status IN ('pending','active')),
                    nonce BLOB NOT NULL,
                    ciphertext BLOB NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    revision INTEGER NOT NULL DEFAULT 0
                );
                CREATE INDEX IF NOT EXISTS account_vault_recent
                    ON account_vault_entries(updated_at DESC);
                CREATE INDEX IF NOT EXISTS account_vault_lookup
                    ON account_vault_entries(service,origin,username);
            """)
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass

    @staticmethod
    def _metadata(row) -> dict:
        return {key: row[key] for key in (
            "record_id", "service", "account_label", "username", "origin",
            "status", "created_at", "updated_at", "revision",
        )}

    def store_password(self, service: str, username: str, password: str,
                       origin: str, account_label: str = "") -> dict:
        service = _clean(service, "service", 120)
        username = _clean(username, "username", 254)
        account_label = account_label.strip() if isinstance(account_label, str) else ""
        if len(account_label) > 120 or "\x00" in account_label:
            raise AccountVaultError("invalid_account_label")
        if not isinstance(password, str) or not 8 <= len(password) <= 256 or "\x00" in password:
            raise AccountVaultError("invalid_password")
        origin = _origin(origin)
        record_id = "av_" + secrets.token_urlsafe(18)
        nonce = secrets.token_bytes(12)
        aad = (record_id + "\x00" + service + "\x00" + username + "\x00" + origin).encode()
        ciphertext = AESGCM(self._key).encrypt(nonce, password.encode("utf-8"), aad)
        now = _utc()
        with self._lock, self._connection() as db:
            db.execute(
                "INSERT INTO account_vault_entries(record_id,service,account_label,username,"
                "origin,status,nonce,ciphertext,created_at,updated_at) "
                "VALUES(?,?,?,?,?,'pending',?,?,?,?,?)",
                (record_id, service, account_label, username, origin, nonce,
                 ciphertext, now, now),
            )
        return self.get_metadata(record_id)

    def get_metadata(self, record_id: str) -> dict:
        if not isinstance(record_id, str) or not RECORD_ID.fullmatch(record_id):
            raise AccountVaultError("invalid_vault_record_id")
        with self._connection() as db:
            row = db.execute(
                "SELECT * FROM account_vault_entries WHERE record_id=?", (record_id,)
            ).fetchone()
        if row is None:
            raise AccountVaultError("vault_record_not_found")
        return self._metadata(row)

    def list_entries(self, limit: int = 30, service: str = "") -> list[dict]:
        if type(limit) is not int or not 1 <= limit <= 50:
            raise AccountVaultError("invalid_limit")
        if service and (not isinstance(service, str) or len(service) > 120):
            raise AccountVaultError("invalid_service")
        with self._connection() as db:
            if service:
                rows = db.execute(
                    "SELECT * FROM account_vault_entries WHERE service=? "
                    "ORDER BY updated_at DESC LIMIT ?", (service, limit)
                ).fetchall()
            else:
                rows = db.execute(
                    "SELECT * FROM account_vault_entries ORDER BY updated_at DESC LIMIT ?",
                    (limit,),
                ).fetchall()
        return [self._metadata(row) for row in rows]

    def mark_verified(self, record_id: str) -> dict:
        self.get_metadata(record_id)
        with self._lock, self._connection() as db:
            db.execute(
                "UPDATE account_vault_entries SET status='active',updated_at=?,"
                "revision=revision+1 WHERE record_id=?", (_utc(), record_id),
            )
        return self.get_metadata(record_id)

    def _secret_for_browser_fill(self, record_id: str, current_origin: str) -> tuple[dict, str]:
        metadata = self.get_metadata(record_id)
        if metadata["origin"] != _origin(current_origin):
            raise AccountVaultError("vault_origin_mismatch")
        with self._connection() as db:
            row = db.execute(
                "SELECT nonce,ciphertext FROM account_vault_entries WHERE record_id=?",
                (record_id,),
            ).fetchone()
        if row is None:
            raise AccountVaultError("vault_record_not_found")
        aad = (record_id + "\x00" + metadata["service"] + "\x00" +
               metadata["username"] + "\x00" + metadata["origin"]).encode()
        try:
            secret = AESGCM(self._key).decrypt(row["nonce"], row["ciphertext"], aad)
            value = secret.decode("utf-8")
        except Exception:
            raise AccountVaultError("vault_record_authentication_failed") from None
        return metadata, value


@lru_cache(maxsize=1)
def account_vault() -> AccountVault:
    return AccountVault()
