"""Offline tests for encrypted local account credential storage."""
from contextlib import closing
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from console.account_vault import AccountVault, AccountVaultError


class AccountVaultTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.db = self.root / "communications.sqlite3"
        self.key = self.root / "account-vault.key"
        self.vault = AccountVault(self.db, self.key)

    def test_password_is_encrypted_and_metadata_never_returns_secret(self):
        entry = self.vault.store_password(
            "AWS", "owner@example.net", "LongRandomPassword!123",
            "https://signin.aws.amazon.com", "personal",
        )
        self.assertEqual(entry["status"], "pending")
        self.assertNotIn("password", entry)
        with closing(sqlite3.connect(self.db)) as db, db:
            row = db.execute(
                "SELECT ciphertext FROM account_vault_entries WHERE record_id=?",
                (entry["record_id"],),
            ).fetchone()
        self.assertNotIn(b"LongRandomPassword!123", row[0])
        self.assertNotIn(b"LongRandomPassword!123", self.db.read_bytes())
        metadata, secret = self.vault._secret_for_browser_fill(
            entry["record_id"], "https://signin.aws.amazon.com/path",
        )
        self.assertEqual(metadata["username"], "owner@example.net")
        self.assertEqual(secret, "LongRandomPassword!123")

    def test_password_cannot_be_filled_on_another_origin(self):
        entry = self.vault.store_password(
            "AWS", "owner@example.net", "LongRandomPassword!123",
            "https://signin.aws.amazon.com",
        )
        with self.assertRaisesRegex(AccountVaultError, "origin_mismatch"):
            self.vault._secret_for_browser_fill(
                entry["record_id"], "https://console.aws.amazon.com",
            )

    def test_mark_verified_and_list_do_not_expose_ciphertext(self):
        entry = self.vault.store_password(
            "AWS", "owner@example.net", "LongRandomPassword!123",
            "https://signin.aws.amazon.com",
        )
        active = self.vault.mark_verified(entry["record_id"])
        self.assertEqual(active["status"], "active")
        listed = self.vault.list_entries()
        self.assertEqual(len(listed), 1)
        self.assertNotIn("ciphertext", listed[0])
        self.assertNotIn("nonce", listed[0])

    def test_tampered_ciphertext_fails_authentication(self):
        entry = self.vault.store_password(
            "AWS", "owner@example.net", "LongRandomPassword!123",
            "https://signin.aws.amazon.com",
        )
        with closing(sqlite3.connect(self.db)) as db, db:
            row = db.execute(
                "SELECT ciphertext FROM account_vault_entries WHERE record_id=?",
                (entry["record_id"],),
            ).fetchone()
            changed = bytes([row[0][0] ^ 1]) + row[0][1:]
            db.execute(
                "UPDATE account_vault_entries SET ciphertext=? WHERE record_id=?",
                (changed, entry["record_id"]),
            )
        with self.assertRaisesRegex(AccountVaultError, "authentication_failed"):
            self.vault._secret_for_browser_fill(
                entry["record_id"], "https://signin.aws.amazon.com",
            )

    def test_key_file_permissions_and_origin_validation(self):
        if os.name != "nt":
            self.assertEqual(self.key.stat().st_mode & 0o777, 0o600)
        with self.assertRaises(AccountVaultError):
            self.vault.store_password(
                "AWS", "owner@example.net", "LongRandomPassword!123",
                "http://signin.aws.amazon.com",
            )

    def test_missing_key_with_existing_entries_fails_closed(self):
        self.vault.store_password(
            "AWS", "owner@example.net", "LongRandomPassword!123",
            "https://signin.aws.amazon.com",
        )
        self.key.unlink()
        with self.assertRaisesRegex(AccountVaultError, "key_missing_existing_records"):
            AccountVault(self.db, self.key)

    def test_reopen_uses_same_key_and_database(self):
        entry = self.vault.store_password(
            "AWS", "owner@example.net", "LongRandomPassword!123",
            "https://signin.aws.amazon.com",
        )
        reopened = AccountVault(self.db, self.key)
        _metadata, secret = reopened._secret_for_browser_fill(
            entry["record_id"], "https://signin.aws.amazon.com",
        )
        self.assertEqual(secret, "LongRandomPassword!123")


if __name__ == "__main__":
    unittest.main()
