import threading
import time
import unittest
from unittest.mock import patch
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from console.owner_input import OwnerInputBroker, OwnerInputError


class OwnerInputBrokerTests(unittest.TestCase):
    def test_pending_metadata_never_exposes_submitted_value(self):
        broker = OwnerInputBroker()
        result = {}
        session = "deepseek:" + "a" * 32

        def request():
            result.update(broker.request_and_wait(
                session, "AWS verification", "otp", "Verification code", timeout=3, expected_origin="https://signin.aws.amazon.com"
            ))

        worker = threading.Thread(target=request)
        worker.start()
        deadline = time.monotonic() + 2
        pending = None
        while time.monotonic() < deadline and pending is None:
            pending = broker.pending(session)
            time.sleep(0.01)
        self.assertIsNotNone(pending)
        self.assertNotIn("value", pending)
        broker.submit(session, pending["request_id"], "123456")
        worker.join(2)
        self.assertFalse(worker.is_alive())
        self.assertTrue(result["ok"])
        self.assertNotIn("value", result)
        kind, value, origin = broker.consume(session, result["request_id"])
        self.assertEqual((kind, value, origin), ("otp", "123456", "https://signin.aws.amazon.com"))
        with self.assertRaises(OwnerInputError):
            broker.consume(session, result["request_id"])

    def test_request_is_bound_to_session(self):
        broker = OwnerInputBroker()
        result = {}
        session = "deepseek:" + "b" * 32
        worker = threading.Thread(target=lambda: result.update(
            broker.request_and_wait(session, "Confirm email", "otp", "Code", timeout=3, expected_origin="https://example.com")
        ))
        worker.start()
        deadline = time.monotonic() + 2
        pending = None
        while time.monotonic() < deadline and pending is None:
            pending = broker.pending(session)
            time.sleep(0.01)
        with self.assertRaises(OwnerInputError):
            broker.submit("deepseek:" + "c" * 32, pending["request_id"], "123456")
        broker.submit(session, pending["request_id"], "123456")
        worker.join(2)
        self.assertTrue(result["ok"])

    def test_password_can_be_saved_only_after_owner_opt_in_and_never_returned(self):
        broker = OwnerInputBroker()
        saved = {}
        class FakeVault:
            def store_password(self, service, username, password, origin, account_label):
                saved.update(service=service, username=username, password=password,
                             origin=origin, account_label=account_label)
                return {"record_id": "av_" + "x" * 20, "service": service}

        result = {}
        session = "deepseek:" + "e" * 32
        with patch("console.owner_input.account_vault", return_value=FakeVault()):
            worker = threading.Thread(target=lambda: result.update(
                broker.request_and_wait(
                    session, "Create AWS password", "password", "Password", timeout=3,
                    expected_origin="https://signin.aws.amazon.com",
                    offer_vault_save=True, service="AWS",
                    username="owner@example.net", account_label="personal",
                )
            ))
            worker.start()
            deadline = time.monotonic() + 2
            pending = None
            while time.monotonic() < deadline and pending is None:
                pending = broker.pending(session)
                time.sleep(0.01)
            self.assertTrue(pending["vault_save_available"])
            broker.submit(session, pending["request_id"], "LongRandomPassword!123",
                          save_to_vault=True)
            worker.join(2)
        self.assertTrue(result["ok"])
        self.assertEqual(result["vault_record_id"], "av_" + "x" * 20)
        self.assertNotIn("password", result)
        self.assertEqual(saved["origin"], "https://signin.aws.amazon.com")
        kind, value, origin = broker.consume(session, result["request_id"])
        self.assertEqual(kind, "password")
        self.assertEqual(value, "LongRandomPassword!123")
        self.assertEqual(origin, "https://signin.aws.amazon.com")

    def test_vault_save_is_rejected_for_otp_or_without_offer(self):
        broker = OwnerInputBroker()
        with self.assertRaises(OwnerInputError):
            broker.request_and_wait(
                "deepseek:" + "f" * 32, "OTP", "otp", "Code",
                expected_origin="https://example.com", offer_vault_save=True,
                service="AWS", username="owner@example.net",
            )

    def test_payment_card_is_one_time_and_never_returned_in_request_metadata(self):
        broker = OwnerInputBroker()
        result = {}
        session = "deepseek:" + "g" * 32
        field_hosts = {
            "card_number": "signin.aws.amazon.com",
            "expiry": "js.stripe.com",
            "cvv": "js.stripe.com",
            "cardholder_name": "signin.aws.amazon.com",
        }
        worker = threading.Thread(target=lambda: result.update(
            broker.request_and_wait(
                session, "AWS asks to verify the payment method", "payment_card",
                "Payment card", timeout=3,
                expected_origin="https://signin.aws.amazon.com",
                payment_fields=list(field_hosts),
                payment_field_hosts=field_hosts,
            )
        ))
        worker.start()
        deadline = time.monotonic() + 2
        pending = None
        while time.monotonic() < deadline and pending is None:
            pending = broker.pending(session)
            time.sleep(0.01)
        self.assertIsNotNone(pending)
        self.assertEqual(pending["payment_frame_hosts"], ["js.stripe.com"])
        self.assertEqual(pending["expected_origin"], "https://signin.aws.amazon.com")
        self.assertNotIn("value", pending)
        self.assertNotIn("card_number", pending)
        card = {
            "card_number": "4242 4242 4242 4242",
            "expiry_month": "12", "expiry_year": "30",
            "cvv": "123", "cardholder_name": "Test Owner",
        }
        broker.submit(
            session, pending["request_id"], payment_card=card,
            approved_frame_hosts=["js.stripe.com"],
        )
        worker.join(2)
        self.assertFalse(worker.is_alive())
        self.assertTrue(result["ok"])
        self.assertNotIn("4242424242424242", str(result))
        consumed, origin, hosts, approved = broker.consume_payment_card(
            session, result["request_id"]
        )
        self.assertEqual(consumed["card_number"], "4242424242424242")
        self.assertEqual(origin, "https://signin.aws.amazon.com")
        self.assertEqual(hosts, field_hosts)
        self.assertEqual(approved, ["js.stripe.com"])
        for key in list(consumed):
            consumed[key] = ""
        consumed.clear()

    def test_payment_card_requires_luhn_and_explicit_external_frame_approval(self):
        broker = OwnerInputBroker()
        result = {}
        session = "deepseek:" + "h" * 32
        field_hosts = {
            "card_number": "signin.aws.amazon.com",
            "expiry": "signin.aws.amazon.com",
            "cvv": "signin.aws.amazon.com",
        }
        worker = threading.Thread(target=lambda: result.update(
            broker.request_and_wait(
                session, "Verify card", "payment_card", "Card", timeout=3,
                expected_origin="https://signin.aws.amazon.com",
                payment_fields=list(field_hosts), payment_field_hosts=field_hosts,
            )
        ))
        worker.start()
        deadline = time.monotonic() + 2
        pending = None
        while time.monotonic() < deadline and pending is None:
            pending = broker.pending(session)
            time.sleep(0.01)
        with self.assertRaisesRegex(OwnerInputError, "checksum_invalid"):
            broker.submit(
                session, pending["request_id"],
                payment_card={
                    "card_number": "4242424242424241",
                    "expiry_month": "12", "expiry_year": "30", "cvv": "123",
                },
                approved_frame_hosts=[],
            )
        with self.assertRaisesRegex(OwnerInputError, "frame_approval_invalid"):
            broker.submit(
                session, pending["request_id"],
                payment_card={
                    "card_number": "4242424242424242",
                    "expiry_month": "12", "expiry_year": "30", "cvv": "123",
                },
                approved_frame_hosts=["attacker.example"],
            )
        broker.submit(
            session, pending["request_id"],
            payment_card={
                "card_number": "4242424242424242",
                "expiry_month": "12", "expiry_year": "30", "cvv": "123",
            },
            approved_frame_hosts=[],
        )
        worker.join(2)
        self.assertTrue(result["ok"])
        consumed, _origin, _hosts, _approved = broker.consume_payment_card(
            session, result["request_id"]
        )
        self.assertEqual(consumed["card_number"], "4242424242424242")

    def test_payment_confirmation_is_one_shot_and_bound_to_button_and_origin(self):
        broker = OwnerInputBroker()
        result = {}
        session = "deepseek:" + "i" * 32
        worker = threading.Thread(target=lambda: result.update(
            broker.request_and_wait(
                session, "AWS may place a temporary card authorization; no recurring plan shown",
                "payment_confirmation", "Verify payment method", timeout=3,
                expected_origin="https://signin.aws.amazon.com",
                action_origin="https://payments.aws.amazon.com",
                action_button="Verify payment method",
            )
        ))
        worker.start()
        deadline = time.monotonic() + 2
        pending = None
        while time.monotonic() < deadline and pending is None:
            pending = broker.pending(session)
            time.sleep(0.01)
        self.assertEqual(pending["action_button"], "Verify payment method")
        self.assertEqual(pending["action_origin"], "https://payments.aws.amazon.com")
        broker.submit(session, pending["request_id"], decision=True)
        worker.join(2)
        self.assertTrue(result["ok"])
        decision, origin, action_origin, button = broker.consume_payment_confirmation(
            session, result["request_id"]
        )
        self.assertTrue(decision)
        self.assertEqual(origin, "https://signin.aws.amazon.com")
        self.assertEqual(action_origin, "https://payments.aws.amazon.com")
        self.assertEqual(button, "Verify payment method")
        with self.assertRaises(OwnerInputError):
            broker.consume_payment_confirmation(session, result["request_id"])

    def test_card_details_are_not_an_allowed_input_type(self):
        broker = OwnerInputBroker()
        with self.assertRaises(OwnerInputError):
            broker.request_and_wait("deepseek:" + "d" * 32, "Pay AWS", "card", "Card", timeout=1)


if __name__ == "__main__":
    unittest.main()
