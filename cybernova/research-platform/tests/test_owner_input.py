import threading
import time
import unittest

from console.owner_input import OwnerInputBroker, OwnerInputError


class OwnerInputBrokerTests(unittest.TestCase):
    def test_pending_metadata_never_exposes_submitted_value(self):
        broker = OwnerInputBroker()
        result = {}
        session = "deepseek:" + "a" * 32

        def request():
            result.update(broker.request_and_wait(
                session, "AWS verification", "otp", "Verification code", timeout=3
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
        kind, value = broker.consume(session, result["request_id"])
        self.assertEqual((kind, value), ("otp", "123456"))
        with self.assertRaises(OwnerInputError):
            broker.consume(session, result["request_id"])

    def test_request_is_bound_to_session(self):
        broker = OwnerInputBroker()
        result = {}
        session = "deepseek:" + "b" * 32
        worker = threading.Thread(target=lambda: result.update(
            broker.request_and_wait(session, "Confirm email", "otp", "Code", timeout=3)
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

    def test_card_details_are_not_an_allowed_input_type(self):
        broker = OwnerInputBroker()
        with self.assertRaises(OwnerInputError):
            broker.request_and_wait("deepseek:" + "d" * 32, "Pay AWS", "card", "Card", timeout=1)


if __name__ == "__main__":
    unittest.main()
