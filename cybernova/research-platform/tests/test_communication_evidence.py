"""Offline checks of communication evidence provenance and review handoff."""
from __future__ import annotations

from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from console.communication import CommunicationStore, CommunicationError
from console.evidence import EvidenceJournal
from console.communication_tools import CommunicationToolClient

class NoUpstream:
    def initialize(self): return []
    def call(self, name, args): raise AssertionError("Unexpected external call")

class CommunicationEvidenceTests(unittest.TestCase):
    def setUp(self):
        t = tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        self.db = CommunicationStore(Path(t.name) / "cybernova.sqlite3")
        self.tid = self.db.create_task("Исследование учебного API")["task_id"]
        self.journal = EvidenceJournal(self.db)

    def test_qwen_claim_is_persisted_but_unverified(self):
        item = self.journal.record_qwen_claim(
            self.tid, "Ответ API отличается между ролями",
            "Сопоставление ответов", kind="hypothesis",
            source_ref="har:lab-sample", source_sha256="a" * 64,
        )
        self.assertTrue(item["evidence_id"].startswith("ev_"))
        self.assertEqual(item["attribution"], "qwen_reported_unverified")
        reopened = EvidenceJournal(CommunicationStore(self.db.path))
        self.assertEqual(reopened.get_evidence(self.tid, item["evidence_id"]), item)

    def test_tool_receipts_hash_only_no_secrets(self):
        sensitive = "access_token=must-not-be-stored"
        receipts = self.journal.record_tool_events(self.tid, [
            {"type": "tool_result", "name": "ip_network_summary",
             "arguments": {"cidr": "192.0.2.1/24"},
             "result": {"ok": True, "credential": sensitive}, "is_error": False},
            {"type": "approval_required", "name": "lab_nmap_scan",
             "result": {"ok": False}, "is_error": True},
            {"type": "agent_error", "message": sensitive},
        ])
        self.assertEqual(len(receipts), 2)
        rows = self.journal.list_tool_receipts(self.tid)
        self.assertEqual(len(rows), 2)
        self.assertTrue(all(len(x["result_sha256"]) == 64 for x in rows))
        self.assertNotIn(sensitive, str(rows))

    def test_model_claim_does_not_masquerade_as_scan(self):
        claim = self.journal.record_qwen_claim(
            self.tid, "Я якобы запустила Nmap", "Со слов модели")
        self.assertEqual(claim["attribution"], "qwen_reported_unverified")
        self.assertEqual(self.journal.list_tool_receipts(self.tid), [])

    def test_secret_shaped_text_rejected(self):
        for value in ("Authorization: Bearer abc123", "password=aaa", "api_key: xyz"):
            with self.assertRaises(CommunicationError):
                self.journal.record_qwen_claim(self.tid, value, "Метод")

    def test_task_isolation(self):
        x = self.journal.record_qwen_claim(self.tid, "Наблюдение", "Метод")
        other = self.db.create_task("Другой стенд")["task_id"]
        with self.assertRaises(CommunicationError):
            self.journal.get_evidence(other, x["evidence_id"])

    def test_session_bound_qwen_tool(self):
        client = CommunicationToolClient(NoUpstream(), self.db, self.tid)
        self.assertIn("comm_record_evidence", [x["name"] for x in client.initialize()])
        result, failed = client.call("comm_record_evidence", {
            "kind": "observation", "observation": "Найдено два маршрута API",
            "method": "Офлайн-анализ OpenAPI",
        })
        self.assertFalse(failed)
        self.assertEqual(result["attribution"], "qwen_reported_unverified")
        self.assertEqual(len(self.journal.list_evidence(self.tid)), 1)

    def test_review_packet_includes_claims_and_controller_receipts(self):
        self.db.append(self.tid, "human", "instruction",
                       "Проверь лабораторное API", status="running")
        self.db.append(self.tid, "qwen", "result",
                       "Гипотеза об авторизации", status="needs_review")
        self.journal.record_qwen_claim(
            self.tid, "Нужен негативный контроль", "Анализ ответа", kind="hypothesis")
        self.journal.record_tool_events(
            self.tid, [{"type": "tool_result", "name": "gateway_status",
                        "arguments": {}, "result": {"ok": True}}])
        packet = self.journal.review_packet(self.tid)
        self.assertIn("не верифицированы", packet)
        self.assertIn("gateway_status", packet)
        self.assertIn("негативный контроль", packet.lower())
        self.assertLessEqual(len(packet), 35000)

if __name__ == "__main__":
    unittest.main()
