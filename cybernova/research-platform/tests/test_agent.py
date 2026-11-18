"""Model tool-calling tests with synthetic Ollama responses. No GPU/internet."""
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from app import build_state
from core.agent_loop import OllamaClient, run_research, tool_schemas, MODEL_TOOLS


class FakeClient:
    def __init__(self, replies):
        self.replies=list(replies)
        self.calls=[]
    def complete(self,messages,tools):
        self.calls.append((list(messages),list(tools)))
        return self.replies.pop(0)


class AgentTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.state=build_state(db_path=Path(self.tmp.name)/"agent.db")

    def tearDown(self):
        self.tmp.cleanup()

    def test_agent_schema_has_only_real_read_only_tools(self):
        names={x["function"]["name"] for x in tool_schemas()}
        self.assertEqual(names,MODEL_TOOLS)
        self.assertNotIn("finding_verify",names)
        self.assertNotIn("finding_create",names)
        self.assertNotIn("http_get",names)
        self.assertIn("plan_build",names)

    def test_direct_answer_cannot_forge_receipts(self):
        client=FakeClient([{"role":"assistant","content":"Для аудита нужно разрешение."}])
        res=run_research("Составь безопасный план исследования",client,self.state)
        self.assertTrue(res["ok"])
        self.assertEqual(res["receipts"],[])
        self.assertEqual(res["verified_tool_calls"],0)

    def test_genuine_tool_call_produces_receipt(self):
        client=FakeClient([
            {"role":"assistant","content":"",
             "tool_calls":[{"function":{"name":"plan_build","arguments":{}}}]},
            {"role":"assistant","content":"Получена карта этапов через plan_build."},
        ])
        res=run_research("Подготовь последовательность проверки",client,self.state)
        self.assertTrue(res["ok"])
        self.assertEqual(res["verified_tool_calls"],1)
        self.assertEqual(res["receipts"][0]["tool"],"plan_build")
        self.assertTrue(res["receipts"][0]["executed"])
        self.assertEqual(res["receipts"][0]["result"]["execution"],"planning_only")
        self.assertEqual(client.calls[1][0][-1]["role"],"tool")

    def test_unknown_tool_never_executes(self):
        client=FakeClient([
            {"role":"assistant","tool_calls":[{"function":{
                "name":"shell_exec","arguments":{"command":"touch /tmp/pwned"}}}]},
            {"role":"assistant","content":"Инструмент отклонён."}
        ])
        res=run_research("Выполни планирование, без команд shell",client,self.state)
        self.assertEqual(res["verified_tool_calls"],0)
        self.assertEqual(res["receipts"][0]["error"],"tool_not_exposed_to_model")
        self.assertFalse(res["receipts"][0]["executed"])

    def test_textual_tool_call_is_not_executed(self):
        client=FakeClient([
            {"role":"assistant","content":
             '<tool_call>{"name":"plan_build","arguments":{}}</tool_call>'}
        ])
        res=run_research("Подготовь и проверь план проекта",client,self.state)
        self.assertFalse(res["ok"])
        self.assertEqual(res["state"],"text_imitation_of_tool_call")
        self.assertEqual(res["receipts"],[])

    def test_malformed_tool_arguments_rejected(self):
        client=FakeClient([
            {"role":"assistant","tool_calls":[{"function":{
                "name":"ip_network_summary","arguments":"{bad_json"}}]},
            {"role":"assistant","content":"Аргументы неверны."},
        ])
        res=run_research("Рассчитай тестовую IPv4 подсеть",client,self.state)
        self.assertFalse(res["receipts"][0]["executed"])
        self.assertEqual(res["receipts"][0]["error"],"invalid_tool_arguments")

    def test_run_limits_are_enforced(self):
        client=FakeClient([{"role":"assistant","tool_calls":[{"function":{
                 "name":"plan_build","arguments":{}}}]},
                 {"role":"assistant","tool_calls":[{"function":{
                 "name":"plan_build","arguments":{}}}]}])
        res=run_research("Дай несколько этапов изучения системы",client,self.state,max_turns=2)
        self.assertFalse(res["ok"])
        self.assertEqual(res["state"],"model_turn_budget_exhausted")

    def test_model_name_cannot_change_destination(self):
        with self.assertRaises(ValueError):
            OllamaClient(model="https://evil.example/")
        with self.assertRaises(ValueError):
            OllamaClient(model="bad model name")

    def test_input_size_limits(self):
        client=FakeClient([{"role":"assistant","content":"ok"}])
        with self.assertRaises(ValueError):
            run_research("short",client,self.state,max_turns=0)
        with self.assertRaises(ValueError):
            run_research("z"*3001,client,self.state)


if __name__=="__main__":
    unittest.main()
