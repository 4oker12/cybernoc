"""Regression: evidence review runs after tool activity, not every chat turn."""
from pathlib import Path
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))

from console.agent import Agent


TOOL = {
    "name": "gateway_status",
    "description": "Read the configured gateway status.",
    "inputSchema": {
        "type": "object", "properties": {}, "required": [],
        "additionalProperties": False,
    },
}


def gateway_call():
    return {
        "role": "assistant", "content": "",
        "tool_calls": [{"function": {"name": "gateway_status", "arguments": {}}}],
    }


class ScriptedModel:
    model="scripted-review-model"
    def __init__(self,replies):
        self.replies=list(replies)
        self.calls=[]
    def chat(self,messages,tools=None,**kwargs):
        self.calls.append({"messages":messages,"tools":tools})
        if not self.replies:
            raise AssertionError("no_model_reply")
        reply=self.replies.pop(0)
        return reply if isinstance(reply,dict) else {
            "role":"assistant","content":reply,
        }


class FakeMCP:
    def initialize(self):
        return [TOOL]
    def call(self,name,args):
        if name=="gateway_status":
            return {"ok":True,"authorized_hosts":["example.org"]},False
        return {"ok":False,"error":"unknown_tool"},True


class AnswerSecondPassTests(unittest.TestCase):
    def test_second_pass_catches_error_before_answer_is_returned(self):
        draft="MTU 1500 подтверждён."
        revised="MTU 1500 не подтверждён; доступные данные показывают только таймауты."
        model=ScriptedModel([gateway_call(),draft,revised])
        result=Agent(ollama=model,mcp_factory=lambda:FakeMCP()).run(
            [],"Разбери таймауты VPN",tools_enabled=True,force_tools=False
        )
        self.assertEqual(result["answer"],revised)
        self.assertEqual(result["review"]["status"],"completed")
        self.assertEqual(result["review"]["passes"],2)
        self.assertEqual(result["review"]["scope"],"existing_evidence_only")
        self.assertEqual(len(model.calls),3)
        self.assertEqual(model.calls[2]["tools"],[])
        self.assertIn("ПРОВЕРЬ КАЧЕСТВО ИТОГА",str(model.calls[2]["messages"]))
        self.assertNotIn("Повторная проверка",result["answer"])

    def test_review_failure_is_reported_and_draft_is_preserved(self):
        draft="Первый проход: диагностика пока недостаточна."
        model=ScriptedModel([gateway_call(),draft])
        result=Agent(ollama=model,mcp_factory=lambda:FakeMCP()).run(
            [],"В чём причина?",tools_enabled=True,force_tools=False
        )
        self.assertEqual(result["answer"],draft)
        self.assertEqual(result["review"]["status"],"unavailable")
        self.assertEqual(result["review"]["passes"],1)
        self.assertEqual(result["review"]["reason"],"AssertionError")
        self.assertEqual(len(model.calls),3)

    def test_review_accepts_concise_answer_without_fixed_report_section(self):
        draft="## Вывод\nПока недостаточно данных."
        concise="По доступным данным причина пока не установлена."
        model=ScriptedModel([gateway_call(),draft,concise])
        result=Agent(ollama=model,mcp_factory=lambda:FakeMCP()).run(
            [],"Что обнаружено?",tools_enabled=True,force_tools=False
        )
        self.assertEqual(result["answer"],concise)
        self.assertEqual(result["review"]["status"],"completed")
        self.assertNotIn("second_pass_missing_required_section",result["review"])


if __name__=="__main__":
    unittest.main()
