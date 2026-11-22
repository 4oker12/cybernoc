"""Regression: every completed DeepSeek answer receives a bounded second evidence review."""
from pathlib import Path
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))

from console.agent import Agent


class ScriptedModel:
    model="scripted-review-model"
    def __init__(self,replies):
        self.replies=list(replies)
        self.calls=[]
    def chat(self,messages,tools=None,**kwargs):
        self.calls.append({"messages":messages,"tools":tools})
        if not self.replies:
            raise AssertionError("no_model_reply")
        return {"role":"assistant","content":self.replies.pop(0)}


class AnswerSecondPassTests(unittest.TestCase):
    def test_second_pass_catches_error_before_answer_is_returned(self):
        draft="## Вывод\nMTU 1500 подтверждён.\n\n## Что проверено\nЕсть наблюдение о таймаутах."
        revised=(
            "## Вывод\n**MTU 1500 не подтверждён**; требуется измерение.\n\n"
            "## Что проверено\nПодтверждено только наличие таймаутов.\n\n"
            "## Повторная проверка\nОбнаружено при повторной проверке: "
            "в черновике MTU 1500 ошибочно назван проверенным. Исправлено.\n\n"
            "## Ограничения\nНет фактического вывода MTU интерфейса.\n\n"
            "## Рекомендации по приоритету\n**P1** — измерить MTU."
        )
        model=ScriptedModel([draft,revised])
        result=Agent(ollama=model).run(
            [],"Разбери таймауты VPN",tools_enabled=False,force_tools=False
        )
        self.assertEqual(result["answer"],revised)
        self.assertEqual(result["review"]["status"],"completed")
        self.assertEqual(result["review"]["passes"],2)
        self.assertEqual(result["review"]["scope"],"existing_evidence_only")
        self.assertEqual(len(model.calls),2)
        self.assertEqual(model.calls[1]["tools"],[])
        self.assertIn("ОБЯЗАТЕЛЬНЫЙ ВТОРОЙ ПРОХОД",str(model.calls[1]["messages"]))

    def test_review_failure_is_reported_and_draft_is_preserved(self):
        draft="Первый проход: диагностика пока недостаточна."
        model=ScriptedModel([draft])
        result=Agent(ollama=model).run(
            [],"В чём причина?",tools_enabled=False,force_tools=False
        )
        self.assertEqual(result["answer"],draft)
        self.assertEqual(result["review"]["status"],"unavailable")
        self.assertEqual(result["review"]["passes"],1)
        self.assertEqual(result["review"]["reason"],"AssertionError")
        self.assertEqual(len(model.calls),2)

    def test_review_without_required_section_is_not_marked_complete(self):
        draft="## Вывод\nПока недостаточно данных."
        model=ScriptedModel([draft,"Да, точно."])
        result=Agent(ollama=model).run(
            [],"Что обнаружено?",tools_enabled=False,force_tools=False
        )
        self.assertEqual(result["answer"],draft)
        self.assertEqual(result["review"]["status"],"incomplete")
        self.assertEqual(result["review"]["reason"],"second_pass_missing_required_section")


if __name__=="__main__":
    unittest.main()
