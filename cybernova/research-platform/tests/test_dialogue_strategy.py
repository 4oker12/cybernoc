"""Qwen handles unstructured voice-like questions without excessive pauses."""
import sys
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from console.agent import Agent, BASE_SYSTEM
from console.dialogue_strategy import DIALOGUE_STRATEGY


class SimpleModel:
    model = "qwen-test"
    def __init__(self):
        self.calls = []
    def chat(self, messages, tools=None, **kwargs):
        self.calls.append(messages)
        return {"role":"assistant","content":"Похоже, речь о маршрутизации или RADIUS. Что именно проверить?"}


class EmptyMCP:
    def initialize(self):
        return []


class DialogueStrategyTests(unittest.TestCase):
    def test_strategy_is_given_to_qwen(self):
        model=SimpleModel()
        result=Agent(model,lambda:EmptyMCP()).run(
            [{"role":"user","content":"Проверь путь до BNG"}],
            "ну а вот там де нету его ну куда тогда ?",force_tools=False)
        self.assertIn(DIALOGUE_STRATEGY,model.calls[0][0]["content"])
        self.assertIn("Похоже",result["answer"])

    def test_informal_language_handling_and_choices(self):
        for snippet in ("диктовка", "опечатки", "2–3 варианта",
                        "ОДИН конкретный уточняющий вопрос",
                        "не задавай формальные вопросы",
                        "не меняй содержательный смысл",
                        "продолжай независимый офлайн-анализ",
                        "Не выдумывай «согласие»"):
            with self.subTest(snippet=snippet):
                self.assertIn(snippet,DIALOGUE_STRATEGY)

    def test_does_not_expand_external_testing_scope(self):
        self.assertIn("НЕ угадывай",DIALOGUE_STRATEGY)
        self.assertIn("подтверждения полномочий",DIALOGUE_STRATEGY)
        self.assertIn("предыдущими репликами",DIALOGUE_STRATEGY)


if __name__ == "__main__":
    unittest.main()
