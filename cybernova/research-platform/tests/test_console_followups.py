"""No-network tests for contextual follow-up question generation."""
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from console.followups import generate_followups, normalize_questions, extract_explicit_offers


class FollowupTests(unittest.TestCase):
    def test_explicit_closing_offer_becomes_prompts_and_is_removed_from_display(self):
        answer = (
            "Кусочек 7. Из чего состоит арбитражник\n"
            "Он выбирает товар и запускает рекламу.\n\n"
            "Вот и вся схема. Если интересно — могу разобрать отдельно, куда уходит "
            "каждый рубль на каждом шаге, или показать пример из другой ниши, "
            "например арбитраж трафика."
        )
        result = extract_explicit_offers(answer)
        self.assertIsNotNone(result)
        self.assertEqual(result["answer"], (
            "Кусочек 7. Из чего состоит арбитражник\n"
            "Он выбирает товар и запускает рекламу.\n\n"
            "Вот и вся схема."
        ))
        self.assertEqual(result["questions"], [
            "Разбери отдельно, куда уходит каждый рубль на каждом шаге?",
            "Покажи пример из другой ниши, например арбитраж трафика?",
        ])

    def test_explicit_offer_supports_single_action(self):
        answer = "Итог.\n\nЕсли хочешь, могу подробнее рассказать, как работает эта схема."
        result = extract_explicit_offers(answer)
        self.assertIsNotNone(result)
        self.assertEqual(result["answer"], "Итог.")
        self.assertEqual(result["questions"], [
            "Расскажи подробнее, как работает эта схема?"
        ])

    def test_no_explicit_offer_is_left_unchanged(self):
        self.assertIsNone(extract_explicit_offers("Готово.\n\nПроверка завершена."))

    def test_normalization_deduplicates_and_limits_to_three(self):
        raw = {"questions": [
            "  Что означает ошибка DNS?  ",
            "Что означает ошибка DNS?",
            "Какие данные нужно собрать для диагностики?",
            "Как проверить эту гипотезу локально?",
            "Какая следующая проверка будет полезной?",
        ]}
        self.assertEqual(normalize_questions(raw), [
            "Что означает ошибка DNS?",
            "Какие данные нужно собрать для диагностики?",
            "Как проверить эту гипотезу локально?",
        ])

    def test_malformed_model_text_does_not_forge_questions(self):
        for raw in ("not json", '{"questions":"text"}', "[]", None,
                    {"questions": [3, {"prompt": "Hello"}]},
                    {"wrong": ["Как проверить статус?"]}):
            self.assertEqual(normalize_questions(raw), [])

    def test_oversized_short_and_nonquestions_are_rejected(self):
        raw = {"questions": ["Коротко?", "А" * 161 + "?", "Нужно проверить.",
                            "Как интерпретировать ответ HTTP?"]}
        self.assertEqual(normalize_questions(raw), ["Как интерпретировать ответ HTTP?"])

    def test_single_followup_inference_is_tool_free(self):
        calls = []
        def stub(endpoint, payload, timeout):
            calls.append((endpoint, payload, timeout))
            return {"message": {"content": (
                '{"questions":["Как подтвердить расчёт CIDR?",'
                '"Что означают адреса из этой подсети?"]}'
            )}}
        history = [{"role": "user", "content": "Разбери 192.0.2.7/24"},
                   {"role": "assistant", "content": "Это 192.0.2.0/24."}]
        questions = generate_followups(history, transport=stub)
        self.assertEqual(len(questions), 2)
        self.assertEqual(len(calls), 1)
        endpoint, payload, timeout = calls[0]
        self.assertEqual(endpoint, "http://127.0.0.1:11434/api/chat")
        self.assertEqual(payload["format"], "json")
        self.assertFalse(payload["stream"])
        self.assertNotIn("tools", payload)
        self.assertEqual(payload["messages"][-2:], history)
        self.assertLessEqual(timeout, 120)

    def test_task_and_project_context_are_included_without_tools(self):
        calls = []
        def stub(endpoint, payload, timeout):
            calls.append(payload)
            return {"message": {"content": (
                '{"questions":["Как проверить итоговую сборку интерфейса Cybernova?"]}'
            )}}
        history = [{"role": "user", "content": "Улучши интерфейс Cybernova"},
                   {"role": "assistant", "content": "Нужно проверить сборку."}]
        questions = generate_followups(
            history,
            task_context={
                "title": "Cybernova UI polish",
                "hosts": ["127.0.0.1"],
                "capture_detail": "evidence",
            },
            project_instructions="Исследователь работает в рамках проекта CyberNoc.",
            transport=stub,
        )
        self.assertEqual(len(questions), 1)
        messages = calls[0]["messages"]
        self.assertIn("CyberNoc", messages[0]["content"])
        self.assertIn("Cybernova UI polish", messages[1]["content"])
        self.assertIn("127.0.0.1", messages[1]["content"])
        self.assertEqual(messages[-2:], history)
        self.assertNotIn("tools", calls[0])

    def test_long_history_is_bounded_for_followup_context_window(self):
        captured = []
        def stub(endpoint, payload, timeout):
            captured.append(payload)
            return {"message": {"content": '{"questions":[]}'}}
        history = [
            {"role": "user", "content": "U" * 6000},
            {"role": "assistant", "content": "A" * 9000},
        ]
        self.assertEqual(generate_followups(history, transport=stub), [])
        messages = captured[0]["messages"]
        self.assertLessEqual(len(messages[-2]["content"]), 2200)
        self.assertLessEqual(len(messages[-1]["content"]), 2200)
        self.assertIn("фрагмент сокращён", messages[-1]["content"])

    def test_incomplete_history_does_not_call_model(self):
        called = []
        def stub(*args):
            called.append(args)
            return {"message": {"content": "{}"}}
        invalid = [
            [],
            [{"role": "user", "content": "Hi"}],
            [{"role": "assistant", "content": "A"}, {"role": "assistant", "content": "B"}],
            [{"role": "user", "content": "Hi"}, {"role": "assistant", "content": ""}],
        ]
        for history in invalid:
            self.assertEqual(generate_followups(history, transport=stub), [])
        self.assertFalse(called)

    def test_invalid_qwen_response_returns_empty(self):
        history = [{"role": "user", "content": "Вопрос"},
                   {"role": "assistant", "content": "Ответ"}]
        def stub(*args):
            return {"message": {"content": "Задай что-нибудь дальше..."}}
        self.assertEqual(generate_followups(history, transport=stub), [])


if __name__ == "__main__":
    unittest.main()
