"""Qwen mission tests: initiative without unauthorised execution."""
import sys
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from console.agent import Agent, BASE_SYSTEM
from console.research_mission import RESEARCH_MISSION


class RecordingModel:
    model = "cybernova-test"
    def __init__(self):
        self.prompts = []
    def chat(self, messages, tools=None, **kwargs):
        self.prompts.append(messages)
        return {"role": "assistant", "content": "Данные исследованы, нужны уточнения."}


class EmptyMCP:
    def initialize(self):
        return []


class ResearchMissionTests(unittest.TestCase):
    def test_research_mission_reaches_agent_system_prompt(self):
        qwen = RecordingModel()
        result = Agent(qwen, lambda: EmptyMCP()).run(
            [], "Проведи офлайн-анализ учебного DHCP лога", force_tools=False
        )
        self.assertTrue(qwen.prompts)
        system = qwen.prompts[0][0]
        self.assertEqual(system["role"], "system")
        self.assertIn(RESEARCH_MISSION, system["content"])
        self.assertIn("Данные исследованы", result["answer"])
        self.assertEqual(result["tool_calls"], 0)

    def test_mission_trains_cross_layer_hypothesis_reasoning(self):
        for term in ("ONU", "OLT/PON", "VLAN/QinQ", "BNG/BRAS", "RADIUS",
                     "NAT/CGNAT", "PCAP/HAR", "первопричина",
                     "ГИПОТЕЗЫ", "ДОКАЗАТЕЛЬСТВА", "ПЕРЕСМОТРИ"):
            with self.subTest(term=term):
                self.assertIn(term, RESEARCH_MISSION)

    def test_initiative_and_consent_are_both_explicit(self):
        for statement in (
            "Самостоятельно продолжай разбор",
            "Не спрашивай разрешения на каждый",
            "Составь запрос человеку",
            "Дождись явного согласования",
            "продолжай все независимые допустимые",
            "не предоставляет\nправ на чужую инфраструктуру",
            "не отменяет проверки прав на объект",
        ):
            with self.subTest(statement=statement):
                self.assertIn(statement, RESEARCH_MISSION)

    def test_active_testing_is_proposed_not_blanket_refused(self):
        self.assertNotIn("не запускай атакующие проверки", BASE_SYSTEM)
        self.assertIn("Активные проверки можно предлагать", BASE_SYSTEM)
        self.assertIn("после необходимого согласования", BASE_SYSTEM)
        self.assertIn("Не превращай необходимость согласования в отказ", BASE_SYSTEM)

    def test_neo_metaphor_teaches_initiative_not_fantasy(self):
        self.assertIn("ПРОФИЛЬ «НЕО»", RESEARCH_MISSION)
        self.assertIn("ДЕЙСТВУЙ, А НЕ ЖДИ", RESEARCH_MISSION)
        self.assertIn("не утверждение\\nоб особых свойствах модели", RESEARCH_MISSION)
        self.assertIn("Не считай метафору «Нео»", RESEARCH_MISSION)
        self.assertIn("Не скрывай полезное действие", RESEARCH_MISSION)

    def test_base_safety_policy_not_overridden(self):
        self.assertIn("Если инструмент требует разрешения", BASE_SYSTEM)
        self.assertIn("Не имитируй вызовы", BASE_SYSTEM)
        self.assertIn("Не расширяй scope", RESEARCH_MISSION)


if __name__ == "__main__":
    unittest.main()
