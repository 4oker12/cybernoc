"""Bounded built-in task guidance and per-run failure suppression.
Skills are advisory and never authorize tools or change scope.
"""
from __future__ import annotations

import hashlib
import json
import re

SKILLS = (
    ("Windows Administrator", r"windows|powershell|драйвер|процесс|служб|ноутбук|компьютер", "Проверь ОС, процессы, владельцев портов и состояние службы. Начинай с чтения, используй штатные средства, проверяй эффект изменений."),
    ("Web Researcher", r"поиск|поищи|найди|источник|браузер|сайт|ваканси|research|browser", "Сравни несколько независимых источников; прочитай первоисточники, отметь дату и статус доступа. При 403, 429 или CAPTCHA не обходи защиту, используй разрешённые альтернативы."),
    ("NOC Engineer", r"\bdns\b|\btls\b|\bpon\b|\bbgp\b|\bvpn\b|маршрут|сетев|подсет|\bnat\b", "Диагностируй по слоям от линка и адресации до транспортного и прикладного протокола. Отделяй измерения от гипотез."),
    ("Security Auditor", r"аудит|безопасност|security|\bcve\b", "Проверь авторизованный scope, используй допустимые проверки, фиксируй наблюдения, ограничения и меры защиты; не расширяй полномочия."),
    ("Software Developer", r"исходник|код|разработ|рефактор|репозитори|тесты|python|javascript", "Изучи текущую реализацию и тесты, внеси минимальное обратимое изменение, проверь синтаксис, тесты и diff."),
    ("GitHub Engineer", r"github|pull request|коммит|ветк|\bci\b|\bgit\b", "Проверь репозиторий, ветку, HEAD и состояние изменений. Не переписывай историю. Проверяй реальные результаты CI."),
    ("Data Analyst", r"таблиц|логи|\bcsv\b|\bjson\b|статистик|выгрузк|документ", "Проверь структуру, единицы измерения, полноту и происхождение данных; отдели исходные данные от производных."),
    ("Computer Operator", r"окно|приложени|интерфейс|кнопк|скриншот", "Сначала установи точное окно или приложение; сверяй видимое состояние после каждого действия. Не выполняй побочные действия без полномочий."),
)

def select_skill_guidance(text: str) -> str:
    matched = [(name, guidance) for name, pattern, guidance in SKILLS
               if re.search(pattern, text, re.I)][:2]
    if not matched:
        return ""
    return ("Встроенные рабочие навыки (рекомендации, не новые права):\n" +
            "\n".join(name + ": " + guidance for name, guidance in matched))

class FailedCallGuard:
    """Do not automatically replay identical failed actions indefinitely."""
    def __init__(self):
        self._failures = {}

    @staticmethod
    def _key(name, args):
        raw = json.dumps([name, args], sort_keys=True, ensure_ascii=False, default=str)
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def blocked(self, name, args):
        # Only a small known read-only set may be tried a second time.
        # An ambiguous failure of a write or unclassified operation may have
        # already produced side effects; inspect state before doing anything else.
        retryable = {"gateway_status", "local_webui_health", "ip_network_summary",
                     "browser_snapshot", "browser_navigate", "research_source_open",
                     "google_search", "dev_list", "dev_read"}
        return self._failures.get(self._key(name, args), 0) >= (2 if name in retryable else 1)

    def record(self, name, args, failed):
        key = self._key(name, args)
        if failed:
            self._failures[key] = self._failures.get(key, 0) + 1
        else:
            self._failures.pop(key, None)
