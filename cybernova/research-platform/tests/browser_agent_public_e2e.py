"""Manual model-driven browser check on the project's public GitHub repository."""
from __future__ import annotations

import json
import urllib.error
import urllib.request


def main():
    message = (
        "Открой в настоящем браузере https://github.com/4oker12/cybernoc . "
        "Сориентируйся по странице репозитория, найди видимую ссылку на каталог "
        "cybernova и перейди по ней. Проверь URL и заголовок после перехода. "
        "Верни конечный URL, заголовок страницы и одно название файла или "
        "подкаталога, которое действительно видно в открытом каталоге. "
        "Используй браузерные инструменты; не делай вывод из локальных файлов."
    )
    body = json.dumps({"message": message, "tool_groups": ["browser"]}).encode()
    request = urllib.request.Request(
        "http://127.0.0.1:18794/api/chat", body,
        headers={"Content-Type": "application/json"}, method="POST",
    )
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(request, timeout=240) as response:
            outcome = json.load(response)
    except urllib.error.HTTPError as exc:
        print(f"HTTP {exc.code}: {exc.read(600).decode(errors='replace')}")
        raise SystemExit(2) from None
    events = outcome.get("events") or []
    tools = [e.get("tool") or e.get("name") for e in events if isinstance(e, dict)]
    answer = str(outcome.get("answer", ""))
    checks = {
        "browser_navigate": "browser_navigate" in tools,
        "browser_follow_link": "browser_follow_link" in tools,
        "destination": "github.com/4oker12/cybernoc/tree/main/cybernova" in answer,
    }
    print(json.dumps({"checks": checks, "passed": all(checks.values()),
                      "tool_calls": outcome.get("tool_calls"), "tools": tools,
                      "answer_excerpt": answer[:1800]}, ensure_ascii=True, indent=2))
    if not all(checks.values()):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
