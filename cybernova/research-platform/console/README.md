# Cybernova Chat Console — собственный простой чат

Отдельный интерфейс для локальной Qwen и существующего MCP gateway: список диалогов слева, переписка по центру, поле ввода снизу, результаты инструментов под ответом.

## Схема

    Браузер (SSH port-forward)
      → FastAPI 127.0.0.1:18794
      → Ollama 127.0.0.1:11434 / cybernova-security:30b
      → tool_calls Qwen (native или строго валидированный JSON)
      → MCP 127.0.0.1:18792/mcp
      → 6 существующих инструментов

Open WebUI и MCPO не требуются. Нет платного API или прямого shell от модели. Полный набор 87 возможностей ещё не подключён.

## Безопасность и ограничения

- Максимум 6 вызовов инструментов и 3 модельных цикла на сообщение.
- Публичный HTTP GET по умолчанию выключен. Его можно разрешить отдельно для одного сообщения, максимум 3 GET.
- Даже при включении GET доступ возможен только к точным хостам, которые уже разрешены через существующий MCP gateway. Сам шлюз контролирует DNS, TLS, HTTP методы, перенаправления и интервал запросов.
- Другие 5 инструментов выполняют локальные или офлайн-операции.
- Контекст хранится только в оперативной памяти Python и не сохраняется на диск. После перезапуска диалоги исчезнут.
- Веб-сервер слушает исключительно 127.0.0.1. Приложение пока не поддерживает аккаунты, поэтому открывать его в интернет запрещено. Используйте аутентифицированный SSH-туннель.

## Запуск из отдельной копии ветки feature/cybernova-chat-console

    cd cybernova/research-platform
    python3 -m venv /workspace/cybernova-chat-venv
    /workspace/cybernova-chat-venv/bin/pip install -r console/requirements.txt
    /workspace/cybernova-chat-venv/bin/python -m unittest discover -s tests -v
    /workspace/cybernova-chat-venv/bin/python console/server.py

Сервер поднимется по адресу http://127.0.0.1:18794 на Vast.

На домашнем Windows PowerShell настройте SSH-проброс того же порта, используя реальный endpoint и ключ от Vast:

    ssh -L 18794:127.0.0.1:18794 root@YOUR_VAST_SSH_ENDPOINT

Затем откройте на своём ноутбуке http://127.0.0.1:18794/.

## Автономный тест без сетевых обращений к целям

    cd cybernova/research-platform
    python3 -m unittest discover -s tests -p 'test_*.py' -v
    node --check console/static/app.js
    python3 -m compileall -q console

Acceptance: /api/status показывает реальный Ollama и MCP, Qwen выбирает ip_network_summary для 192.0.2.7/24, в чате появляется настоящий MCP receipt; запрещённые цели и неизвестные инструменты блокируются.
