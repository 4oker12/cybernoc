# Cybernova Controller — GitHub handshake v1.2

Только проверка двусторонней связи `ChatGPT → GitHub Issue #1 → Vast Controller → GitHub Issue comment → ChatGPT ACK`. Ни shell-команд, ни установки пакетов, ни изменения модели по содержимому Issue.

- Репозиторий: `4oker12/cybernoc` (private).
- Issue: `https://github.com/4oker12/cybernoc/issues/1`.
- Request ID: `CN-HS-20261117-01`.
- Протокол: `cybernova-handshake/v1`.
- Локальный одноразовый запуск: `python3 handshake.py --issue 1 --request-id CN-HS-20261117-01`.
- Установка контроллера на Vast **пока не выполнена**. Скрипт должен быть доставлен на Vast и запущен **один раз** пользователем `cybernova`; на сервере нужен **fine-grained GitHub token** для единственного репозитория `cybernoc` с правами **Issues Read/Write**, сохранённый оператором в `/workspace/cybernova-updater/secrets/github-issues-token` (0600). Не отправляйте токен в чат, не публикуйте в GitHub.
- После публикации ответного комментария ChatGPT прочтёт JSON, сверит Request ID и отправит `ACK` в Issue.
- Временно `agent_version=not-probed`: handshake сам по себе не запускает Qwen; для доказательства реального Vast потребуется также локальный лог сервера.

Проверка: `python3 -m unittest discover -s tests -v`.

GitHub Issue comments используют тот же GitHub-аккаунт, если подключён персональный токен. Для независимой идентификации в перспективе лучше использовать отдельное приложение GitHub App. Этот тест проверяет двустороннюю доставку, не автономную разработку Qwen.