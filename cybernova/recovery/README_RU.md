# Cybernova: повторная установка на новый Vast

Это **исходники в приватной ветке** `cybernova-autodeploy`. Установщик `cybernova/recovery/install.sh` использует `cybernova/v10` и `cybernova/bridge`, ставит Ollama и скачивает `brianmatzelle/qwen3-coder-heretic:30b` (~19 GB).

## На новом Vast
1. Открыть Jupyter Terminal. Получить **read-only** SSH Deploy Key или иной разрешённый приватный доступ к `4oker12/cybernoc`. Не отправлять закрытый ключ или токен в ChatGPT.
2. Клонировать ветку `cybernova-autodeploy` в `/workspace/cybernoc`:
   `git clone --branch cybernova-autodeploy --single-branch git@github.com:4oker12/cybernoc.git /workspace/cybernoc`
3. `bash /workspace/cybernoc/cybernova/recovery/install.sh --check`
4. `bash /workspace/cybernoc/cybernova/recovery/install.sh`

Скрипт устанавливает Agent v1.0 в `/workspace/cybernova-agent` и read-only MCP Bridge в `/workspace/vast-bridge`. Не открывает публичных HTTP-портов и не переносит прежние секреты. Для подключения ChatGPT требуется **отдельно** создать и авторизовать Secure MCP Tunnel; старый MCP, привязанный к удалённому инстансу, автоматически не переключится.

`cybernova/autoupdater/install.sh` и `start_daemon.sh` — отдельный одноразовый этап после первого развёртывания. При их установке агент переводится под управление непривилегированного пользователя, включается проверка GitHub раз в 30 секунд; она не запускается только от коммита.

Есть также автономный ZIP-пакет восстановления из архивов пользователя (`agent v0.7`, `vast-bridge v0.1`) для первой установки **без GitHub-доступа**. ZIP следует получать от пользователя/из доверенной резервной копии, а не из открытого интернета.
