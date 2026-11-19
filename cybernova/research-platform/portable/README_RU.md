# Cybernova Portable — установка на новый Vast, VPS или локальный ПК

**Статус:** переносимое ядро Research Console в ветке feature/cybernova-chat-console. Ветка main ещё не содержит единый production-релиз. Коммит с установщиком не обновляет действующий Vast.

## Что переносится

- Собственный Web Console, Communication MCP, Tool MCP Gateway, SQLite с историей задач.
- Модульный LLM: Ollama либо внешний OpenAI-compatible Chat Completions API. Для облака нужен отдельный API-ключ; подписка ChatGPT Plus его не предоставляет.
- Docker Compose с изолированными MCP/Ollama; опубликован только 127.0.0.1:18795.
- Scope allowlist, одноразовое подтверждение новых действий, журналы доказательств.
- Шифрованная резервная копия SQLite с отдельным ключом и проверкой целостности.

**Пока НЕ входит в единый portable-профиль:** отдельный агент cybernova/v10, Vast-specific MCP bridge, внешний updater, отдельная Event Ring Panel, бинарники всех сканеров, старые файлы/модели с Vast. Их миграция требует отдельной проверки. Успех Docker build не означает завершение полного переезда.

## Требования

Git, Python 3, Docker Engine/Compose v2 или Docker Desktop в режиме Linux containers; Windows PowerShell 5.1+. Для GPU Ollama нужны совместимый NVIDIA драйвер и Container Toolkit. Qwen 30B в Q4 требует приблизительно 19 GB для весов плюс ресурсы на контекст; для первоначального теста можно выбрать меньшую модель. Облачный API может оплачиваться отдельно.

## Установка на чистой машине

SSH-ключ доступа к приватному репозиторию следует настроить локально, не вставляя его в чат.

Linux / Vast:

    git clone --branch feature/cybernova-chat-console git@github.com:4oker12/cybernoc.git
    cd cybernoc
    bash install.sh

Windows PowerShell:

    git clone --branch feature/cybernova-chat-console git@github.com:4oker12/cybernoc.git
    cd cybernoc
    .\install.ps1

Установщик проверит Git remote, полный SHA текущего HEAD, Git/Python/Docker Compose и вызовет существующий мастер portable/manage.py wizard. Мастер запросит подтверждение перед развёртыванием и скачиванием модели. Для привязки к проверенному коммиту можно задать CYBERNOVA_EXPECTED_SHA — при несовпадении скрипт откажет в запуске. SHA — контроль версии, но не подпись автора.

Режим 1: Ollama на собственном ПК или GPU Vast. Модель скачивается после отдельного подтверждения. Режим 2: внешний HTTPS API, ID модели и скрытый ввод ключа. Например, базовый URL OpenAI API: https://api.openai.com/v1. Ключ сохраняется в приватном Docker-томе, а не в Git или .env. Провайдер должен поддерживать Chat Completions и желательно tool calls.

После запуска откройте http://127.0.0.1:18795/ . Для удалённой машины используйте SSH port forwarding или защищённый туннель. Не открывайте наружу MCP, Ollama и внутреннюю панель без авторизации. Логин и пароль создаются при первом запуске; получайте их только локально, через docker compose exec -T cybernova cat /data/web_access.txt из каталога portable.

## Команды из cybernova/research-platform/portable

    python manage.py doctor
    python manage.py logs
    python manage.py stop
    python manage.py up
    python manage.py pull-model
    python manage.py set-key --rotate

Команда stop сохраняет Docker-тома. НЕ используйте docker compose down -v. Инициализация init повторно не нужна, если .env уже создан.

## Backup и миграция

После первого запуска создать ключ один раз и резервировать БД:

    python manage.py init-backup-key
    python manage.py backup --to ./private-backups
    python manage.py export-backup-key --to ./private-backups/backup.key

Экспортировать вне арендуемого сервера .cnbk вместе с .manifest.json; 32-байтный backup.key хранить **отдельно**. Не коммитить .env, SQLite, HAR, PCAP, API-токены, SSH-ключи или архивы. Текущий backup охватывает SQLite размером до 128 MiB, но не весь Vast и не вложения. Для больших БД нужна другая offsite стратегия.

В console.backup уже есть проверяемое расшифрование AES-256-GCM и restore, создающий **новый** файл без перезаписи живой БД. Автоматического безопасного переключения файлов БД в мастере пока нет: перенос истории нужно сначала испытать на тестовом хосте, остановить приложение и заменить БД только после верификации.

## Контроль перед отключением старого Vast

1. Проверка doctor и готовности MCP.
2. Реальный ответ модели и ограниченный инструментальный вызов в Web Console.
3. Подтверждение отказа при выходе за scope.
4. Сохранение диалогов после штатного restart.
5. Шифрованный архив, манифест и ключ вывезены; restore на отдельной машине успешен.
6. Отмечены внешние компоненты, которые не вошли в portable-профиль, и зафиксирован Git SHA.
7. Старый Vast остаётся доступным до завершения всех проверок.

Правило релиза: feature branch → PR → CI → ревью → pinned commit/tag → развёртывание → health check → rollback. Приватность GitHub не заменяет резервные копии и ротацию ключей.
