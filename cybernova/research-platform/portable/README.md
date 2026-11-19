# Cybernova Portable — установка и перенос

Цель: Cybernova как переносимый самостоятельный продукт на Vast, VPS, Linux
или Windows (Docker Desktop). Исходники и история релизов находятся в приватном
GitHub, рабочие данные — в отдельном Docker-томе, резервные копии — вне сервера.

## Архитектура

В одном непривилегированном контейнере:
- Cybernova Web UI, localhost:18794;
- агент с динамически обнаруживаемыми MCP-функциями, офлайн-анализаторами,
  инструментами разработки и интерактивным Chromium;
- MCP Tool Gateway, localhost:18792;
- Communication MCP, localhost:18796;
- Basic-auth gateway, порт 18795 — единственный публикуемый порт.

Отдельно запускается Ollama (опционально) либо используется удалённая модель
с API /v1/chat/completions. В Git не хранятся модельные веса, секреты,
незашифрованные дампы или исследования.

## Нативная установка без Docker — для арендованного Vast-контейнера

В арендованном Vast.ai экземпляре Docker Engine внутри контейнера часто
недоступен. В этом случае используй native.py: он создаст отдельный Python
venv и приватный каталог данных, не меняя системный Python.

~~~bash
git clone --branch feature/cybernova-chat-console git@github.com:4oker12/cybernoc.git
cd cybernoc/cybernova/research-platform/portable
python3 native.py --data-dir /workspace/cybernova-portable-data wizard
~~~

Мастер выбирает Ollama либо внешний OpenAI-совместимый API, устанавливает
Python-зависимости в отдельный venv и запускает все три внутренних сервиса
через tmux (если установлен). Для локальной Ollama она уже должна быть
установлена на хосте с нужной моделью; скрипт не скачивает веса незаметно.
В качестве стартовой модели можно указать уже установленную Heretic 30B.

Проверка:

~~~bash
python3 native.py --data-dir /workspace/cybernova-portable-data doctor
~~~

Собственный Web UI: http://127.0.0.1:18795/ внутри Vast; с ноутбука
подключаться через SSH -L или защищённый туннель. Пароль хранится в
/workspace/cybernova-portable-data/web_access.txt. Не публиковать его.

Нативный режим также имеет шифрование и восстановление:

~~~bash
python3 native.py --data-dir /workspace/cybernova-portable-data init-backup-key
python3 native.py --data-dir /workspace/cybernova-portable-data export-backup-key --to /SECURE_OFFLINE/cybernova-backup.key
python3 native.py --data-dir /workspace/cybernova-portable-data backup --to /SECURE_OFFLINE/backups
python3 native.py --data-dir /workspace/cybernova-portable-data stage-restore --from /SECURE_OFFLINE/backups/ARCHIVE.cnbk --key-file /SECURE_OFFLINE/cybernova-backup.key
~~~

Важно: путь /workspace сохраняется после удаления аренды ТОЛЬКО если это
действительно подключённое постоянное хранилище Vast. Проверить тип тома
до работы, а копии обязательно переносить за пределы арендуемой машины.

## Установка — новый Vast/Linux

Необходимы Docker + Compose, Python 3.10+, Git и доступ к приватному GitHub.

~~~bash
git clone --branch feature/cybernova-chat-console git@github.com:4oker12/cybernoc.git
cd cybernoc/cybernova/research-platform/portable
python3 manage.py wizard
~~~

Мастер предлагает Ollama (режим 1) или внешний OpenAI-совместимый API (режим 2),
запрашивает модель, согласие на передачу данных внешнему провайдеру и скрытый
ключ, затем может собрать и запустить Docker. Большие модели не скачиваются
без отдельного согласия. Под Windows: py manage.py wizard после запуска Docker
Desktop (Linux Containers / WSL2).

Первая локальная тестовая модель в мастере: qwen2.5-coder:7b.
Это НЕ кастомная Qwen3-Coder Heretic 30B, использовавшаяся на Vast.
Её веса/Modelfile нужно переносить отдельно с проверкой SHA-256 и лицензии.

Без мастера, Ollama:

~~~bash
python3 manage.py init --provider ollama --model qwen2.5-coder:7b
python3 manage.py up
python3 manage.py pull-model
python3 manage.py doctor
~~~

С NVIDIA Container Toolkit: python3 manage.py up --gpu

Внешний провайдер:

~~~bash
python3 manage.py init --provider openai_compatible --model MODEL_ID --base-url https://provider.example/v1
python3 manage.py set-key
python3 manage.py up
python3 manage.py doctor
~~~

Подписка на сайт ChatGPT НЕ обеспечивает платный или бесплатный API-доступ.
Удалённые API обычно оплачиваются и получают запросы, сообщения и результаты
инструментов — не направляй конфиденциальные данные неподходящему провайдеру.
Для локального vLLM / LM Studio тоже можно использовать OpenAI-совместимый
API, если модель поддерживает нужные функции. Не все провайдеры полностью
совместимы со всеми настройками tool calling.

Адаптер отправляет только нужные поля совместимого Chat Completions API.
Для моделей с префиксами `gpt-5`, `gpt-6`, `o1`, `o3`, `o4` он
выбирает `max_completion_tokens`; остальные по умолчанию используют
`max_tokens`. При необходимости явно задай переменную
`CYBERNOVA_LLM_TOKEN_PARAMETER=max_completion_tokens` (или `max_tokens`).
`temperature` по умолчанию не передаётся — часть reasoning-моделей не
поддерживает это поле. При подтверждённой поддержке провайдером можно
использовать `CYBERNOVA_LLM_TEMPERATURE=0.2`. Проверка реального API,
tool calling, лимитов и стоимости выполняется отдельно с выбранным ключом.


## DeepSeek — облачная модель

Portable включает отдельный preset для официального DeepSeek API. Текущая
рекомендуемая модель по официальной документации — `deepseek-flash`
(DeepSeek-V4.1-Flash). OpenAI-compatible endpoint:
`https://api.deepseek.com/chat/completions`.

Для чистой установки:

~~~bash
python manage.py init --provider deepseek --model deepseek-flash
python manage.py set-key
python manage.py up
python manage.py doctor
~~~

Ключ вводится скрыто и хранится в приватном Docker volume, не в Git и не в
.env. По умолчанию включены DeepSeek Thinking и reasoning_effort=high.
Адаптер сохраняет reasoning_content в пределах многошагового tool-calling
цикла, как требует официальная документация DeepSeek. DeepSeek получает
историю диалога и результаты вызванных инструментов; не передавайте ему
секреты, закрытые клиентские данные и производственные дампы без отдельной
оценки обработки данных провайдером.

## Изолированный Chromium

В portable Docker-образ устанавливается Chromium для Playwright. Агент получает
одну изолированную браузерную сессию на чат, не подключается к личному Chrome
и не читает его cookies или профиль.

Автоматические действия: открыть публичную HTTPS-страницу, читать DOM и
видимые элементы, переходить по ссылкам, заполнять обычные поля, выбирать
опции, нажимать обычные кнопки и возвращаться назад. Поля паролей, токенов и
платёжных реквизитов запрещены. Загрузки файлов отключены. URL с локальными
или приватными адресами, небезопасные схемы и нестандартные порты блокируются.

Отправка формы/подтверждение вынесены в отдельный `browser_submit`: этот вызов
требует явного разрешения пользователя и допускает не более одного POST
на текущий origin. Другие write-методы, cross-origin POST и WebSockets блокируются.
Высокоэффектные кнопки (оплата, заказ, бронирование, подтверждение) не
нажимаются обычным `browser_click_button`.

Тексты страниц, ссылки и DOM считаются недоверенными данными, а не
инструкциями для модели. При облачном DeepSeek содержимое страницы,
которое модель использует для анализа, отправляется в DeepSeek API.

## Интерфейс

На хосте: http://127.0.0.1:18795/ , логин cybernova.
Пароль автоматически создаётся в Docker-томе /data/web_access.txt.
Получить только локально:

~~~bash
docker compose exec -T cybernova cat /data/web_access.txt
~~~

SSH к удалённой машине:

~~~bash
ssh -L 18795:127.0.0.1:18795 USER@SERVER
~~~

В браузере того же ноутбука открыть http://127.0.0.1:18795/.

Необязательный HTTPS Quick Tunnel: python3 manage.py up --tunnel
Адрес появится в docker compose --profile tunnel logs cloudflared.
Quick Tunnel временен; для постоянного доступа нужны стабильный домен,
отдельная аутентификация (например Cloudflare Access/SSO/MFA) и политика ACL.
Никогда не публиковать Ollama, внутренний MCP или SQLite наружу.

## Git — код, версия и целостность

~~~bash
python3 manage.py verify-source
python3 manage.py export-source --to /SECURE_OFFLINE/source
~~~

В GitHub Actions дополнительно работает `repo_guard.py`: сборка падает,
если в Git случайно добавлены SQLite-БД, HAR/PCAP, ключи, зашифрованные
архивы или большие веса моделей. Он проверяет имена и размеры отслеживаемых
файлов, но не заменяет полноценный секрет-сканер и контроль доступа.

verify-source запускает git fsck и показывает SHA коммита. Docker-образ
маркируется org.opencontainers.image.revision, а код проверяется GitHub CI.
export-source создаёт проверяемый Git bundle с SHA-256 для офлайн-копии кода.

Рекомендуется защитить main: PR, обязательный CI, review, запрет force-push,
подписанные релизные теги и проверка обновлений. SHA-256 обнаруживает
случайную порчу, но для защиты от подмены источника нужны доверенные ключи
подписи и защищённые права GitHub.

## Данные — зашифрованные копии, не Git

Рабочая история: приватный именованный Docker-том cybernova_data.
Запустить один раз создание ключа и ОБЯЗАТЕЛЬНО сохранить его ВНЕ Vast:

~~~bash
python3 manage.py init-backup-key
python3 manage.py export-backup-key --to /SECURE_OFFLINE/cybernova-backup.key
~~~

Создать и проверить копию:

~~~bash
python3 manage.py backup --to /SECURE_OFFLINE/backups
~~~

SQLite online backup учитывает WAL и проходит integrity_check.
Данные шифруются AES-256-GCM, манифест хранит SHA-256 зашифрованного архива.
Пара файлов .cnbk и .cnbk.manifest.json переносится вместе. Без сохранённого
backup.key архив не восстановить. Держи ключ и архив в РАЗНЫХ местах.

На новой машине подготовь проект и Docker, затем:

~~~bash
python3 manage.py stage-restore --from /SECURE_OFFLINE/backups/cybernova-YYYYMMDDTHHMMSSZ.cnbk --key-file /SECURE_OFFLINE/cybernova-backup.key
~~~

Команда отправляет ключ и зашифрованный снимок в Docker через stdin,
проверяет аутентичность/SQLite и создаёт НОВЫЙ файл
/data/communications-restored.sqlite3. Действующую историю не перезаписывает.
Перед активацией ОБЯЗАТЕЛЬНО остановить сервисы, сравнить восстановленные
данные, сохранить старую базу и только затем выполнить контролируемый
перенос. Автоматическая перезапись отключена намеренно.

Облачный API-ключ не включён в бэкап БД; после переезда его вводят заново.
Модельные веса хранят отдельно (не в Git). Снимок SQLite ограничен 128 MiB.
Для больших PCAP/HAR нужен самостоятельный зашифрованный object storage.

## Диагностика и ограничения

~~~bash
python3 manage.py doctor
python3 manage.py logs
python3 manage.py stop
~~~

doctor проверяет Web UI и MCP, но НЕ гарантирует авторизацию облачного API
или реальную генерацию модели: отправь один безопасный тестовый вопрос.
Для модели Heretic 30B потребуются её конкретные веса и подходящий GPU.

GitHub CI собирает образ и запускает тесты. Это не равно проверенному
переносу реальной базы на вторую машину: эксплуатационное acceptance
тестирование новой системы и автоматизация offsite-копий — отдельная фаза.
Сканерные бинарники НЕ включены в минимальный образ, одобрение внешних
целей по умолчанию выключено. GitHub не заменяет резервные копии.


## Восстановление сразу в пустую базу (новый хост)

Режим stage-restore выше подходит для осмотра снимка без активации.
Для **полностью новой** установки добавлены отдельные команды:

~~~bash
# Сначала init, но не запускайте up.
python3 manage.py init --provider ollama --model qwen2.5-coder:7b
python3 manage.py import-backup-key --from /SECURE_OFFLINE/cybernova-backup.key
python3 manage.py restore --from /SECURE_OFFLINE/backups/cybernova-YYYYMMDDTHHMMSSZ.cnbk
python3 manage.py up
python3 manage.py doctor
~~~

При восстановлении запускается одноразовый контейнер, каталог архива монтируется
**только на чтение**, а библиотека backup.py проверяет манифест, AES-GCM и
SQLite integrity. Операция прекращается, если сервис cybernova работает,
или если /data/communications.sqlite3 уже существует. **Данные не сливаются
и не перезаписываются.** Пароль Web UI и API-ключи необходимо настроить заново.

Не используйте этот сценарий для существующей Vast-базы без предварительной
проверки, что она создана именно переносимым стеком и содержит требуемые данные.
