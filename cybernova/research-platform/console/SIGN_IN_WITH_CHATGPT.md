# Cybernova — Sign in with ChatGPT (official OAuth)

**Статус:** реализация в PR #10, до установки на Vast нужна проверка на чистом
локальном экземпляре и первая интерактивная авторизация в OpenAI.
Это не вход через пароль ChatGPT и не использование внутренних web API.

Основа: официальный OpenAI **Sign in with ChatGPT / ChatGPT plan usage for
open-source or eligible private/local clients**:
- https://developers.openai.com/siwc/token-sharing-open-source
- https://developers.openai.com/siwc/token-sharing-open-source/sign-in
- https://developers.openai.com/siwc/token-sharing-open-source/self-hosted-vms
- https://developers.openai.com/siwc/token-sharing-open-source/models-and-inference
- https://developers.openai.com/siwc/token-sharing-open-source/preview-limitations

## Как подключить

1. Обновить Cybernova до ревизии, содержащей файлы siwc.py и siwc_inference.py,
   установив Python-зависимости. Конфигурация Docker задаёт
   CYBERNOVA_SIWC_DIR=/data/chatgpt-siwc и CYBERNOVA_SIWC_CALLBACK_PORT=18795.
2. **На Vast открывать UI через локальный SSH-проброс**, а не через Quick Tunnel:

~~~bash
ssh -L 18795:127.0.0.1:18795 USER@YOUR_VAST_SSH_ENDPOINT
~~~

3. На своём компьютере открыть http://127.0.0.1:18795/ и пройти Basic Auth
   Cybernova. В верхней панели нажать **ChatGPT**, далее
   **Continue with ChatGPT**.
4. Браузер перейдёт на auth.openai.com. Подтвердить вход и разрешённые
   разрешения. OpenAI вернёт браузер по адресу
   http://127.0.0.1:18795/auth/callback.
5. Сервер одноразово сверяет state, PKCE, клиентский ID, JWT/JWKS подпись,
   issuer, audience, срок действия и nonce. Данные доступа сохраняются
   только в приватном Docker volume, не в localStorage браузера.
6. В Web UI отображается статус, доступные модели аккаунта и действие
   **Проверить текущую задачу через GPT**. В облако отправляется пакет
   текущего исследования **только при явном нажатии**.
7. Ответ GPT выводится в общей ленте и сохраняется в SQLite журнала.
   Кнопка **Передать ответ GPT исследователю Qwen** явно ставит замечание
   в очередь для следующего этапа Qwen.

При запуске Cybernova нативно без Docker на ноутбуке проверьте,
что CYBERNOVA_SIWC_CALLBACK_PORT совпадает с HTTP-портом браузера
(по умолчанию 18794). Для обычного UI на 18795 используется Docker
gateway. OAuth redirect всегда 127.0.0.1, а не публичный адрес.

## Что разрешено, что нет

- Возможность расходовать ChatGPT plan зависит от типа клиента,
  доступности OpenAI и согласия пользователя; некоторые приватные
  приложения не участвуют. Настоящую пригодность определит живой OAuth.
- Один текущий аккаунт на установку. API-ключ для OAuth не требуется.
- Вход не даёт доступа к истории ChatGPT, памяти или пользовательским
  файлам ChatGPT. Это новая модельная сессия, а не данный чат буквально.
- Отдельная кнопка выполняет **текстовую рецензию** через public
  https://api.openai.com/v1/responses. Используется store=false,
  stream=true, без неподдерживаемых опций. Список моделей берётся с
  официального /v1/models. Ни Qwen, ни Controller автоматически не
  выгружают логи, HAR или PCAP.
- Пароли ChatGPT, web cookies и обходные/неофициальные API никогда не
  запрашиваются. Не включайте debug-логирование OAuth callback URL с code.
- Сеансы refresh_token хранятся до отключения; кнопка отключения
  предпринимает попытку их отозвать. При ошибке сети следует отключить
  доступ в настройках ChatGPT (Security and login > Login connections).
- Доступ через обычный Cloudflare Quick Tunnel не поддерживает этот
  loopback OAuth callback. Подключайтесь на время входа через SSH.
- После переноса Vast OAuth-ключи и токены переносятся только через
  отдельную защищённую миграцию, **не через GitHub** и **не через
  резервную копию Communications SQLite**.

## Acceptance

~~~bash
cd cybernova/research-platform
python -m unittest discover -s tests -p 'test_siwc.py' -v
python -m compileall -q console
node --check console/static/app.js
~~~

Тесты покрывают OAuth state/PKCE, отклонение подменённого client_id, JWT
аудиторию/nonce, приватное хранение, refresh/revoke, маршруты proxy и
Responses stream. Это **офлайн-тесты**, а не подтверждение авторизации
конкретного ChatGPT аккаунта или реального ответа GPT.

Проверка живого подключения после установки: кнопка входа, согласие OpenAI,
статус plan_usage=true, список моделей, одна безопасная рецензия учебного
исследования, передача ответа Qwen, выключение подключения и повторный вход.
