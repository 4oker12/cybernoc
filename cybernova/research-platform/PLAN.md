# CYBERNOVA — универсальная исследовательская платформа
## Мастер-план аудита Web / API / инфраструктуры, профиль SIMNET
**Статус:** проектная спецификация; не разрешение на активный аудит.  
**Дата:** 2026-11-18. **Версия:** 1.0.  
**Цель:** чтобы локальная Qwen работала как исследователь — строила модель системы, выбирала уместные инструменты, проверяла гипотезы, фиксировала доказательства и предлагала исправления, а не просто запускала набор сканеров.

### 0. Критерий качества и границы выводов
- 83 универсальных именованных возможностей перечислены в tools/catalog.json. Статус каждой указан честно: deployed_mcp, planned_adapter, planned_rename. Наличие строки в каталоге **не равно** установленному исполняемому инструменту.
- Уже работали на Vast: gateway_status, http_get, http_header_review, python_static_review, ip_network_summary; локальная проверка WebUI существует как local_webui_health и позже может стать runtime_health.
- На SIMNET был получен один публичный GET / со статусом 200, Server nginx, видимыми HTML generator WordPress 7.1.4 / AIOSEO 4.7.3 / Site Kit 1.192.0 и HSTS max-age=300. Это наблюдение о метаданных, а не доказанная уязвимость, не исчерпывающий инвентарь и не утверждение о состоянии иных узлов.
- Домен simnet.ua не автоматически включает my.simnet.kiev.ua, admin.simnet.kiev.ua, произвольные IP, сторонних поставщиков и внутренние узлы.
- Для production: сначала согласованные Rules of Engagement, контакты владельца, расписание, области, частота, типы проверок, тестовые данные и немедленная остановка. До этого: анализ архитектуры из предоставленных материалов и исключительно допустимые публичные наблюдения; сетевые проверки за пределами согласованного допуска НЕ запускаются.
- Невозможно честно гарантировать «не пропущено ни одной уязвимости». Вместо этого обеспечиваем **прослеживаемость покрытия**: каждое требование, путь, роль и граница либо проверены и задокументированы, либо явно помечены исключением/недоступностью.

### 1. Опорные источники и проверочные стандарты
1. **OWASP WSTG**: версия v4.2 как фиксированный набор идентификаторов тестов; «latest» используем отдельно и не подменяем им результаты прошлых проверок. Группы: информационный сбор, конфигурация/развёртывание, identity, authentication, authorization, session, injection, errors, cryptography, business logic, client-side, API, WebAssembly.
2. **OWASP ASVS 5.0.0**: технические требования и уровни доверия; для отчётов указывать полный версионированный ID v5.0.0-<...>. Уровень проверки выбирает владелец системы.
3. **OWASP API Security Top 10:2023**: BOLA, broken authentication, BOPLA, resource consumption, BFLA, sensitive flows, SSRF, misconfiguration, inventory, unsafe third-party API consumption.
4. **NIST SP 800-115**: планирование, проведение, анализ результатов и способы устранения.
5. **OWASP SAMM / Threat Dragon**: модель зрелости безопасности и диаграммы угроз; OWASP ZAP Automation Framework как автоматизированный, но контролируемый транспорт для web.
6. **CVSS и CWE**: категоризация и техническая тяжесть; **CISA KEV / EPSS** и реальная экспозиция — входные сигналы для приоритета, не замена верификации.

Ссылки:
- https://wstg.owasp.org/stable/
- https://asvs.owasp.org/
- https://api-security.owasp.org/editions/2023/en/0x11-t10/
- https://csrc.nist.gov/pubs/sp/800/115/final
- https://owaspsamm.org/model/
- https://www.zaproxy.org/docs/automate/automation-framework/
- https://nvd.nist.gov/vuln-metrics/cvss
- https://www.cisa.gov/known-exploited-vulnerabilities-catalog

### 2. Зафиксировать модель объекта до сканирования
#### 2.1. Набор независимых поверхностей (КАНДИДАТЫ, не разрешённые цели)
A — публичный сайт (в планировании: simnet.ua). Возможные потоки: анонимный пользователь → страницы/формы/обратная связь → backend → CRM/другие сервисы; реальное устройство требует доказательств.
B — личный кабинет (кандидат: my.simnet.kiev.ua). Потоки: абонент → аутентификация → профиль/услуги/платежи/заявки → backend; проверять только с отдельным допуском и синтетическими пользователями.
C — административные приложения (кандидат: admin.simnet.kiev.ua). Потоки: сотрудник → роли → операции billing/support; отдельная критическая зона. Никогда не включать в scope косвенным выводом.
D — публичные API, если найдены и прямо включены: REST/GraphQL, webhook, mobile endpoints, integrations, historical versions.
E — окружение и доставка: DNS, TLS, CDN, reverse proxy, WAF, ingress, хостинг, CMS/plugin ecosystem, CI/CD и хранение секретов.
F — внутренний ISP-периметр, **отдельная будущая программа**: BNG/BRAS, RADIUS, DHCP/IPoE, CGNAT, биллинг, OLT/PON, коммутаторы, мониторинг, логи, доступ операторов. Не путать с web-аудитом публичного домена.

#### 2.2. Инвентарь каждого актива
- Название, точный FQDN/IP/порт/путь, бизнес-владелец, служба/репозиторий, deployment ID, среда prod/stage/lab, контакт, страна/правовой режим, провайдер/третья сторона.
- Тип данных: публичные, персональные, учетные, платёжные, технические, административные; строгие правила retention, маскирования и допуска.
- Роли: анонимный; абонент A; абонент B; поддержка L1; поддержка L2; биллинг; администратор; API consumer; service account. Это **проектная матрица тестовых ролей**, не описание фактически реализованных ролей SIMNET.
- Точки входа: методы HTTP, формы, файлы, WebSocket, OAuth/OIDC, мобильные API, callback/webhook, импорты/экспорты, сторонние JS.
- Границы доверия: браузер ↔ CDN/WAF ↔ proxy ↔ app ↔ API ↔ DB ↔ billing/CRM/AAA ↔ интеграции ↔ внешние поставщики.
- События и состояния: login, logout, password reset, создание/изменение заявки, смена тарифа, изменение реквизитов, платежи, временные начисления, привязки договора/услуги.

#### 2.3. Документ Rules of Engagement
Обязательны: разрешение собственника, точные allowlist-цели и исключения, сроки и часовой пояс, разрешённые методы, тестовые аккаунты, бюджет запросов, число соединений, запрет массового перебора, аварийные контакты, порядок коммуникации, уведомление NOC/SOC, план восстановления и остановки, правила безопасности персональных данных. Подтвердить также политику подрядчиков/CDN/WAF и стороннего хостинга. Разрешение на один FQDN нельзя расширять на остальные автоматически.

### 3. Исследовательский цикл Qwen
1. **Observe** — запросить и получить наблюдение или предоставленный источник. Не выдавать предположения за факт.
2. **Model** — построить граф активов, потоки данных, роли, доверенные границы, зависимости; сохранить неизвестные узлы.
3. **Hypothesize** — сформулировать проверяемую гипотезу, условия существования, возможное влияние и альтернативные объяснения.
4. **Select** — выбрать минимально необходимую проверку и инструмент, указать ожидаемые признаки и условия остановки.
5. **Authorize** — выполнить проверку scope, метода, лимита, тестовых данных, срока разрешения; при отказе остановиться.
6. **Execute** — контролируемая операция с параметрами, фиксированным кодом/версией инструмента и протоколом выполнения.
7. **Correlate** — сопоставить с логами, кодом, схемой, вторым способом наблюдения; отсеять ложноположительные выводы.
8. **Verify** — подтвердить безопасным минимальным воспроизведением в среде и на данных, которые можно использовать.
9. **Explain** — назвать первопричину и точную trust boundary; измерить техническое и бизнес-влияние без гипербол.
10. **Remediate & Retest** — предложить исправление, регрессионный тест, проверить после внедрения.
Каждый шаг сохраняет JSONL-событие; состояние «неизвестно» допустимо, скрытое додумывание — нет.

### 4. Этапы программы с входами, проверками и результатами

#### P0 — Допуск и безопасность
Вход: согласованный владелец, FQDN/URL, ROE, аварийные контакты, профиль данных и тестовые аккаунты. Инструменты: engagement_validate, scope_check, plan_validate, run_cancel. Выход: подписанный реестр scope, лимиты/окно и чек-лист прекращения. Gate: **без допуска только офлайн-анализ и допустимые публичные сведения**. Особый контроль: не менять состояние биллинга и заказов, не контактировать с реальными абонентами и не запускать отказоустойчивостные/нагрузочные проверки на production.

#### P1 — Пассивный инвентарь и атрибуция
Сбор из предоставленной документации и разрешённых открытых источников: DNS A/AAAA/CNAME/MX/NS/TXT/CAA; CT и сертификаты; публичные архивы; HTML/JS метаданные; robots/sitemap; признаки reverse proxy/CDN/WAF/CMS; ownership каждого внешнего домена. Свести конкурирующие источники, дату и уверенность, отметить неизвестные адреса не как разрешённые цели. Инструменты: dns_lookup, certificate_transparency_search, passive_asset_discovery, web_archive_search, domain_registration_review, asset_inventory. Выход: Asset Graph с origin/source/confidence и непроверенными кандидатами.

#### P2 — Карта реальной поверхности
На разрешённой среде: status code, redirects с проверкой каждого нового хоста, методы, страницы, формы, JS endpoints, маршруты, API схемы, версии, файлы и обработчики, SSO, WebSockets, роли. Для приватных разделов — только учётные записи, выделенные владельцем. Исключить third-party links и logout/destructive paths из автоматического обхода. Инструменты: http_get, http_probe, web_crawl, browser_capture, web_route_inventory, client_script_inventory, api_schema_import, api_endpoint_inventory. Выход: endpoint × method × role × data class × trust-boundary matrix.

#### P3 — Архитектура и модель угроз
Диаграмма request-to-response и data flows; активы и доверенные границы; кто принимает решения access control; место reverse proxy/WAF; сервисные вызовы/ очереди / БД / API gateway; точки логирования и secrets flow. STRIDE и abuse cases; безопасность цепочек доверия «frontend → backend → billing», а не только отдельных URL. Инструменты: service_dependency_map, asset_inventory, Threat Dragon (внешний движок), планировщик Qwen. Выход: DFD, trust-boundary register, угрозы с likelihood и проверяемыми контрольными требованиями.

#### P4 — HTTP / TLS / конфигурация
TLS chain/SNI/validity, versions/ciphers, redirects, HSTS/CSP/XFO/XCTO/Referrer/Permissions, cache control, compression, cookies, security.txt, CORS, storage, debug/error output, directory listing, publicly leaked documentation, policies DNSSEC/CAA/SPF/DMARC. Не считать одно отсутствие заголовка само по себе эксплуатируемой уязвимостью. Тестировать корректность настройки с учётом функционала. Инструменты: tls_inspect, tls_configuration_test, security_header_review, dns_security_review, web_technology_inventory, error_handling_review, cache_security_review. Выход: конфигурационная матрица и проверенные рекомендации.

#### P5 — Identity / Authentication / Sessions
Согласованные тестовые роли: регистрация, credential handling, MFA, reset, enumeration resistance, ограничения входа без brute force, OIDC/OAuth state/nonce/PKCE/redirect, cookie Secure/HttpOnly/SameSite, CSRF, rotation, fixation, logout/invalidation, idle/absolute timeout, изменение пароля/почты, восстановление устройства. Сценарии только на тестовых идентичностях. Инструменты: identity_flow_review, authentication_review, oauth_oidc_review, session_management_review, csrf_control_test. Выход: state-machine и нарушения при переходах, доказательства тестовыми аккаунтами.

#### P6 — Авторизация и межпользовательская изоляция
Матрица: Аноним / абонент A / абонент B / оператор / администратор × read/list/create/update/delete/export × объект. Проверять горизонтальные и вертикальные границы (BOLA/IDOR/BFLA/BOPLA), конфликт ролей, попытки доступа после logout/role change, доверие к client-provided идентификатору и фильтру, bulk endpoints. **Только свои синтетические объекты** — никаких реальных чужих договоров, платежей, профилей. Инструменты: authorization_matrix_test, api_object_access_test, api_contract_test, evidence_capture. Выход: конкретные права и доказанные расхождения с ожидаемым ACL.

#### P7 — Валидация / injection / file handlers
Проверяем классы: SQL/NoSQL injection, XSS DOM/reflected/stored, OS command injection, template injection, path traversal/LFI, XML/XXE, SSRF, unsafe deserialization, header injection/CRLF, open redirect, unsafe file upload/download, type confusion, parameter pollution, JSON parsing/encoding issues, CORS misconfiguration. Для опасных классов — unit/integration tests и локальный стенд; production только после отдельного разрешения на минимально воздействующее подтверждение. Фиксируем error paths, контекст кодирования, валидацию, server-side boundary. Инструменты: input_validation_test, injection_control_test, file_handling_review, client_security_review, static_code_scan. Выход: подтверждённые или отвергнутые гипотезы, воспроизводимость.

#### P8 — API и интеграции
REST/GraphQL/OpenAPI/legacy endpoints; BOLA/BOPLA/BFLA, object property minimization, auth scopes, bearer token lifecycle, method-level authorization, mass assignment, resource consumption, pagination/filter/sort, excessive data exposure, old API versions, OpenAPI divergence, webhook signatures/replay, SSRF in URL fetchers, unsafe upstream API consumption, API gateway policy, cache/auth inconsistency. Только тестовые объекты, лимит запросов; интроспекцию и прочие queries согласовать. Инструменты: api_schema_import, api_endpoint_inventory, api_object_access_test, api_contract_test, resource_limit_test. Выход: coverage по всем категориям API Top 10 плюс хронология результатов.

#### P9 — Бизнес-логика и ISP-специфика
Изучить предусмотренные бизнес-сценарии: заявка на подключение → проверка адреса → тариф → контакт → назначение → завершение; личный кабинет → профиль → договор/услуга → платеж/баланс → обращение/заказ; операторская система → роль → изменение статуса/финансов/обслуживания. Наблюдать переходы state-machine, необходимость повторного подтверждения, race/idempotency, дубли, rollback, ownership checks, audit trail, согласованность фронтенда и backend.
Особенно критично: баланс и временные платежи, изменение тарифа, привязка чужого договора, PII, роль L1/L2, интеграция с CRM/RADIUS. Это **потенциальные бизнес-потоки для моделирования**, не утверждение, что такие публичные endpoint существуют.
Финансовые действия и RADIUS/BNG не тестировать в живой системе. Проверка на стенде со специальными учебными счетами и фиктивными операциями. Выход: transition diagrams, invariant tests, контрольная модель авторизации, список root causes.

#### P10 — Frontend / клиентская защита / supply chain
DOM sinks/sources, CSP, XSS, mixed content, third-party JS, SRI, storage/localStorage/IndexedDB, service workers, browser cache, postMessage origin, CSRF, clickjacking, протоколы OAuth, frontend secret leakage, NPM dependencies, nonces, accessibility of security UX, progressive-enhancement errors. Offline анализ исходников/сборок и controlled browser. Выход: цепочки source → sink → boundary и исправления.

#### P11 — Развёртывание / секреты / сеть (при наличии допуска)
SAST, SCA/SBOM, уязвимости компонентов и проверка применимости CVE (точная версия + конфигурация + reachable code); secrets в разрешённых репозиториях, config drift; Docker/K8s/IaC/CI/CD; DNS/TLS/network exposure; минимальный согласованный порт-инвентарь с жёстким лимитом; проверка логов WAF/IDS, reverse proxy, API gateway; supply chain, provenance, резервное копирование. Не собирать secrets в открытую переписку или отчёт.
При ISP-аудите infrastructure — **отдельный scope**: OLT/PON, BRAS/BNG, RADIUS, DHCP/IPoE, CGNAT, ACL, management VLAN и OSS/BSS. Продакшен-сканы этих систем недопустимы без отдельной программы и участия владельцев. Инструменты: static_code_scan, dependency_audit, secret_scan, container_image_audit, iac_configuration_audit, port_inventory, packet_capture_analyze, firewall_policy_review. Выход: архитектурные и конфигурационные выводы с evidence.

#### P12 — Корреляция, доказательства, ложные срабатывания
Для каждой гипотезы задать: asset, test ID, условия, собственный тестовый principal, request, expected, actual, время, идентификаторы артефактов, SHA-256, подтверждение вторым способом, impact, root cause, mitigation, sensitivity и redaction. Не сохранять незамаскированные cookies, bearer tokens, персональные данные и платежные реквизиты.
Четыре состояния: observation / hypothesis / verified / rejected; плюс not_tested и blocked_by_scope на матрице покрытия. CVE не считать доказанным по generator string.
Инструменты: evidence_capture, evidence_hash, evidence_redact, finding_correlate, finding_verify, cve_applicability_review, risk_assess. Выход: воспроизводимая цепочка доказательств без секретов.

#### P13 — Отчёт, исправления и повторный аудит
Executive summary; scope и исключения; карта активов; coverage WSTG/ASVS/API; findings по риску; PoC только с учебными данными; первопричины; конкретные исправления: валидация на сервере, access control, token/session lifecycle, architectural controls; приоритизация; owner, дата, SLA; regression/retest logs. Отдельно: пределы выводов, отказы доступа, недоступные компоненты, false positives. Инструменты: report_generate, retest_track, audit_event_log.

### 5. Классификация режимов выполнения
**offline** — предоставленные коды, логи, pcap, конфиги, схемы, материалы; без контакта с целью.
**passive_public** — чтение разрешённых открытых источников; не означает разрешение на активное воздействие.
**low_impact_active** — GET/HEAD и ограниченный разрешённый browser navigation; нужен ROE, бюджет, строгий scope.
**controlled_active** — роль/сессия/API/входные данные/порт/нагрузка в тестовой среде, с явным разрешением, пользователями, лимитами и аварийной остановкой.
Запрет по умолчанию: bypass из scope, дополнительные домены в редиректе, внутренние/private/metadata IP без отдельного утверждения, разрушение/снятие данных, brute force, DoS/стресс, реальные финансовые транзакции, утечка личных данных, скачивание баз/дампов, обход WAF как самоцель, массовый поиск в PROD.

### 6. Принцип «одна возможность — много движков»
Tool Registry — единый список универсальных capability. Имена никогда не содержат имя сайта, производителя, клиента или случайной модели устройства. Для каждой записи: input schema, output schema, risk mode, permissions, required approval, executor adapter, engine version, timeout, request budget, evidence schema, reproducibility and test fixture.
Конкретные движки — **адаптеры**, а не отдельный API для модели:
- http_get/http_probe: ограниченный Python HTTP клиент либо ProjectDiscovery httpx.
- dns_lookup/passive_asset_discovery: DNS, CT, subfinder, Amass в режиме пассивного сбора.
- web_crawl/web_route_inventory: Katana, Playwright, ZAP с realm scope.
- tls_inspect/tls_configuration_test: Python ssl и testssl.sh.
- browser_navigate/browser_capture: Playwright в изолированном профиле.
- api_schema_import/api_contract_test: OpenAPI/GraphQL/Postman, schema validators и ZAP.
- static_code_scan/dependency_audit: Semgrep, Trivy, OSV/Grype.
- secret_scan/iac_configuration_audit/container_image_audit: Gitleaks, Checkov/Trivy, Syft, Trivy.
- port_inventory: Nmap только по отдельно разрешённому network scope и safe profiles.
- input_validation_test/injection_control_test: контролируемые проверки на локальном стенде, ZAP policy, собственные unit/integration test harnesses.
- evidence_* / finding_* / report_*: собственная проверяемая бизнес-логика и хранение, не отданная на усмотрение LLM.

Перед подключением движка обязательно: закрепить версию, лицензирование, проверку происхождения, sandboxing, parsing JSON/SARIF, запрет небезопасных опций, лимиты, вывод ошибок, сохранение версий шаблонов и redaction. Не доверять найденным через Интернет шаблонам как исполняемому коду без ревью.

### 7. Архитектура исполнения
~~~text
Пользователь / ChatGPT (цель, scope, приоритеты, финальная проверка)
                      ↓
             CYBERNOVA Controller
  engagement registry / policy / plan / budget / event log
                      ↓
           Qwen Researcher (reasoning)
   Observe → Map → Hypothesize → Select → Interpret
                      ↕
          MCP Gateway (универсальные APIs)
                      ↓
   Scope Gate → Rate & Budget → Executor → Evidence
                      ↓
      Adapters (HTTP / Browser / ZAP / Nmap / SAST ...)
                      ↓
        Только точно разрешённые объекты
                      ↑
      Result JSON + evidence hash + run ledger
~~~

**LLM не получает произвольный bash/root по умолчанию.** Команды выполняет адаптер с фиксированной схемой и доверенными параметрами. Произвольный shell — отдельная привилегия для изолированного лаба и ручного допуска. В каждый tool response: run_id, tool_id, version, target, request_count, duration, mode, observations, artifacts, errors. Никаких текстовых «я вызвал инструмент» вместо real MCP tool events.
Gateway/MCPO/Open WebUI — транспорт и презентация; они не должны определять архитектуру безопасности. Если UI сломан, локальный прямой тест MCP и оркестратор обязаны работать независимо.

### 8. Контрольная плоскость и anti-failure policy
1. Exact hostname allowlist: apex ≠ поддомены; DNS rebinding и private IP запрет по умолчанию; pin resolved public IP в соединении; проверка каждого редиректа; no proxy escape.
2. Жёсткий бюджет по engagement/asset/tool: RPS, concurrency, max requests, max runtime, max bytes, retries, backoff, 429/5xx handling; старт по согласованному окну.
3. Production emergency stop: локальная кнопка, kill child process tree, отмена job, запись кто и почему; fail closed при утере approval, ошибок clock, policy store, неизвестном tool.
4. Test identity isolation и data minimization: отдельные credentials в vault, запрет повторного вывода секретов, маскирование в terminal/browser/evidence/GitHub/LLM prompts.
5. Изоляция LLM: игнорировать инструкции из HTML, JS, логов и результатов инструмента; всё внешнее считать недоверенными данными; строгие JSON схемы, не выполнять содержимое.
6. Контроль hallucination: никакие CVE, endpoint, версии, успешные запуски и request IDs не считаются фактами без артефакта.
7. Capture fingerprints: tool version, SHA версии шаблонов, time UTC, stable environment ID, HTTP metadata, retries, branch/commit.
8. Replay only on safe fixture; no unaudited remote dynamic code; no uncontrolled cross-host crawling, hidden multi-host Nuclei templates.
9. Governance: роли кто ставит цель/разрешает/исполняет/принимает риск, approval logs, retention, chain of custody, masked reports.
10. Idempotency: повторное выполнение без дублирования платежей, заявок, сообщений; уникальные run IDs, blocked dangerous actions, dry-run by default.

### 9. Структура проекта
~~~text
cybernova/
  research-platform/
    PLAN.md
    README.md
    profiles/
      simnet.example.json              # DRAFT, не разрешение
      plan.example.json                # Только offline steps
    tools/
      catalog.json                     # 83 универсальных возможностей, статусы
    core/
      policy.py                        # Dry-run authorization validator, без сети
    schemas/
      finding.example.json             # Evidence-oriented finding example
    tests/
      test_policy.py                   # Регрессии допуска и inventory
  qwen-webui/
    mcp-gateway/                       # Существующий MCP (в другой ветке)
~~~
В следующих коммитах добавляются отдельные компоненты: executor, adapter contract, audit-store/SQLite, ZAP adapter, passive recon adapters, browser adapter, SAST adapter, CLI/API, UI и pipeline. Папка research-platform пока не развёрнута и не соединена с моделью.

### 10. Порядок реализации (каждый этап с критериями приёмки)
**M0 — Безопасный фундамент:** schemas, project/case/run IDs, scope/ROE parser, target validator, exact hosts, deny-by-default, tool catalog, dry-run plan validator, evidence metadata, redaction. Unit tests на URL parser, scope bypass, expired ROE, missing contact, unknown tools, fake tool outputs. Критерий: ни один активный план не стартует без документированного разрешения.
**M1 — Надёжный минимальный исследователь:** DNS/CT (passive), HTTP GET/HEAD, TLS, headers, technology fingerprint, robots/sitemap, JS asset inventory; real MCP tools/list & call, JSON evidence, snapshots, dedupe. Тестируем на собственном локальном fixture и только затем на явно разрешённой цели. Критерий: Qwen самостоятельно делает три проверяемых наблюдения, фиксирует доказательства и не выдумывает инструментов.
**M2 — Mapping и browser:** Playwright/HAR, scoped crawler, form/route/API inventory, OpenAPI import, role-safe fixtures. Критерий: карта покрытия URL/method/role, сторонний домен не затрагивается, logout и mutating routes исключены.
**M3 — Проверки security controls:** ZAP passive, config/TLS, auth/session/CSRF/CORS, тестовые A/B аккаунты, API object authorization, шаблоны безопасных отклонений и false-positive review. Критерий: демонстрация успешного и отвергнутого BOLA кейса в локальном учебном API; без живого PII.
**M4 — Code & infra:** Semgrep, SCA/SBOM, Gitleaks, IaC/container audits, limited Nmap/testssl adapters; отдельные права на network target. Критерий: диагностируем известный учебный дефект и подтверждаем исправление, все ресурсы в scope.
**M5 — Research autonomy:** hypothesis planner, feedback loops, human escalation for dangerous tests, evidence correlation, risk scoring, report renderer, regression/retest tracking, GitHub issues/PR workstream. Критерий: Qwen объясняет первопричину, отвергает ложную гипотезу после данных, воспроизводит на fixture и готовит точный remediation.
**M6 — Production readiness:** observability, retention, secrets manager, configurable queue, retries/idempotency, long-running jobs, kill switch, agent evaluation on benchmark corpus, dashboards, review by owner, maintenance plan. Критерий: отказоустойчивое выполнение без бесконтрольного продолжения после ошибки.

### 11. Тесты качества самой Cybernova
A — Offline parser: malicious URL, credentials in URL, fragment, invalid IDNA, internal target, DNS rebinding, mixed public/private records, alternate port, host confusion.
B — Scope control: запрещённый FQDN, поддомен и wildcard, third-party redirect, scope expiration, method not allowed, blocked path, count budget exceeded.
C — Traffic controls: 429, timeout, TLS failure, retry budget, large body, disallowed content type, many redirects, infinite loops, origin down.
D — Evidence: SHA, UTC timestamps, no leaked Authorization/Set-Cookie/PII, idempotent event log, source attribution, redaction.
E — Agent cognition: false CVE inference from generator string, response prompt injection, synthetic tool output text, unimplemented tools, contradiction, wrong risk classification, business impact overstatement.
F — Cross-tool quality: real tool schema valid, parameters validated, dependency missing, nonzero exit codes preserved, subprocess stopped, deterministic fixture.
G — Integration E2E: synthetic web app with vulnerable and fixed variants; role A/B, fixture billing changes with no real money, signed-off report/retest.
H — Backup/restore and event spool; no lost work from WebUI/MCPO disconnection.

### 12. Оценка завершённости и KPI
Нужно видеть: количество scope-approved assets, discovered-but-unapproved assets, reachable entrypoints, роли×операции×объекты, ASVS requirement coverage, WSTG test coverage, API Top 10 category coverage, verified hypotheses, rejected false positives, findings with evidence hash, retested fixes, inaccessible checks, aborted checks, unsafe actions blocked. Обязательно разделять:
- Implemented tool vs registered stub vs planned adapter;
- Observed signal vs probable misconfiguration vs verified vulnerability;
- Tested vs not tested vs blocked by scope;
- Target service vulnerability vs third-party dependency;
- Technical severity vs actual impact on ISP operations.

### 13. Первая программа именно для SIMNET (после фиксации ROE)
1. Зафиксировать simnet.ua как кандидат и запросить разрешение владельца на конкретные HTTP проверки. Отдельными строками указать my.simnet.kiev.ua и admin.simnet.kiev.ua как неразрешённые по умолчанию.
2. Сделать пассивную карту публичного сайта: страницы, DNS/TLS/HTTP metadata, CMS/plugin version signals, публичные формы и JS, подключённые третьи стороны.
3. Создать архитектурные вопросы: где фактически заканчивается сайт и начинается CRM/биллинг; как передаются заявки; есть ли публичный API; какие personal data входят/выходят; кто владелец интеграций.
4. Согласовать стенд или учебные аккаунты для subscriber/admin сценариев; не переносить client IDs/договоры из действующего биллинга.
5. Построить matrix access control и business workflow для предоставленных синтетических объектов.
6. Проверить конфигурацию/версии по первоисточникам и коду, если доступ предоставлен; не подтверждать CVE по HTML generator.
7. Запустить только утверждённый low-impact pipeline; тяжелые/intrusive методы вынести в отдельное окно или стенд.
8. Подготовить evidence-backed отчёт с архитектурными причинными цепочками и конкретным remediation.
9. Повторить безопасную проверку после исправлений, обновить покрытие и остаточные риски.

### 14. Что реально готово в этой ветке
- Полный tool manifest из 83 универсальных имён со **статусом каждого**.
- Сухой policy/evaluate_action/validate_plan, который ничего не отправляет по сети и по умолчанию запрещает live запросы без ROE.
- Пример неутверждённого SIMNET-профиля и формат выводов.
- Unit tests policy (не считать пройденными, пока CI либо локальный runtime реально не запустил).
- Этот подробный план.
**Не готовы:** адаптеры всех перечисленных движков, единый executor, evidence store, real end-to-end agent integration. Их нельзя выдавать за сделанные. Следующий этап — M0/M1, а не установка 83 «пустых кнопок».

### 15. Контрольные вопросы перед любым реальным запуском
- Кто дал право и на какой точный адрес, метод, окно?
- Какой неизвестный факт мы хотим узнать? Что будет считаться опровержением?
- Может ли эта операция изменить деньги, подписку, учетную запись, чужие данные или доступность?
- Можно ли проверить офлайн/на стенде с меньшим риском?
- Есть ли точные лимиты, emergency stop, контакт и идентификация запросов?
- Как сохраним лог/артефакт без cookie/token/PII?
- Чем подтвердим результат независимо? Какая первопричина и какой тест исправления?
- Что останется not_tested и как это честно показать в отчёте?

### 16. Полный арсенал и установка
Подробная классификация пользовательского списка, 107 engine candidates, сопоставление с 83 универсальными MCP-capabilities, профили установки, порядок проверки лицензий, binary integrity и безопасного включения: **ARSENAL.md**. Машинный реестр: **engines/manifest.json**. Установщик (dry-run по умолчанию): **install_arsenal.py**. Наличие в каталоге не подтверждает установки на Vast.

**Решение:** строить Cybernova как безопасную многоцелевую исследовательскую платформу, а не как набор скриптов, привязанных к названиям сайтов и произвольному LLM shell.
