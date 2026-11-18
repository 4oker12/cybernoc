# Cybernova × WEB AUDIT KIT (WAK): интеграция версии 1.1

Дата: 2026-11-18. Источник: предоставленный пользователем WAK-документ (392 строки, 0–11 разделы).

## Что перенесено

1. В 12-фазный workflow workflow/phases.json — identify, passive, resolve, live, ports, webmap, threat_model, vulnerability, verify, suspicious, report, retest.
2. Дизамбигуация одноимённых компаний и source-tagged asset inventory — core/research.py: entity_disambiguation, asset_inventory.
3. Открытые внешние сигналы (история, CT, типосквоттинг, публичные индексы) — threat_intelligence_review, только offline-normalization, без сетевых запросов и обвинений.
4. Граф гипотез / цепочек найденных нарушений — attack_path_model. Наличие 2 подтверждённых findings не доказывает работоспособность перехода между ними; нужны отдельные свидетельства.
5. Вместо произвольного Security Score 0–100 — security_posture_summary с тремя осями: Coverage, Verified Risk, Confidence. Отсутствие проверок не равно защищённости.
6. Сводка готовности каждого этапа — core/workflow.py. Зависимости, unknown tool, cycle и отсутствующие адаптеры проверяются до любых операций.
7. CLI dry-run: python3 cli.py workflow; assets/entity/threats/attack-path/posture — только с предоставленными JSON данными.
8. Регрессионные тесты: tests/test_wak_integration.py. CI проверяет 12 фаз и полное отсутствие автоматического исполнения.
9. Интеграция с масштабируемым каталогом универсальных инструментов. Старые названия по сайту не используются. Сейчас 87 capabilities, из них 5 были наблюдаемыми через MCP в прежнем runtime, новые offline utility НЕ развёрнуты.

## Чего НЕ перенесли из WAK и почему

| Исходный подход WAK | Решение Cybernova |
|---|---|
| authorized: true + существующий authorization_doc | Не доверять булевому флагу; отдельное реальное подтверждение owner/time/scope и проверка runtime. Наличие файла само по себе не подтверждает право |
| Все находки subfinder автоматически передаются dnsx/httpx | Кандидаты остаются неразрешёнными, пока собственник не добавит каждый точный hostname в approved scope |
| IP из DNS автоматически передаются naabu/nmap | ИП может принадлежать CDN/общему хостингу/внешнему оператору; отдельный IP scope и соглашения |
| global grep in_scope() и guard в начале Bash | Проверять scope/метод/скорость у executor перед реальным запросом; запрет прямых вызовов в обход контроллера |
| bash modules with implicit CFG, OUT, LOG | Явные schemas и params (work item, project ID, tool version, limits, evidence pointers) |
| Запуск nuclei со всем набором шаблонов | Только закреплённые версии и review шаблонов, ограниченные безопасные политики |
| Параллельные gowitness, Nmap и ffuf с независимыми лимитами | Центральный per-target rate/concurrency budget и emergency stop |
| curl -sk | TLS проверка включена по умолчанию |
| Проглатывание ошибок через || true | Distinct states success/failed/skipped/blocked, stderr и returncode в ledger |
| Автоинтерпретация nuclei match как CVE | Candidate finding, затем ручная или разрешённая controlled verification |
| Синтетический security score = 100 - штрафы | Coverage + Verified Risk + Confidence; overall score unknown до определённого владельцем набора тестов |
| ~2 недели как универсальный срок ISP-аудита | Нельзя вывести срок без asset inventory, roles, scope, доступности test data; фазы и требования измеримы, сроки оценивают после discovery |
| suspicious phase «всегда безопасна» | Индексные API могут платно тарифицироваться и раскрывать поисковые запросы; некоторые инструменты делают DNS/HTTP запросы, поэтому source-by-source scope checks |
| command examples against real business systems | Отдельное соглашение и синтетический стенд; никаких финансовых операций или доступа к реальным абонентам |

## Зрелость и текущие границы

* Записаны workflow JSON, offline research logic, tests и CLI; они не выполняют интернет-запросы.
* Тесты на CI добавлены, но успешный CI прогон должен быть подтверждён отдельно.
* Реальные adapters (DNS/CT/httpx/Katana/Nuclei/ZAP/Nmap/Playwright), executor, tool-call receipt collector и WebUI доступны только после следующих milestones.
* Ветка feature/cybernova-audit-architecture не развёрнута на Vast, а работавший MCP Gateway не импортирует этот core.
* Юридический scope для simnet.ua / my.simnet.kiev.ua / admin.simnet.kiev.ua не получен в чате. Все адреса в profiles/simnet.example.json не имеют in_scope разрешения.

## Проверка offline после checkout ветки

    cd cybernova/research-platform
    python3 cli.py catalog
    python3 cli.py workflow
    python3 cli.py engagement
    python3 install_arsenal.py --profile inventory
    python3 -m unittest discover -s tests -v

Пример типичного безопасного результата workflow: 12 фаз описаны, execution disabled, недостающие adapters перечислены, none automatically_executable. Это целевой результат для design branch, а не «ошибка». 

## Следующие milestones

M1: no-target local fixture web + простая интеграция Qwen через MCP, работающая независимо от WebUI. Доказать, что модель делает реальный tools/list и tools/call.
M2: adapter runner и полное enforcement authorization at network boundary; добавить отдельный request budget и immutable event record.
M3: отдельный scope-approved public pipeline OSINT → HTTP/TLS → scoped crawl. Не путать внешнюю цель с тестовым стендом.
M4: формы/логин/API и бизнес-логика только в согласованном fixture; manual verification и false-positive review.
M5: controlled active adapters и отчёт/повторный аудит по OWASP WSTG/ASVS/API Top 10.
