# CYBERNOVA — расширенный арсенал и политика установки

**Версия 1.0 — 18 ноября 2026.** Основной технический план: PLAN.md.
**Каталог движков:** engines/manifest.json — 107 записей, включая программы, SaaS-источники, библиотеки и reference frameworks. **Каталог MCP возможностей:** tools/catalog.json — 83 универсальных имени.

## 1. Исходный список учтён

| Категория | Движки / провайдеры |
|---|---|
| OSINT / имя → активы | amass intel; theHarvester; whois; RDAP; crt.sh; Certspotter; Shodan; Censys; FOFA; ZoomEye; Wayback Machine; gau; waybackurls; dnsdumpster; SecurityTrails |
| Субдомены | subfinder; assetfinder; puredns; massdns; shuffledns; dnsx; gotator; altdns; github-subdomains; chaos |
| Живость / fingerprint | httpx (ProjectDiscovery); gowitness; aquatone; whatweb; wafw00f; tlsx; webanalyze |
| Порты / сервисы | naabu; masscan; nmap; nmap vulners NSE; rustscan |
| Crawl / content | katana; gospider; hakrawler; ffuf; feroxbuster; dirsearch; arjun; paramspider; unfurl; qsreplace; gf |
| JS / secrets | subjs; getJS; LinkFinder; SecretFinder; mantra; jsleak; trufflehog; gitleaks |
| Vulnerability | nuclei; ZAP; nikto; wapiti; sqlmap; dalfox; XSStrike; commix; tplmap; crlfuzz; smuggler; corsy; jwt_tool; subzy; subjack; s3scanner; cloud_enum; testssl.sh; sslyze; graphql-cop; interactsh |
| Verification / proxy | Burp Suite; Caido; mitmproxy; searchsploit; Exploit-DB; Metasploit auxiliary; cvemap |
| Infrastructure / mail | checkdmarc; dig; dnstwist; ssh-audit |
| Orchestration references | reconFTW; Osmedeus; Sn1per; Axiom |
| Report | report.py; cvss Python; Dradis; Serpico |
| Дополнительно необходимые | OpenAPI; Postman; GraphQL schema; Playwright; Semgrep; Trivy; OSV-Scanner; Grype; Syft; Checkov; uncover |

Список включает не только CLI: SaaS платформы могут требовать ключ и платный доступ, коммерческие GUI требуют отдельную лицензию, reference orchestration не должны запускаться как независимые бесконтрольные сканеры. «107» — инвентаризация доступных решений, НЕ 107 установленных бинарников.

## 2. MCP имена всегда универсальные

| Универсальная возможность | Возможные движки |
|---|---|
| passive_asset_discovery / recon_search | amass, subfinder, assetfinder, Shodan, Censys, FOFA, ZoomEye, uncover, сертификатные и архивные API |
| dns_lookup | dig, dnsx, massdns |
| http_probe / http_get | ProjectDiscovery httpx, ограниченный HTTP client |
| tls_inspect / tls_configuration_test | tlsx, testssl.sh, sslyze |
| web_technology_inventory | whatweb, wafw00f, webanalyze, gowitness |
| port_inventory | naabu, nmap, rustscan, masscan |
| web_crawl / web_route_inventory | katana, gospider, hakrawler, ffuf, feroxbuster, dirsearch |
| client_script_inventory | subjs, getJS, LinkFinder, SecretFinder, mantra, jsleak |
| secret_scan | trufflehog, gitleaks |
| vulnerability_scan | nuclei, ZAP, nikto, wapiti |
| input_validation_test / injection_control_test | sqlmap, dalfox, XSStrike, commix, tplmap, crlfuzz, smuggler |
| cors_policy_review / oauth_oidc_review | corsy, jwt_tool, ZAP и API validators |
| api_contract_test | graphql-cop, OpenAPI/Postman fixtures |
| file_handling_review | s3scanner, cloud_enum в owned tenant |
| oast_observation | interactsh / отдельный доверенный callback collector |
| http_intercept_review | Burp Suite, Caido, mitmproxy, HAR |
| cve_applicability_review | searchsploit, Exploit-DB, cvemap, CISA KEV |
| mail_security_review | checkdmarc, dig |
| service_protocol_review | ssh-audit |
| static_code_scan / dependency_audit | Semgrep, Trivy, OSV-Scanner, Syft, Grype |
| iac_configuration_audit | Checkov, Trivy |
| browser_capture | Playwright |
| report_generate / plan_build | собственный Cybernova Core |

Принцип: одна capability, несколько взаимозаменяемых движков, единый строгий contract на входы и JSON/SARIF выходы; выбор движка основывается на цели, влиянии, версиях, допуске и бюджете.

## 3. Режимы и допуски

- offline: без сетевого контакта с целью. Исходники, конфиги, HAR, PCAP, SBOM, логи, отчёты;
- passive_public: открытые источники, CT/архивы/RDAP/интернет-индексы; соблюдение условий поставщика и бюджета;
- low_impact_active: DNS, HTTP GET/HEAD, TLS, браузер и ограниченные URL, если цель утверждена;
- controlled_active: порт-инвентарь, fuzzing, nuclei, ZAP, auth/API матрицы, валидация вводов: явное разрешение, окно, фиксированный объём и тестовые данные;
- lab_only: опасные PoC, нагрузочные и некоторые Metasploit сценарии, только изолированные стенды по умолчанию.

Установка программ не означает разрешение вызывать их против SIMNET. У Qwen отсутствует неконтролируемое исполнение shell или NSE/scripts/templates. URL из редиректов и обнаруженные поддомены не наследуют разрешения.

## 4. Профили установки

В репозитории создан Python-скрипт install_arsenal.py:
- inventory — прочитать 107 записей и версии/наличие известных бинарников, не устанавливать;
- baseline — 5 официальных ProjectDiscovery движков: subfinder, dnsx, httpx, tlsx, katana;
- expanded — baseline + nuclei, naabu, uncover, interactsh;
- all — полный статус-реестр; автоматически устанавливаются только проверенные PDTM candidates, все остальные отмечены как needing upstream review.

Никакого root/sudo, произвольного curl|bash, автоматической отправки запросов к целевым ресурсам или незаметного включения шаблонов.

### 4.1. Команды для checkout проектной ветки, НЕ текущего рабочего Vast

В отдельной копии репозитория:

    cd cybernova/research-platform
    python3 install_arsenal.py --profile inventory
    python3 install_arsenal.py --profile baseline
    python3 -m unittest discover -s tests -v

После явного решения об установке в подготовленном Python/Go окружении:

    python3 install_arsenal.py --profile baseline --apply --i-understand-installation --bootstrap-pdtm

Позже (отдельное разрешение на установку бинарников расширенного профиля):

    python3 install_arsenal.py --profile expanded --apply --i-understand-installation --bootstrap-pdtm

Скрипт не запускает обнаружение сайтов, проверки портов и сканы. Перед установкой PDTM проверить версию Go: новые версии официального менеджера могут требовать более новую версию компилятора. Воспроизводимость сборки и SHA release образа необходимы до продакшен-деплоя.

### 4.2. Остальные движки: пошаговая упаковка

Для каждого из source_review в manifest нужны: актуальный upstream, проверенная лицензия, версия, подходящий Linux/архитектура, integrity SHA256, установка в отдельное пространство или контейнер, locked dependencies, no-target smoke test, машинно-читаемый выход, корректная обработка ошибок, ресурсные ограничения.

Типы поставки: apt/distro package, pinned Go module, pinned PyPI venv, pinned GitHub release, Docker image digest, платная desktop license либо только SaaS API с квотами. Не устанавливать десятки сторонних install.sh без ревью. Некоторые программы устарели или требуют особого окружения; заменять их функциональность на надёжный движок допустимо, сохраняя кандидат в catalog.

### 4.3. ZAP

Официальный стабильный Docker образ zaproxy/zap-stable, изолированный контейнер и Automation Framework YAML. Отдельно включать passive или controlled active job. ZAP API не должен быть открыт без авторизации; официальный Docker guide предупреждает об опасности незащищённого порта.

Справка: https://www.zaproxy.org/docs/automate/automation-framework/
https://www.zaproxy.org/docs/docker/about/

### 4.4. reconFTW, Osmedeus, Sn1per, Axiom

Изучить схемы автоматизации, но не запускать их параллельно с новым контроллером «всё и сразу». reconFTW имеет полноценную систему установки и зависимости, требует отдельного обзора самого инсталлятора, flags и частоты вызовов.

Справка: https://docs.reconftw.com/deployment/deployment
https://github.com/six2dez/reconftw

### 4.5. PDTM

Официальный ProjectDiscovery Tool Manager ставит конкретные движки по имени: команда менеджера pdtm -i subfinder,dnsx,httpx,tlsx,katana. По документации PDTM умеет и пакетную установку, но Cybernova сознательно не использует install-all без анализа состава.

Справка: https://github.com/projectdiscovery/pdtm
https://projectdiscovery.io/open-source

### 4.6. Оплачиваемые источники

Shodan / Censys / FOFA / ZoomEye / SecurityTrails / Certspotter и другие могут требовать ключи и лимиты или платную подписку. Отдельные статусы: installed, configured, authenticated, quota_available. Нет ключа = provider_not_configured, а не ложная ошибка сканирования. Никакие платные запросы/покупки автоматически не совершаются.

## 5. Что действительно готово

- Реестр 107 engine candidates с attribution, назначением, режимом и установочным статусом.
- 83 универсальных capability с честной пометкой deployed / offline implemented / planned.
- Dry-run by default install_arsenal.py с явным флагом согласия для установки девяти PDTM кандидатов.
- Тесты установщика, scope/authorization policy и evidence redaction в проектной ветке.
- Подробный план по исследованию SIMNET в PLAN.md.

**Не готово:** установки остальных десятков инструментов, runtime адаптеры к ним, production executor, реальные self-test всех бинарников и интеграция в живой Qwen/Open WebUI. Предлагается не выдавать spec/manifest за внедрение.

## 6. Условия приёмки каждого движка

1. Upstream owner/commit/release/signature/digest/актуальность проверены.
2. Установлен в изоляции; зависимости и ABI совместимы; лицензия принята.
3. Движок отвечает на --help или локальный no-target smoke, exit-code сохранён.
4. Адаптер выдаёт валидный JSON, корректно обрабатывает empty, timeout, stderr, truncation.
5. Policy исключает неправильный FQDN, порт, DNS rebinding, redirect, oversized traffic, auth expired и неизвестные опции.
6. Есть фикстура с положительным и отрицательным исходом, safety test, fake vulnerable/patch pair.
7. Qwen получает реальный tool receipt, не текст-имитацию, результаты сохранены без токенов и персональных данных.
8. В интерфейсе status равен deployed только после успешного end-to-end вызова.

Пока требования не соблюдены — engine остаётся candidate / not_verified.
