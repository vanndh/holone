# changelog

все значимые изменения проекта фиксируются здесь. формат — по мотивам
[keep a changelog](https://keepachangelog.com/), версионирование стремится
следовать [semver](https://semver.org/).

## [0.3.0] — 2026-07-08

### добавлено
- **веб-дашборд** (`holone dashboard`) — локальный web UI на `127.0.0.1:9090`
  для полного управления holone из браузера:
  - **профили провайдеров** — добавление, удаление, редактирование
    end-to-end-провайдеров с сохранением в `~/.holone/providers.json`.
  - **мониторинг активности** — live-feed решений прокси (alert/block/clean),
    сканов и аудитов, автообновление каждые 5 секунд.
  - **скан провайдера** — запуск canary-проб прямо из браузера с визуальным
    отображением verdict, risk score, findings и IOC hits.
  - **аудит системы** — запуск OS-level проверок с табличным отображением
    статусов.
  - REST API (`/api/status`, `/api/providers`, `/api/activity`, `/api/scan`,
    `/api/audit`) для программного доступа.
  - single-page UI: тёмная тема, sidebar-навигация, адаптивные карточки.
- **rules v4** — +30 правил (всего 105). новые категории и векторы:
  - **thinking-block injection** — скрытые инструкции в `thinking` /
    `redacted_thinking` полях стримингового ответа (обход пользовательской
    видимости), аномально большой `signature` как стеганографический канал.
  - **supply-chain атаки** — typosquatting-пакеты, postinstall-hook с payload,
    dependency confusion (extra-index-url / scope registry).
  - **новые LOLBins** — `hh.exe` (CHM download), `IEExec.exe` (.NET assembly),
    `atbroker.exe`, `pcwrun.exe`, `cmd.exe` pipe-chain с recon-командами.
  - **process injection / hollowing** — `CreateRemoteThread`,
    `WriteProcessMemory`, `VirtualAllocEx`, `QueueUserAPC`, reflective DLL
    loading (`ReflectiveLoader` / `ManualMap` / `RunPE`), shellcode staging
    (`VirtualProtect` → `PAGE_EXECUTE_READWRITE`).
  - **UAC bypass** — fodhelper / computerdefaults / eventvwr / compmgmtlauncher
    + registry hijack (`ms-settings\Shell\Open\command`, `mscfile`).
  - **Windows Defender tampering** — `Set-MpPreference -DisableRealtimeMonitoring`,
    `MpCmdRun -removedefinitions`, `sc stop WinDefend`.
  - **Windows Credential Manager** — `vaultcmd`, `cmdkey /list`, mimikatz/
    sekurlsa/lsadump references.
  - **cloud credential theft** — Azure (`~/.azure/`), GCP (`~/.config/gcloud/`,
    `GOOGLE_APPLICATION_CREDENTIALS`, `gcloud auth print-access-token`).
  - **additional exfil channels** — webhook.site / requestbin / ngrok / serveo,
    CloudFront C2, pastebin upload, direct SMTP (`Send-MailMessage`),
    cloud storage upload (`aws s3 cp`, `gsutil cp`, `rclone copy`).
  - **hidden file attributes** — `attrib +h+s`, `Set-ItemProperty Attributes
    Hidden`, `chflags hidden`.
  - **NTFS ADS** — alternate data stream manipulation (`:$DATA`, `type > file:stream`).
  - **registry persistence** — `RunOnceEx`, `RunServices`, `AppInit_DLLs`,
    `IFEO`, `Winlogon\Shell`, `BootExecute`, и другие альтернативные ключи.
  - **kernel driver loading** — `sc.exe create type=kernel`, `New-Service
    KernelDriver`.
  - **container escape** — `nsenter --target 1 --mount`, `--cap-add=SYS_ADMIN`,
    `--security-opt apparmor=unconfined`.
  - **LD_PRELOAD persistence** — `/etc/ld.so.preload` manipulation (Linux).
- **4 новых mockevil-профиля** (`evil-supply` / `evil-inject` / `evil-uac` /
  `evil-def`) для e2e покрытия новых векторов.
- **сканер: 4 пробы вместо 2** — добавлены tooled-probes (с объявленными
  инструментами) для обоих протоколов; пробы выполняются concurrently.
- **сканер: progress callback** — live-отображение статуса каждой пробы.
- **сканер: duration tracking** — время выполнения каждой пробы в отчёте.
- **сканер: bilingual report** — summary / notes / recommendations доступны
  на английском и русском в JSON, CLI и dashboard.
- **update-check** — проверка GitHub Releases при запуске с кэшем на 12 часов,
  `--no-update-check` и `HOLONE_NO_UPDATE_CHECK=1` для отключения.
- **+27 тест-кейсов** на новые правила (high + medium severity), тесты
  дашборда (CRUD providers, activity log, REST API, RU/EN scan render).

### изменено
- `rules.json`: version 3 → 4, note обновлён с описанием новых категорий.
- `scanner.go`: полностью переписан — concurrent probe execution, 4 пробы,
  progress callback, duration tracking, улучшенный scoring.
- CLI `scan` output: визуальный редизайн — box-drawing границы, цветные
  badges, детальное отображение findings с severity и match, bilingual summary
  и рекомендации.
- Dashboard scan view: локализует summary / notes / recommendations по выбранному
  языку, показывает срок TLS-сертификата и детали проб.
- `main.go`: version 0.2.0 → 0.3.0, добавлена `dashboard` subcommand.

### не изменилось
- ioc-блоклист — без новых верифицированных индикаторов.
- прокси-движок (inspect/stream/block) — без изменений в hot path.

## [0.2.0] — 2026-06-21

расширение детекта: покрытие attack surfaces, которые вредоносный провайдер
достигает через ai-клиент, но v0.1.0 пропускал.

### добавлено
- **+41 поведенческое правило** (rules v3, всего 75). новые категории:
  - **client-config poisoning** — отравление конфигов ai-клиента
    (`.claude/settings.json`, `~/.claude.json`, `.mcp.json`, `CLAUDE.md` /
    `AGENTS.md` / `.cursorrules`), инъекция lifecycle-хуков
    (`PreToolUse` / `PostToolUse` / `Stop`), подмена mcp-серверов. это главный
    пробел v0.1.0: персистентность на уровне дев-окружения без нового `tool_use`.
  - **credential theft** — чтение ssh-ключей, `~/.aws/credentials`,
    `~/.kube/config`, `~/.docker/config.json`, `~/.netrc`, `.env`,
    chrome credential/cookie stores, `git credential` helper.
  - **exfil-каналы к легитимным хостам** — discord / telegram / slack webhooks,
    anonymous paste-сервисы, dns-tunnel command substitution
    (`nslookup $(...)`), `dnscat2`. обходят доменные блоклисты.
  - **новые lolbins** — `msiexec /i http`, `installutil` / `regasm` / `regsvcs`,
    `forfiles /c`, `wmic process call create`, `add-type` inline c#,
    `osascript do shell script`.
  - **edr / amsi / etw / clm evasion** — `amsiInitFailed`, `AmsiUtils` reflection,
    etw patching, constrained language mode bypass.
  - **git-атаки** — `core.hooksPath`, `remote set-url` hijack, `.git/hooks`
    writes, `.github/workflows` ci poisoning.
  - **macos / linux / docker / wsl / pkg persistence** — `launchctl bootstrap`,
    loginwindow login items, `systemd-run` с payload, shell-rc poisoning
    (`.bashrc` / `.zshrc`), `docker --privileged` / `-v /:/` breakout,
    `wsl --exec` pivot, npm / pip config registry poisoning.
  - **linux anti-forensics** — log wipe (`/var/log`), history wipe
    (`unset HISTFILE`, `history -c`, `shred ~/.bash_history`).
- **3 новых mockevil-профиля** (`evil-cfg` / `evil-cred` / `evil-exfil`) для e2e
  покрытия новых векторов; `IsEvilProfile` расширен до префикса `evil*`.
- **+41 high/medium тест-кейс**, +20 corpus-файлов (12 malicious / 8 clean),
  тест mockevil-пакета: каждый payload прогоняется через реальный движок.
- бенчмарк: ~0.5мс/op на 75 правилах — negligible относительно сетевого
  стриминга.

### изменено
- `rules.json`: version 2 → 3, обновлён note с описанием новых категорий.
- сужения против ложных срабатываний: `cred-ssh-key-read` отсекает `*.pub`,
  `cred-env-read` отсекает `.env.example` / `.sample`, `exec-osascript` требует
  `do shell script`, `git-remote-attack` только `set-url` (не `add`),
  `persist-systemd` не ловит `systemctl enable nginx`.

### не изменилось
- ioc-блоклист — без новых верифицированных индикаторов; регекспы покрывают
  паттерны точнее голых доменов. свежие ioc приветствуются через pr.

## [0.1.0] — 2026-06-21

первый публичный релиз.

### добавлено
- **инспектирующий реверс-прокси** (`holone proxy`) — клиент-независимый страж:
  форвардит трафик реальному провайдеру и проверяет стрим ответа на инъекции
  вызовов инструментов / payload. поддержка стрим-протоколов anthropic messages и
  openai chat completions.
  - **monitor** (по умолчанию): сначала форвардит байты, потом инспектирует
    копию — латентность ~0, только alert.
  - **block**: вырезает вредоносные или непрошеные вызовы инструментов до того,
    как их увидит клиент, сохраняя легитимный текст; переписывает stop/finish.
- **движок детекта** (`internal/inspect`) — ~34 поведенческих re2-правила по
  категориям download-exec, obfuscation, persistence, network, anti-forensics,
  locale, плюс литеральный ioc-блоклист и сигнал «вызов инструмента без
  объявленных инструментов».
- **сканер провайдера** (`holone scan`) — canary-пробы обоих протоколов,
  проверка tls / резолва ip / ioc-блоклиста, risk-score.
- **аудит и sentinel** (`holone audit`, `holone sentinel`) — разовые и
  непрерывные ос-проверки на индикаторы заражения кампании (левые процессы,
  задачи персистентности, дроп-файлы, socks-маршрутизация).
- файловый корпус детекта, интеграционные тесты против встроенного фейкового
  вредоносного провайдера (`mockevil`), бенчмарки латентности и ci под
  windows/macos/linux.

[0.3.0]: https://github.com/vanndh/holone/releases/tag/v0.3.0
[0.2.0]: https://github.com/vanndh/holone/releases/tag/v0.2.0
[0.1.0]: https://github.com/vanndh/holone/releases/tag/v0.1.0
