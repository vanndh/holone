# changelog

все значимые изменения проекта фиксируются здесь. формат — по мотивам
[keep a changelog](https://keepachangelog.com/), версионирование стремится
следовать [semver](https://semver.org/).

## [0.2.0] — unreleased

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

[0.2.0]: https://github.com/vanndh/holone/releases/tag/v0.2.0

[0.1.0]: https://github.com/vanndh/holone/releases/tag/v0.1.0
