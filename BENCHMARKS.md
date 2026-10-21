# Бенчмарки и проверки эффективности holone

Документ фиксирует воспроизводимые измерения текущего кода: бенчмарки горячих
путей, fuzz-цели и инварианты ограниченной памяти. Все цифры ниже — реальный
вывод `go test` на указанном хосте, без оценок «на глаз».

## Методика

- `testing.B` с `b.Loop()`, `b.ReportAllocs()` и `b.SetBytes()` там, где имеет
  смысл скорость в MB/s. Настройка (компиляция движка, генерация входа,
  `httptest`-серверы) вынесена за таймер.
- `b.Loop()` сам подбирает число итераций: быстрые входы в финальном прогоне
  выполнились 5148 (1 KiB) / 940 (4 KiB) / 9 (1 MiB) раз, а 10 MiB stream
  (`1.27 s`) и adversarial 1 MiB (`1.09 s`) — ровно один раз, потому что одна
  итерация уже превышает бюджет 1 s.
- Таблицы бенчмарков ниже — из одного финального полного прогона с `-count=1`
  на незагруженной машине. Fuzz-результаты и замеры памяти — отдельные прогоны
  (их команды приведены в соответствующих разделах). End-to-end бенчмарки
  дополнительно перепроверены с `-count=3`; разброс описан в конце.
- End-to-end бенчмарки прокси идут через `httptest` + `internal/mockevil`
  (профили `clean` и `evil`), как в обычных тестах.
- Память: инварианты проверяются детерминированными утверждениями (длины,
  ёмкости, число вызовов колбэков). Единственное измерение heap —
  `runtime.ReadMemStats` с намеренно щедрой границей; оно не является
  единственной защитой теста.
- Fuzz: нативные Go fuzz-цели, сид-корпус задан в коде, поэтому обычный
  `go test ./...` быстро прогоняет сиды без режима фаззинга.

### Хост и тулчейн

| Параметр | Значение |
|---|---|
| CPU | Intel Core i5-9400F @ 2.90 GHz (GOMAXPROCS=6, суффикс `-6`) |
| ОС | Windows 10 (10.0.19045), amd64 |
| Go | go1.26.4 windows/amd64 |
| Правила | `rules.json` v5: 105 правил, keywords у 103 |

## Команды

```sh
go version
go env GOOS GOARCH

# весь набор бенчмарков (то же делают scripts/bench.sh / scripts/bench.ps1)
go test -run '^$' -bench . -benchmem ./internal/... -count=1

# по пакетам
go test -run '^$' -bench 'Inspect|Redact' -benchmem ./internal/inspect
go test -run '^$' -bench 'StreamInspector|ReadSSE|Proxy|Monitor|Direct' -benchmem ./internal/proxy
go test -run '^$' -bench 'Normalize|Endpoint' -benchmem ./internal/scanner
```

`scripts/bench.sh` и `scripts/bench.ps1` — тонкие обёртки: печатают
`go version`, `go env GOOS GOARCH` и запускают
`go test -run '^$' -bench . -benchmem ./internal/...`.

```sh
sh scripts/bench.sh
```

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/bench.ps1
```

## Результаты

`MB/s` — из `b.SetBytes`; `—` означает, что вход не измеряется в байтах потока
(e2e/микробенчмарки без `SetBytes`).

### internal/inspect — движок детекции

| Бенчмарк | ns/op | MB/s | B/op | allocs/op |
|---|---:|---:|---:|---:|
| BenchmarkInspectCleanProse1KiB | 234 044 | 4.38 | 1 053 | 1 |
| BenchmarkInspectToolJSON4KiB | 1 406 926 | 2.91 | 948 | 0 |
| BenchmarkInspectText1MiB | 124 456 233 | 8.43 | 1 066 361 | 26 |
| BenchmarkInspectAdversarial (~2 KiB) | 8 902 631 | 0.23 | 166 787 | 1 952 |
| BenchmarkInspectAdversarial1MiB (worst case) | 1 087 159 700 | 0.96 | 1 705 848 | 2 515 |
| BenchmarkRedactFindingSized | 43 802 | 5.39 | 4 478 | 33 |
| BenchmarkInspect (существующий, короткий payload) | 196 390 | — | 13 610 | 196 |

Чистый текст теперь почти не доходит до регулярок: keyword-prefilter отсекает
большинство правил, поэтому 1 KiB стоит 0.23 ms, а 1 MiB — 0.124 s. На
adversarial-входе, где почти все keywords присутствуют, цена остаётся на
порядок выше (см. «Оптимизация 0.4.2» и «Почему adversarial остаётся
медленным»).

### internal/proxy — поток и прокси

| Бенчмарк | ns/op | MB/s | B/op | allocs/op |
|---|---:|---:|---:|---:|
| BenchmarkMonitorPassthrough (e2e, monitor) | 893 516 | — | 58 505 | 439 |
| BenchmarkDirect (e2e, без прокси) | 335 355 | — | 15 580 | 216 |
| BenchmarkStreamInspectorWrite1MiB | 125 040 267 | 8.39 | 3 292 438 | 122 |
| BenchmarkStreamInspectorWrite10MiB | 1 271 883 900 | 8.24 | 32 730 200 | 824 |
| BenchmarkReadSSE1MiB (~1 KiB кадры) | 4 070 229 | 257.85 | 4 377 441 | 7 243 |
| BenchmarkReadSSE1000TinyFrames | 260 446 | 57.59 | 129 713 | 5 004 |
| BenchmarkReadSSEOne900KiBFrame | 9 964 515 | 92.49 | 9 380 054 | 19 |
| BenchmarkProxyMonitorCleanSSE | 793 918 | — | 59 372 | 438 |
| BenchmarkProxyBlockCleanSSE | 558 669 | — | 58 883 | 437 |
| BenchmarkProxyBlockMaliciousSSE | 867 186 | — | 88 273 | 806 |

### internal/scanner — построение endpoint

| Бенчмарк | ns/op | MB/s | B/op | allocs/op |
|---|---:|---:|---:|---:|
| BenchmarkNormalizeBaseURL | 371.8 | — | 192 | 2 |
| BenchmarkEndpointURL | 174.4 | — | 88 | 2 |

## Оптимизация 0.4.2

Что сделано в движке:

1. **Keyword-prefilter.** В `rules.json` v5 у 103 из 105 правил появилось поле
   `keywords` — литералы, которые обязаны присутствовать в тексте, если
   сработал regex. `Inspect` один раз делает lowercase-копию входа и проверяет
   `strings.Contains` по keywords; если ни одного нет, regex правила не
   запускается. Это не эвристика: keyword'ы выведены из самих паттернов, а
   эквивалентность проверяется дифференциально (см. ниже).
2. **Параллельная оценка для больших входов.** При `len(text) >= 32 KiB`
   правила делятся на непрерывные группы (по `GOMAXPROCS`, не меньше 8 правил в
   группе), группы считаются конкурентно, результаты сливаются в порядке
   правил. Для входов меньше 32 KiB остаётся последовательный путь: накладные
   расходы на goroutine'ы там не окупаются.

Корректность: `TestKeywordPrefilterSoundness` (172 сэмпла, 84/103 keyword-
правил покрыто) и `FuzzKeywordPrefilterEquivalence` — дифференциальное сравнение
движка с keywords и того же набора правил с вырезанными keywords (сравниваются
`rule_id + match`). В документированном прогоне — 0 расхождений.

### Before / after

Оба столбца — полные прогоны на одном хосте, но на разных состояниях дерева;
разброс между прогонами ~10 %, поэтому ускорения ниже — порядок величины.

| Бенчмарк | до 0.4.2 | после 0.4.2 | ускорение |
|---|---:|---:|---:|
| InspectCleanProse1KiB | 6 829 224 ns | 234 044 ns | ~29× |
| InspectToolJSON4KiB | 31 582 112 ns | 1 406 926 ns | ~22× |
| InspectText1MiB | 8 510 384 500 ns | 124 456 233 ns | ~68× |
| InspectAdversarial (~2 KiB) | 15 258 118 ns | 8 902 631 ns | ~1.7× |
| StreamInspectorWrite1MiB | 8 302 980 700 ns | 125 040 267 ns | ~66× |
| StreamInspectorWrite10MiB | 87 418 918 500 ns | 1 271 883 900 ns | ~69× |
| ProxyBlockMaliciousSSE | 1 651 471 ns | 867 186 ns | ~1.9× |
| RedactFindingSized | 40 332 ns | 43 802 ns | без изменений |

E2E `MonitorPassthrough` практически не изменился (910 µs → 894 µs): mockevil
отдаёт крошечный ответ, и инспектируется только текст дельт (~35 байт), где
prefilter нечего отсекать.

### Почему adversarial остаётся медленным

- `BenchmarkInspectAdversarial` — вход ~2 KiB, то есть **ниже порога 32 KiB**:
  параллельный путь не включается. Почти все keywords присутствуют, поэтому
  prefilter пропускает лишь немногие правила, и основное время уходит на regex
  + аллокации finding'ов. Отсюда скромные ~1.8×.
- `BenchmarkInspectAdversarial1MiB` — уже параллельный путь, но вход специально
  собран из payload'ов почти всех правил: prefilter не может ничего пропустить,
  и все 105 регулярок проходят по 1 MiB. Итог — **1.087 s на 1 MiB
  (0.96 MB/s)**, примерно в 8.7 раза дороже чистого 1 MiB (0.124 s).
- Это и есть актуальный worst case: не «любой текст», а большой текст, в
  котором присутствуют все ключевые слова. На 10 MiB такой вход не измерялся;
  стоимость растёт пропорционально объёму.

## Monitor vs direct и стоимость Block

- Baseline: `Direct` 0.335 ms/запрос, `MonitorPassthrough` 0.894 ms/запрос —
  накладные расходы монитора **+0.56 ms (~2.7×)**. Это цена httptest+mockevil
  на крошечном ответе, а не стоимость инспекции большого тела: mockevil отдаёт
  ~1 KiB SSE, инспектируется ~35 байт текста.
- `ProxyMonitorClean` 0.794 ms, `ProxyBlockClean` 0.559 ms: Block без tool call
  дешевле в этом прогоне; разница между режимами на таком ответе не является
  стабильной метрикой (см. «Вариативность»).
- `ProxyBlockMalicious` 0.867 ms: примерно **+0.31 ms** к Block clean за счёт
  буферизации tool call, инспекции аргументов и подмены кадра safe-note.
- Главное: после 0.4.2 детекция на типичном чистом тексте уже не доминирует с
  прежним отрывом. `readSSE` разбирает 1 MiB за 4.1 ms (258 MB/s), а чистый
  1 MiB инспектируется за 124 ms (8.4 MB/s); на 10 MiB потоке инспектор даёт
  1.27 s (8.2 MB/s). Узкое место теперь — worst case с плотным adversarial-
  текстом, а не парсер SSE и не сам прокси.

## Fuzz

Каждая цель, кроме equivalence, запускалась 15 секунд; equivalence — 20 секунд,
6 воркеров:

```sh
go test ./internal/inspect -run '^$' -fuzz='^FuzzInspect$'                    -fuzztime=15s
go test ./internal/inspect -run '^$' -fuzz='^FuzzRedact$'                     -fuzztime=15s
go test ./internal/inspect -run '^$' -fuzz='^FuzzKeywordPrefilterEquivalence$' -fuzztime=20s
go test ./internal/proxy   -run '^$' -fuzz='^FuzzReadSSE$'                    -fuzztime=15s
go test ./internal/proxy   -run '^$' -fuzz='^FuzzDeclaredToolNames$'          -fuzztime=15s
go test ./internal/proxy   -run '^$' -fuzz='^FuzzResponseToolNames$'          -fuzztime=15s
go test ./internal/scanner -run '^$' -fuzz='^FuzzEndpointURL$'                -fuzztime=15s
```

| Цель | execs | new interesting | Итог |
|---|---:|---:|---|
| FuzzInspect | 149 982 | 59 | PASS |
| FuzzRedact | 456 462 | 32 | PASS |
| FuzzKeywordPrefilterEquivalence | 28 921 | 15 | PASS, 0 расхождений |
| FuzzReadSSE | 353 801 | 15 | PASS |
| FuzzDeclaredToolNames | 600 796 | 34 | PASS |
| FuzzResponseToolNames | 439 355 | 32 | PASS |
| FuzzEndpointURL | 378 253 | 147 | PASS |

Всего ~2.41 млн исполнений. Падений, зависаний и нарушений контрактов нет.
`FuzzKeywordPrefilterEquivalence` на этом прогоне стартовал с 144 сидов
(в отчёте security-core было 136 сидов и 8 716 execs); расхождений между
движком с keywords и без keywords — 0. Новые интересные входы остались в кэше
Go; в `testdata/fuzz` ничего не сохранено, потому что падений нет. Один
найденный пограничный вход `xoxa-...` добавлен явным сидом в код (см. ниже).

Что именно проверяется:

- `FuzzInspect` — нет паники; у каждого finding непустой `RuleID`, валидная
  severity (`low|medium|high`), `Match`/`Excerpt` ≤ 4096 байт; паттерны
  известных креденшелов не встречаются в `Match`/`Excerpt`. Вход ограничен
  64 KiB.
- `FuzzRedact` — нет паники, идемпотентность
  (`redact(redact(s)) == redact(s)`), паттерны креденшелов отсутствуют в
  результате. Вход ограничен 256 KiB.
- `FuzzReadSSE` — нет паники; конкатенация фрагментов `onLine` точно равна
  входу (Monitor обязан переслать каждый байт); `onOversized` вызывается не
  более одного раза, rule id — только `proto-sse-line-oversized` или
  `proto-sse-frame-oversized`. Вход ограничен 8 MiB.
- `FuzzDeclaredToolNames`, `FuzzResponseToolNames` — произвольный JSON не
  паникует, имена непустые. Вход ≤ 1 MiB.
- `FuzzEndpointURL` — нет паники; при автоматической сборке URL (без явного
  `--path`) не появляется дублирующий `/v1/v1`. Если `--path` задан явно или
  сам base path уже содержит `/v1/v1`, это пользовательский ввод, а не ошибка
  склейки, и инвариант не применяется.
- `FuzzKeywordPrefilterEquivalence` — движок с keywords и движок с вырезанными
  keywords возвращают одинаковый набор `rule_id + match` на любом входе
  (≤64 KiB). Это и есть доказательство, что prefilter не меняет детекцию.

### Наблюдения редакции (не падения)

- **Граница слова.** Вход `xoxa-0000000000 0xoxa-0000000000`: второй токен
  приклеен к `0`, поэтому перед `xoxa` нет `\b`. `redact` (и детектор) такие
  токены не распознают, и литерал `xoxa-0000000000` остаётся в выводе. Это
  осознанное свойство boundary-aware паттернов, а не паника; вход оставлен
  явным регрессионным сидом в `FuzzRedact`. Инвариант проверяет отсутствие
  **паттернов** креденшелов, а не подстроки, иначе такой же литерал,
  случайно встретившийся внутри другого слова, давал бы ложное срабатывание.
- **Окно Excerpt.** `Excerpt` одного finding может захватить хвост токена из
  соседней строки, когда префикс (`/webhooks/...`, `api.telegram.org/bot...`)
  остался за границей окна. Редактор работает с каждым finding отдельно и
  распознать такой фрагмент не может; поэтому инвариант проверяет полные
  паттерны, а удаление самих токенов покрыто обычными тестами
  `redact_test.go`. Это ограничение контекстной редакции, не паника фаззера.

## Инварианты ограниченной памяти

```sh
go test ./internal/proxy -run 'TestStreamInspector|TestReadSSE' -v -count=1
go test ./... -count=1
```

| Проверка | Утверждение | Фактически |
|---|---|---|
| `TestStreamInspectorPendingBounded` | после `Write` 16 MiB: `len(pending) <= 256 KiB`, `cap(pending) <= 512 KiB`, `Finish` очищает pending | len=16 412 B, cap=24 576 B |
| `TestStreamInspectorRetainedBoundedAcrossWrites` | 64 записи по 64 KiB: те же границы после каждой записи, буфер не растёт | PASS |
| `TestReadSSEOversizedLineMemoryBounded` | 32 MiB строка без `\n`: пересланы все байты, `onOversized` ровно один раз, rule id = line-oversize, рост heap < 64 MiB | forwarded=33 554 432, calls=1, рост heap=4 751 408 B (~4.5 MiB) |

Тест памяти `streamInspector` использует синтетический движок из одного
правила: проверяется структура окон и удержание буфера, а не детекция, поэтому
результат не зависит от производительности боевого набора правил. Граница
64 MiB для heap намеренно щедрая (`ReadMemStats` зависит от планировщика GC);
детерминированные утверждения — пересланные байты, число вызовов и rule id.

Проверки лимитов тела запроса/ответа «ровно на границе» и «на байт больше»
уже есть в `internal/proxy/limits_test.go` и здесь не дублируются.

## Вариативность и оговорки

- Тяжёлые замеры больше не обязаны быть одноитерационными: `b.Loop()`
  выполняет столько итераций, сколько успевает за 1 s. В финальном прогоне
  1 KiB–1 MiB инспектировались 5148 / 940 / 9 раз, 1 MiB stream — 9 раз,
  10 MiB stream — 1 раз (1.27 s), adversarial 1 MiB — 1 раз (1.09 s).
- Между полными прогонами на этом хосте `InspectText1MiB` дал 124 / 155 / 124 ms,
  а `StreamInspectorWrite10MiB` — 1.27 / 1.41 / 1.27 s (разброс ~10–12 %).
- e2e-замеры шумные: в одном полном прогоне `MonitorPassthrough` показал
  3.83 ms вместо ~0.9 ms, хотя `Direct` в том же прогоне был 0.53 ms. Повтор с
  `-count=3` дал стабильные 0.95–0.98 ms против 0.38–0.41 ms у `Direct`,
  поэтому в таблицах — значения из спокойного прогона, а e2e-числа следует
  читать как порядок величины.
- `BenchmarkReadSSEOne900KiBFrame` намеренно берёт кадр под самым лимитом:
  `B/op` ≈ 9.4 MB на 900 KiB входа (≈10×) из-за накопления строки, конверсии
  в `string` и копий `raw`/`data`. Это худший случай, а не типичный кадр.
- Абсолютные значения зависят от CPU, ОС и загрузки машины; сравнивать имеет
  смысл только прогоны на одном хосте одной командой.
