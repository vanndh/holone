# holone (npm)

npm-обёртка для [holone](https://github.com/vanndh/holone) — клиент-независимого
стража против вредоносных LLM-провайдеров.

## установка

```sh
npm i -g holone
```

или запуск без глобальной установки:

```sh
npx holone --help
```

`postinstall` скачивает Go-бинарь под твою ОС/архитектуру из GitHub Releases и
**проверяет sha-256** по `SHA256SUMS.txt` того же релиза. при несовпадении или
отсутствии записи установка завершается ошибкой, бинарь не кладётся в `bin/`.

поддерживаются windows / macos / linux (x64, arm64).

переменные окружения:

- `HOLONE_VERSION` — скачать другую версию (например `0.4.0`);
- `HOLONE_NPM_SKIP_DOWNLOAD=1` — пропустить скачивание (для CI).

## использование

```sh
holone scan https://api-cc.freemodel.dev --key $ANTHROPIC_API_KEY
holone proxy --upstream https://api.anthropic.com
```

полная документация — в [корневом README](https://github.com/vanndh/holone#readme).

## публикация

пакет лежит в `npm/` и не опубликован. чтобы выпустить:

```sh
cd npm
npm publish --access public
```

публикация требует `npm login` (или `NPM_TOKEN` в CI). перед публикацией
проверь, что версия в `package.json` совпадает с тегом релиза и что релиз с
`SHA256SUMS.txt` уже создан.
