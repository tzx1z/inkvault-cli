# InkVault CLI

[English version](README.md)

Терминальный клиент InkVault - менеджера паролей для самостоятельного размещения со сквозным шифрованием и синхронизацией через XMPP-сервер.

Хранилище живет на вашем XMPP-сервере (например, Prosody) в узлах PEP вашей учетной записи. Сервер хранит только шифротекст, мастер-пароль не покидает устройство. Тот же формат используют web- и Android-клиенты: записи, добавленные в терминале, сразу видны на других устройствах.

Клиент рассчитан на работу в терминале и в скриптах: пароль выводится в stdout, список - таблицей или JSON, секреты читаются из stdin.

## Возможности

- Агент по схеме ssh-agent: `inkvault unlock` один раз, дальше команды работают без ввода мастер-пароля до блокировки.
- Чтение, добавление, правка и удаление записей, теги и избранное.
- Коды TOTP и пароли вида PIN + одноразовый код.
- Генератор паролей.
- Зашифрованный экспорт и импорт, совместимый с web- и Android-клиентами.
- Работа без сети: записи читаются из зашифрованного кэша, изменения отправляются после подключения.
- Смена мастер-пароля.
- Просмотр и изменение лимита записей узла хранилища на сервере.
- Сообщения и справка на английском и русском. Язык берется из первой непустой переменной `LC_ALL`, `LC_MESSAGES`, `LANG`: для локали `ru` (например, `ru_RU.UTF-8`) - русский, для остальных - английский. Встроенные тексты разбора аргументов (`Usage`, `error:`) всегда на английском.

Поддерживаются Linux и macOS. Windows не поддерживается: агенту нужен unix-сокет.

## Установка

Готовые бинарники для Linux x86_64 и aarch64 - на странице [релизов](https://github.com/tzx1z/inkvault-cli/releases). Бинарники собраны статически с musl и работают в любом дистрибутиве. Нужно скачать архив для своей архитектуры и `SHA256SUMS`, проверить архив и положить `inkvault` в каталог из `PATH`:

```sh
sha256sum --ignore-missing -c SHA256SUMS
tar -xzf inkvault-cli-<версия>-x86_64-unknown-linux-musl.tar.gz
install -m 755 inkvault-cli-<версия>-x86_64-unknown-linux-musl/inkvault ~/.local/bin/
```

На macOS и других платформах - установка с [crates.io](https://crates.io/crates/inkvault-cli) (нужен Rust 1.85 или новее):

```sh
cargo install --locked inkvault-cli
```

## Начало работы

Хранилище создается в web- или Android-клиенте. CLI входит в уже созданное хранилище.

```sh
inkvault login alice@example.org     # пароль XMPP и мастер-пароль вводятся в терминале
inkvault ls                          # список записей
inkvault get github.com              # пароль записи в stdout
inkvault get github.com -f username  # другое поле
inkvault otp github.com              # текущий код TOTP
inkvault lock                        # выгрузить ключи из памяти
```

Если хранилище заблокировано и есть терминал, любая команда спросит мастер-пароль и запустит агент. Без терминала команда завершится с ошибкой.

Адрес сервера берется из SRV-записи домена JID. Другой адрес задается при входе: `inkvault login alice@example.org --server xmpp.example.org:5222`. Подключение идет через STARTTLS.

## Примеры

```sh
# скопировать пароль в буфер обмена
inkvault get github.com | wl-copy

# новая запись со сгенерированным паролем длиной 32, тегом и в избранном
inkvault add gitlab.com --username alice --url https://gitlab.com -g -l 32 -t работа/git --favorite

# запись с паролем из stdin, например в скрипте
printf '%s\n' "$DB_PASSWORD" | inkvault add prod-db --username postgres --password-stdin --sync

# запись с паролем вида PIN + код: get выдает PIN вместе с текущим кодом
inkvault add vpn --username bob --pin-totp

# правка: новый логин, снять тег, сгенерировать новый пароль
inkvault edit gitlab.com --username alice2 --untag работа/git -g

# несколько записей с одним названием: выбор по логину
inkvault get mail.example.org -u bob

# переместить в корзину без подтверждения
inkvault rm old-site --force

# резервная копия, зашифрованная отдельным паролем
inkvault export > backup-$(date +%F).ivx
inkvault export | rclone rcat remote:inkvault/backup-$(date +%F).ivx

# импорт: записи сливаются с хранилищем, более новые правки не затираются
inkvault import backup-2026-10-15.ivx
rclone cat remote:inkvault/backup.ivx | inkvault import

# состояние агента для скриптов
inkvault status --json

# пароль без хранилища
inkvault gen -l 24 --no-symbols --avoid-ambiguous

# лимит записей узла: показать, затем поднять после увеличения pep_max_items на сервере
inkvault max-items
inkvault max-items 10000
```

## Команды

| Команда | Действие |
|---------|----------|
| `login JID` | вход на этом устройстве |
| `unlock` | разблокировать хранилище, агент держит ключи в памяти |
| `lock` | заблокировать хранилище |
| `logout` | заблокировать и удалить данные устройства: вход, пароль XMPP и кэш |
| `status` | учетная запись (JID), состояние агента и соединения |
| `ls [ЗАПРОС]` | список записей без паролей, фильтр по названию, адресу, логину или тегу |
| `get ЗАПРОС` | значение поля, по умолчанию пароль; `--json` - вся запись |
| `otp ЗАПРОС` | текущий код TOTP |
| `add НАЗВАНИЕ` | добавить запись и вывести ее id |
| `edit ЗАПРОС` | изменить запись |
| `rm ЗАПРОС` | переместить запись в корзину |
| `export` | зашифрованный файл экспорта в stdout |
| `import [ФАЙЛ]` | импорт файла экспорта, без файла - из stdin |
| `sync` | загрузить записи с сервера заново |
| `max-items [N]` | лимит записей узла хранилища, с `N` - изменить его |
| `passwd` | сменить мастер-пароль |
| `gen` | сгенерировать пароль |

Подробности по ключам: `inkvault --help` и `inkvault КОМАНДА --help`.

Запись выбирается по id, по точному названию или по единственному совпадению с частью названия или адреса. Если подходят несколько записей, команда завершается с ошибкой и просит уточнить логин ключом `-u`.

Ключи, общие для команд:

- `--password-stdin` - читать пароли и секреты из stdin, по одному на строку.
- `--sync` - дождаться отправки изменения на сервер. Без связи изменение с `--sync` не сохраняется, команда завершается с ошибкой.
- `--force` - пропустить проверку или подтверждение, которые иначе остановили бы команду.
- `--json` - вывод в JSON.

## Безопасность

- Мастер-пароль и пароли записей не передаются аргументами командной строки: аргументы видны в списке процессов. Они вводятся в терминале или читаются из stdin.
- Агент слушает unix-сокет в `$XDG_RUNTIME_DIR/inkvault`: каталог 0700, сокет 0600, uid собеседника проверяется.
- Агент блокирует хранилище через 15 минут без запросов (`--timeout` у `unlock` и `login`, 0 - только командой `lock`) и по SIGTERM.
- Пароль XMPP хранится на устройстве зашифрованным ключом хранилища: без мастер-пароля его не открыть.
- Вход по SCRAM, PLAIN только внутри TLS. Без TLS (`--server tcp://127.0.0.1:port`) можно подключиться только к адресу loopback, это режим для тестового сервера.
- Уведомления об изменениях принимаются только от своей учетной записи.

## Данные на устройстве

| Путь | Содержимое |
|------|------------|
| `~/.local/share/inkvault` | вход, зашифрованный пароль XMPP, копия учетной записи, зашифрованный кэш записей |
| `$XDG_RUNTIME_DIR/inkvault` | сокет агента |

Другой профиль задается переменной `INKVAULT_HOME`. Файлы пишутся через временный файл с правами 0600.

`login` и `logout` удаляют кэш вместе с неотправленными изменениями, поэтому при наличии таких изменений требуют `--force`.

## Ограничения

- Хранилище создается в web- или Android-клиенте.
- Корзина в CLI не показывается: восстановление и очистка корзины - в web- и Android-клиентах.
- Вход без SASL2 и FAST: клиент хранит пароль XMPP (зашифрованным), а не токен.
- Если мастер-пароль сменили на другом устройстве, CLI открывает хранилище прежним паролем до подключения к серверу, затем принимает новую учетную запись. Другой вариант - `inkvault login` заново.

## Требования к серверу

Prosody 13 или другой XMPP-сервер с PEP (XEP-0163) и `publish-options`.

Клиент работает с настройками Prosody по умолчанию: новое хранилище создается с лимитом 256 записей, это `pep_max_items` по умолчанию. В лимит входят и записи в корзине. Для хранилищ больше 256 записей рекомендуется поднять лимит на сервере:

```lua
pep_max_items = 10000
```

После этого лимит узла хранилища поднимается один раз с любого клиента, например `inkvault max-items 10000`. Остальные клиенты читают лимит узла с сервера и подхватывают его сами. Лимит больше `pep_max_items` сервер не примет, а меньше числа записей клиент не установит: при уменьшении сервер удалил бы старые записи.

## Разработка

```sh
git clone https://github.com/tzx1z/inkvault-cli.git
cd inkvault-cli
cargo build
cargo test
cargo fmt --check
python3 -I tools/licenses.py   # лицензии зависимостей
```

Ядро - крейт [`inkvault-core`](https://crates.io/crates/inkvault-core) с crates.io. Чтобы собрать CLI с локальной копией [inkvault-core](https://github.com/tzx1z/inkvault-core) в соседнем каталоге:

```sh
cargo build --config 'patch.crates-io.inkvault-core.path="../inkvault-core/core"'
```

Такая сборка меняет запись ядра в `Cargo.lock`, перед коммитом его нужно вернуть: `git checkout Cargo.lock`.

Сквозной тест на тестовом Prosody: хранилище создает Node-утилита ядра `@inkov-dev/inkvault-testkit`, CLI работает с ним через агент. Утилита и образ тестового сервера `registry.gitlab.com/inkvault/inkvault-core/test-prosody` той же версии загружаются из закрытых реестров GitLab ядра. Нужны podman, Node.js 22 и токен GitLab: personal access token со scope `read_api` и `read_registry` или deploy token со scope `read_package_registry` и `read_registry`:

```sh
podman login registry.gitlab.com                                          # один раз
npm config set -- //gitlab.com/api/v4/projects/inkvault%2Finkvault-core/packages/npm/:_authToken <токен>    # один раз
(cd tests && npm ci)
tests/e2e.sh
```

### Пайплайн выпуска

Релизы собирает GitLab CI (`.gitlab-ci.yml`), на GitHub уходят только код и бинарники. На коммит в `main` и в merge request - проверка форматирования, тесты и проверка лицензий. Тег `vX.Y.Z` запускает:

1. `test`: проверяет, что тег совпадает с версией в `Cargo.toml`, затем те же проверки, что на `main`.
2. `binary-x86_64` и `binary-aarch64`: статические release-сборки на раннерах GitLab amd64 и arm64, результат - артефакты `inkvault-cli-X.Y.Z-<target>.tar.gz` с `inkvault`, `LICENSE` и `README.md`.
3. `publish-crates`: публикует `inkvault-cli` на crates.io через Trusted Publishing. Версия, которая уже есть на crates.io, пропускается.
4. `publish-github`: отправляет коммит тега в `main` и тег на GitHub, затем создает релиз с архивами и `SHA256SUMS`. Текст релиза - аннотация тега. Повторный запуск не создает второй релиз.

Настройки:

- GitLab: защищенные теги `v*`, иначе задание не получит защищенную переменную `GH_TOKEN`.
- Переменная CI/CD `GH_TOKEN` с флагами Protected и Masked: fine-grained токен GitHub с доступом Contents: read and write к `tzx1z/inkvault-cli`. Без нее пайплайн тега завершается после `publish-crates`.
- crates.io, настройки крейта `inkvault-cli` - Trusted Publishing: GitLab, namespace `inkvault`, project `inkvault-cli`, workflow filepath `.gitlab-ci.yml`, без environment. Задание получает токен публикации по OIDC, токен crates.io в GitLab не хранится. Trusted Publishing настраивается только для существующего крейта, поэтому первая версия публикуется вручную командой `cargo publish`.

Ветка `main` на GitHub только догоняет коммит тега: если в ней есть коммиты, которых нет в GitLab, push отклоняется.

## Лицензия

[GNU AGPL v3.0](LICENSE) (`AGPL-3.0-only`). Copyright (C) 2026 Evgeny Inkov.

## Автор

Evgeny Inkov

- Почта: [me@inkov.dev](mailto:me@inkov.dev)
- XMPP: [tzx1z@inkov.dev](xmpp:tzx1z@inkov.dev)
- Сайт: [inkov.dev](https://inkov.dev)
