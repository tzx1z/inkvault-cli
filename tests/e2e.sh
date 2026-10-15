#!/bin/sh
# Сквозная проверка CLI на тестовом Prosody: хранилище и записи создает другой клиент
# (testkit/vault/vault.mjs из inkvault-core, ядро в WASM), CLI читает их через агент.
# Нужен checkout inkvault-core (по умолчанию рядом, иначе путь в INKVAULT_CORE) с выполненными
# bindings/build.sh wasm и npm ci в testkit/vault.
set -eu
cd "$(dirname "$0")/.."
ROOT=$(pwd)
CORE=$(cd "${INKVAULT_CORE:-$ROOT/../inkvault-core}" && pwd)
VAULT="$CORE/testkit/vault/vault.mjs"
if [ ! -f "$CORE/bindings/wasm/pkg/node/inkvault_wasm.js" ] || [ ! -d "$CORE/testkit/vault/node_modules" ]; then
    echo "в $CORE нет сборки WASM для Node или зависимостей testkit/vault" >&2
    exit 1
fi
CONTAINER=inkvault-cli-e2e
SERVER=tcp://127.0.0.1:15222
MASTER="correct horse battery staple"
NEW_MASTER="new horse battery staple"
CLI_MASTER="cli horse battery staple"
TOTP_SECRET=JBSWY3DPEHPK3PXP

cargo build -q
INKVAULT="$ROOT/target/debug/inkvault"
INKVAULT_HOME=$(mktemp -d)
export INKVAULT_HOME
BACKUP_DIR=$(mktemp -d)

cleanup() {
    "$INKVAULT" lock >/dev/null 2>&1 || true
    podman rm -f "$CONTAINER" >/dev/null 2>&1 || true
    rm -rf "$INKVAULT_HOME" "$BACKUP_DIR"
}
trap cleanup EXIT

# setsid отвязывает команду от терминала: без него заблокированный CLI спросил бы мастер-пароль
cli() { setsid -w "$INKVAULT" "$@"; }
vault() { node "$VAULT" "$@" >/dev/null; }

FAILED=0
check() {
    if [ "$2" = "$3" ]; then
        echo "ok    $1"
    else
        echo "FAIL  $1: ожидалось '$2', получено '$3'"
        FAILED=1
    fi
}

# команда должна завершиться с ошибкой, в тексте ошибки - ожидаемая подстрока
check_fails() {
    name=$1 expected=$2
    shift 2
    if output=$("$@" 2>&1); then
        check "$name" "ошибка: $expected" "успех: $output"
    else
        case $output in
            *"$expected"*) check "$name" ok ok ;;
            *) check "$name" "$expected" "$output" ;;
        esac
    fi
}

# повторяет команду, пока ее вывод не совпадет с ожидаемым
wait_for() {
    name=$1 expected=$2 seconds=$3
    shift 3
    deadline=$(($(date +%s) + seconds))
    while :; do
        actual=$("$@" 2>&1) || true
        if [ "$actual" = "$expected" ] || [ "$(date +%s)" -ge "$deadline" ]; then
            check "$name" "$expected" "$actual"
            return
        fi
        sleep 0.5
    done
}

wait_server() {
    for _ in $(seq 60); do
        podman logs --since "$1" "$CONTAINER" 2>&1 | grep -q "Activated service 'c2s'" && return
        sleep 0.5
    done
    echo "тестовый Prosody не запустился" >&2
    exit 1
}

totp() {
    python3 -I -c '
import base64, hmac, struct, sys, time
key = base64.b32decode(sys.argv[1])
mac = hmac.digest(key, struct.pack(">Q", int(time.time()) // 30), "sha1")
offset = mac[-1] & 15
print("%06d" % ((struct.unpack(">I", mac[offset:offset + 4])[0] & 0x7fffffff) % 10**6))
' "$TOTP_SECRET"
}

# команда в псевдотерминале, первый аргумент - строка, которую вводят в терминал
in_tty() {
    input=$1
    shift
    printf '%s\n' "$input" |
        python3 -I -c 'import os, pty, sys; sys.exit(os.waitstatus_to_exitcode(pty.spawn(sys.argv[1:])))' "$@"
}

connection() { cli status --json | python3 -I -c 'import json, sys; print(json.load(sys.stdin)["connection"]["state"])'; }
pending() { cli status --json | python3 -I -c 'import json, sys; print(json.load(sys.stdin)["pending"])'; }

podman image exists inkvault-test-prosody || podman build -q -t inkvault-test-prosody "$CORE/testkit/prosody" >/dev/null
podman rm -f "$CONTAINER" >/dev/null 2>&1 || true
since=$(date -u +%Y-%m-%dT%H:%M:%SZ)
podman run -d --name "$CONTAINER" -p 127.0.0.1:15222:5222 -p 127.0.0.1:15280:5280 inkvault-test-prosody >/dev/null
wait_server "$since"

MASTER_PASSWORD=$MASTER vault setup

echo "--- вход"
check_fails "неверный пароль XMPP" "вход в XMPP не выполнен" \
    sh -c "printf 'wrong\n%s\n' '$MASTER' | setsid -w '$INKVAULT' login alice@vault.test --server $SERVER --password-stdin"
check_fails "неверный мастер-пароль при входе" "неверный мастер-пароль" \
    sh -c "printf 'secret\nwrong\n' | setsid -w '$INKVAULT' login alice@vault.test --server $SERVER --password-stdin"
check_fails "хранилища нет на сервере" "нет хранилища" \
    sh -c "printf 'secret\n%s\n' '$MASTER' | setsid -w '$INKVAULT' login bob@vault.test --server $SERVER --password-stdin"
printf 'secret\n%s\n' "$MASTER" | cli login alice@vault.test --server "$SERVER" --password-stdin
check "права каталога профиля" 700 "$(stat -c %a "$INKVAULT_HOME")"
check "права файла пароля XMPP" 600 "$(stat -c %a "$INKVAULT_HOME/xmpp-password")"
if grep -q secret "$INKVAULT_HOME/xmpp-password"; then check "пароль XMPP зашифрован" да нет; else check "пароль XMPP зашифрован" да да; fi

echo "--- чтение"
wait_for "состояние после входа" online 10 connection
check "пароль" 'Xk7#pQ2v' "$(cli get github.com)"
check "поле username" alice "$(cli get GitHub -f username)"
check "список в pipe" "$(printf 'github.com\talice')" "$(cli ls)"
check_fails "второй агент" "агент уже запущен" \
    sh -c "printf '{\"master_password\":\"x\",\"timeout_min\":1,\"login\":null}\n' | '$INKVAULT' agent"
check "первый агент работает после второго" alice "$(cli get github.com -f username)"
check_fails "нет записи" "запись не найдена" cli get gitlab
check_fails "пустое поле" "нет поля url" cli get github.com -f url

echo "--- изменения с другого клиента"
MASTER_PASSWORD=$MASTER vault add "{\"name\":\"vpn\",\"username\":\"bob\",\"password\":\"1234\",\"totp\":\"$TOTP_SECRET\",\"password_mode\":\"pin_totp\"}"
wait_for "уведомление о новой записи" bob 15 cli get vpn -f username
before=$(totp)
code=$(cli otp vpn)
after=$(totp)
[ "$code" = "$after" ] && before=$after
check "код TOTP" "$before" "$code"
ready=$(cli get vpn)
after=$(totp)
case $ready in "1234$before" | "1234$after") ready="1234$after" ;; esac
check "пароль PIN + код" "1234$after" "$ready"

echo "--- добавление записей в CLI"
id=$(printf 'p@ss-1\n' | cli add gitlab.com --username alice --url https://gitlab.com -t ' работа/git/ ' --favorite --password-stdin)
check "пароль новой записи" 'p@ss-1' "$(cli get "$id")"
check "теги новой записи" "@favorite,работа/git" \
    "$(cli ls gitlab --json | python3 -I -c 'import json, sys; print(",".join(json.load(sys.stdin)[0]["tags"]))')"
check "другой клиент получает запись из CLI" 1 \
    "$(MASTER_PASSWORD=$MASTER node "$VAULT" list | grep -cF "$id {\"name\":\"gitlab.com\",\"password\":\"p@ss-1\"")"
check_fails "запись с тем же названием и логином" "уже есть" \
    sh -c "printf 'x\n' | setsid -w '$INKVAULT' add GitLab.com --username alice --password-stdin"
printf 'p@ss-2\n' | cli add gitlab.com --username bob --password-stdin >/dev/null
check "то же название с другим логином" 'p@ss-2' "$(cli get gitlab.com -u bob)"
generated=$(cli get "$(cli add generated -g -l 32)")
check "длина сгенерированного пароля" 32 "${#generated}"
printf '4321\n%s\n' "$TOTP_SECRET" | cli add vpn-cli --username carol --pin-totp --password-stdin >/dev/null
before=$(totp)
ready=$(cli get vpn-cli)
after=$(totp)
case $ready in "4321$before" | "4321$after") ready="4321$after" ;; esac
check "PIN + код из CLI" "4321$after" "$ready"
check_fails "неверный секрет TOTP" "неверный секрет TOTP" \
    sh -c "printf 'pw\nnot-base32!\n' | setsid -w '$INKVAULT' add bad-totp --totp --password-stdin"
check_fails "недопустимый тег" "недопустимый тег" \
    sh -c "printf 'pw\n' | setsid -w '$INKVAULT' add bad-tag -t 'a//b' --password-stdin"

echo "--- правка и удаление в CLI"
printf 'n3w-p@ss\n' | cli edit "$id" -p --username alice2 --url '' -t работа/ci --untag работа/git --no-favorite --password-stdin --sync
check "новый пароль" 'n3w-p@ss' "$(cli get "$id")"
check "новый логин" alice2 "$(cli get "$id" -f username)"
check_fails "удаленный адрес" "нет поля url" cli get "$id" -f url
check "теги после правки" "работа/ci" \
    "$(cli ls alice2 --json | python3 -I -c 'import json, sys; print(",".join(json.load(sys.stdin)[0]["tags"]))')"
check "другой клиент получает правку из CLI" 1 \
    "$(MASTER_PASSWORD=$MASTER node "$VAULT" list | grep -cF "$id {\"name\":\"gitlab.com\",\"password\":\"n3w-p@ss\"")"
check_fails "правка в повтор названия и логина" "уже есть" cli edit gitlab.com -u bob --username alice2
check_fails "правка без изменений" "не указано, что изменить" cli edit gitlab.com -u bob
check_fails "PIN + код без секрета TOTP" "нужен секрет TOTP" cli edit vpn-cli --no-totp
cli edit vpn-cli --no-pin-totp
check "обычный пароль вместо PIN + код" 4321 "$(cli get vpn-cli)"
printf '%s\n' "$TOTP_SECRET" | cli edit generated -g -l 24 --totp --password-stdin
generated=$(cli get generated)
check "новый сгенерированный пароль" 24 "${#generated}"
check "новый секрет TOTP" "$TOTP_SECRET" "$(cli get generated -f totp)"
check_fails "удаление без терминала и --force" "--force" cli rm generated
check_fails "отказ от удаления" "удаление отменено" in_tty n "$INKVAULT" rm generated
check "запись после отказа" "$TOTP_SECRET" "$(cli get generated -f totp)"
in_tty y "$INKVAULT" rm generated >/dev/null
check_fails "удаленная запись" "запись не найдена" cli get generated
cli rm gitlab.com -u bob --force --sync
check_fails "удаление с --force и --sync" "запись не найдена" cli get gitlab.com -u bob

echo "--- лимит узла"
check "лимит узла по умолчанию" 256 "$(cli max-items)"
check_fails "лимит меньше числа записей" "не может быть меньше" cli max-items 1
check_fails "лимит больше pep_max_items" "сервер не принял лимит узла 20000" cli max-items 20000
check "лимит поднят" 1000 "$(cli max-items 1000)"
check "другой клиент следует лимиту узла" "vault: лимит узла 1000" "$(MASTER_PASSWORD=$MASTER node "$VAULT" max-items | tail -1)"

echo "--- экспорт и импорт"
printf 'file-pass\n' | cli export --password-stdin >"$BACKUP_DIR/separate.ivx"
check "формат файла экспорта" inkvault-export \
    "$(python3 -I -c 'import json, sys; print(json.load(open(sys.argv[1]))["format"])' "$BACKUP_DIR/separate.ivx")"
if grep -q 'Xk7#pQ2v' "$BACKUP_DIR/separate.ivx"; then check "пароли в файле зашифрованы" да нет; else check "пароли в файле зашифрованы" да да; fi
check_fails "экспорт в терминал" "перенаправьте" in_tty x "$INKVAULT" export
check_fails "экспорт с неверным мастер-паролем" "неверный мастер-пароль" \
    sh -c "printf 'wrong\n' | setsid -w '$INKVAULT' export --master --password-stdin >/dev/null"
printf '%s\n' "$MASTER" | cli export --master --password-stdin >"$BACKUP_DIR/master.ivx"
cli edit github.com --notes "после экспорта"
# как rclone cat: файл приходит в stdin, пароль файла вводится в терминале
check "импорт из pipe с паролем из терминала" "импорт: новых 0, обновлено 0" \
    "$(in_tty file-pass sh -c 'cat "$1" | "$0" import' "$INKVAULT" "$BACKUP_DIR/separate.ivx" | grep -o 'импорт: новых [0-9]*, обновлено [0-9]*')"
check "импорт не затирает более новую правку" "после экспорта" "$(cli get github.com -f notes)"
check "импорт файла под мастер-паролем" "импорт: новых 0, обновлено 0" \
    "$(printf '%s\n' "$MASTER" | cli import "$BACKUP_DIR/master.ivx" --password-stdin --sync | grep -o 'импорт: новых [0-9]*, обновлено [0-9]*')"
check_fails "неверный пароль файла" "неверный пароль файла" \
    sh -c "printf 'wrong\n' | setsid -w '$INKVAULT' import '$BACKUP_DIR/separate.ivx' --password-stdin"
check_fails "пароль и файл из stdin" "укажите путь к файлу" \
    sh -c "cat '$BACKUP_DIR/separate.ivx' | setsid -w '$INKVAULT' import --password-stdin"
check_fails "пустой файл экспорта" "файл экспорта пуст" sh -c "setsid -w '$INKVAULT' import </dev/null"

echo "--- смена мастер-пароля на другом клиенте"
MASTER_PASSWORD=$MASTER NEW_MASTER_PASSWORD=$NEW_MASTER vault passwd
cli sync
cli lock
check "блокировка" "хранилище заблокировано" "$(cli status)"
check_fails "заблокировано без терминала" "хранилище заблокировано" cli get github.com
check_fails "старый мастер-пароль" "неверный мастер-пароль" sh -c "printf '%s\n' '$MASTER' | setsid -w '$INKVAULT' unlock --password-stdin"
printf '%s\n' "$NEW_MASTER" | cli unlock --password-stdin
check "новый мастер-пароль" 'Xk7#pQ2v' "$(cli get github.com)"

echo "--- смена мастер-пароля в CLI"
check_fails "смена с неверным текущим паролем" "неверный мастер-пароль" \
    sh -c "printf 'wrong\n%s\n' '$CLI_MASTER' | setsid -w '$INKVAULT' passwd --password-stdin"
# заблокированное хранилище: passwd запускает агент текущим паролем и ждет подключения
cli lock
check "смена мастер-пароля" "мастер-пароль изменен" \
    "$(printf '%s\n%s\n' "$NEW_MASTER" "$CLI_MASTER" | cli passwd --password-stdin 2>&1)"
check_fails "другой клиент: прежний мастер-пароль после смены в CLI" "неверный мастер-пароль" \
    env MASTER_PASSWORD="$NEW_MASTER" node "$VAULT" list
MASTER_PASSWORD=$CLI_MASTER vault add '{"name":"after-passwd","username":"dave","password":"y"}'
wait_for "другой клиент открывает хранилище паролем из CLI" dave 15 cli get after-passwd -f username
cli lock
check_fails "CLI: прежний мастер-пароль" "неверный мастер-пароль" sh -c "printf '%s\n' '$NEW_MASTER' | setsid -w '$INKVAULT' unlock --password-stdin"
printf '%s\n' "$CLI_MASTER" | cli unlock --password-stdin
check "CLI: новый мастер-пароль" alice "$(cli get github.com -f username)"

echo "--- без сервера"
cli lock
podman stop -t 1 "$CONTAINER" >/dev/null
printf '%s\n' "$CLI_MASTER" | cli unlock --password-stdin
check "чтение из кэша" alice "$(cli get github.com -f username)"
wait_for "состояние без сервера" offline 10 connection
check_fails "синхронизация без сервера" "сервер недоступен" cli sync
check "лимит узла из кэша без сервера" 1000 "$(cli max-items)"
check_fails "изменение лимита без сервера" "сервер недоступен" cli max-items 2000
check_fails "смена мастер-пароля без сервера" "сервер недоступен" \
    sh -c "printf '%s\nother\n' '$CLI_MASTER' | setsid -w '$INKVAULT' passwd --password-stdin"
check_fails "добавление с --sync без сервера" "сервер недоступен" \
    sh -c "printf 'x\n' | setsid -w '$INKVAULT' add offline-sync --password-stdin --sync"
check_fails "правка с --sync без сервера" "сервер недоступен" cli edit github.com --notes x --sync
check_fails "удаление с --sync без сервера" "сервер недоступен" cli rm github.com --force --sync
warning=$(printf 'off-pw\n' | cli add offline-site --username erin --password-stdin 2>&1 >/dev/null)
case $warning in
    *"еще не отправлены"*) check "предупреждение о неотправленной записи" ok ok ;;
    *) check "предупреждение о неотправленной записи" "еще не отправлены" "$warning" ;;
esac
check "запись без сервера" erin "$(cli get offline-site -f username)"
check "неотправленные изменения" 1 "$(pending)"
check_fails "выход с неотправленными изменениями" "неотправленные изменения записей: 1" cli logout
check_fails "вход с неотправленными изменениями" "неотправленные изменения записей: 1" \
    sh -c "printf 'secret\n%s\n' '$CLI_MASTER' | setsid -w '$INKVAULT' login alice@vault.test --server $SERVER --password-stdin"
since=$(date -u +%Y-%m-%dT%H:%M:%SZ)
podman start "$CONTAINER" >/dev/null
wait_server "$since"
wait_for "переподключение" online 45 connection
wait_for "отправка изменений после переподключения" 0 15 pending
check "другой клиент получает запись, добавленную без сервера" 1 \
    "$(MASTER_PASSWORD=$CLI_MASTER node "$VAULT" list | grep -cF '{"name":"offline-site","password":"off-pw"')"
MASTER_PASSWORD=$CLI_MASTER vault add '{"name":"after-restart","username":"carol","password":"x"}'
wait_for "уведомления после переподключения" carol 15 cli get after-restart -f username

echo "--- выход"
cli logout
check "файлы профиля удалены" "" "$(ls -A "$INKVAULT_HOME")"
check_fails "команды после выхода" "нет входа" cli ls

exit $FAILED
