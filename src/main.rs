//! Терминальный клиент InkVault для команд и скриптов. Ключи хранилища держит агент, который
//! запускает `inkvault unlock`; остальные команды получают записи у него через unix-сокет.

#[cfg(not(unix))]
compile_error!("CLI работает в Linux и macOS: агенту нужен unix-сокет");

/// Текст на языке процесса: `tr!("english {x}", "русский {x}")`. Объявлен до модулей, чтобы был виден в них.
macro_rules! tr {
    ($en:literal, $ru:literal $(, $arg:expr)* $(,)?) => {
        match inkvault_core::lang::current() {
            inkvault_core::Lang::En => format!($en $(, $arg)*),
            inkvault_core::Lang::Ru => format!($ru $(, $arg)*),
        }
    };
}

mod agent;
mod proto;
mod store;
mod xmpp;

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, IsTerminal, Read, Write};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::process::{ExitCode, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use clap::{Args, CommandFactory, FromArgMatches, Parser, Subcommand};
use inkvault_core::Lang;
use inkvault_core::otp::Totp;
use inkvault_core::password::{self, PasswordOptions};
use inkvault_core::record::{FAVORITE_TAG, validate_tag};
use zeroize::Zeroizing;

use proto::{Connection, Entry, Login, Reply, Request, Start};
use store::Store;

#[derive(Parser)]
#[command(name = "inkvault", version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

// справка к подкомандам и аргументам - в таблице HELP на двух языках
#[derive(Subcommand)]
enum Command {
    Login {
        jid: String,
        #[arg(long)]
        server: Option<String>,
        #[command(flatten)]
        unlock: UnlockArgs,
        #[arg(long)]
        force: bool,
    },
    Unlock(UnlockArgs),
    Lock,
    Logout {
        #[arg(long)]
        force: bool,
    },
    Status {
        #[arg(long)]
        json: bool,
    },
    Ls {
        query: Option<String>,
        #[arg(long)]
        json: bool,
    },
    Get {
        #[command(flatten)]
        entry: EntryQuery,
        #[arg(short, long)]
        field: Option<String>,
        #[arg(long, conflicts_with = "field")]
        json: bool,
    },
    Otp(EntryQuery),
    Add(AddArgs),
    Edit(EditArgs),
    Rm {
        #[command(flatten)]
        entry: EntryQuery,
        #[arg(long)]
        force: bool,
        #[arg(long)]
        sync: bool,
    },
    Export {
        #[arg(long)]
        master: bool,
        #[arg(long)]
        password_stdin: bool,
    },
    Import {
        file: Option<String>,
        #[arg(long)]
        password_stdin: bool,
        #[arg(long)]
        sync: bool,
    },
    Sync,
    MaxItems {
        value: Option<u32>,
    },
    Passwd {
        #[arg(long)]
        password_stdin: bool,
    },
    Gen {
        #[arg(short, long, default_value_t = 20)]
        length: u32,
        #[arg(long)]
        no_lower: bool,
        #[arg(long)]
        no_upper: bool,
        #[arg(long)]
        no_digits: bool,
        #[arg(long)]
        no_symbols: bool,
        #[arg(long)]
        avoid_ambiguous: bool,
    },
    #[command(hide = true)]
    Agent,
}

#[derive(Args)]
struct UnlockArgs {
    #[arg(long, default_value_t = 15)]
    timeout: u64,
    #[arg(long)]
    password_stdin: bool,
}

// выбор записи, одинаковый для get, otp, edit и rm
#[derive(Args)]
struct EntryQuery {
    query: String,
    #[arg(short, long)]
    user: Option<String>,
}

#[derive(Args)]
struct GenerateArgs {
    #[arg(short, long)]
    generate: bool,
    #[arg(short, long, requires = "generate")]
    length: Option<u32>,
}

impl GenerateArgs {
    fn password(&self) -> Result<Zeroizing<String>, String> {
        let defaults = PasswordOptions::default();
        let options = PasswordOptions {
            length: self.length.unwrap_or(defaults.length),
            ..defaults
        };
        password::generate(&options).map_err(|e| e.to_string())
    }
}

// Значения полей задаются ключами с именами полей, как в get -f: --name, --username, --url, --notes
#[derive(Args)]
struct AddArgs {
    name: String,
    #[arg(long)]
    username: Option<String>,
    #[arg(long)]
    url: Option<String>,
    #[arg(long)]
    notes: Option<String>,
    #[arg(short = 't', long = "tag", value_name = "TAG")]
    tags: Vec<String>,
    #[arg(long)]
    favorite: bool,
    #[command(flatten)]
    generator: GenerateArgs,
    #[arg(long)]
    totp: bool,
    #[arg(long, conflicts_with = "generate")]
    pin_totp: bool,
    #[arg(long)]
    password_stdin: bool,
    #[arg(long)]
    sync: bool,
}

#[derive(Args)]
struct EditArgs {
    #[command(flatten)]
    entry: EntryQuery,
    #[arg(long)]
    name: Option<String>,
    #[arg(long)]
    username: Option<String>,
    #[arg(long)]
    url: Option<String>,
    #[arg(long)]
    notes: Option<String>,
    #[arg(short = 't', long = "tag", value_name = "TAG")]
    tags: Vec<String>,
    #[arg(long, value_name = "TAG")]
    untag: Vec<String>,
    #[arg(long, conflicts_with = "no_favorite")]
    favorite: bool,
    #[arg(long)]
    no_favorite: bool,
    #[arg(short, long, conflicts_with = "generate")]
    password: bool,
    #[command(flatten)]
    generator: GenerateArgs,
    #[arg(long, conflicts_with = "no_totp")]
    totp: bool,
    #[arg(long)]
    no_totp: bool,
    #[arg(long, conflicts_with = "no_pin_totp")]
    pin_totp: bool,
    #[arg(long)]
    no_pin_totp: bool,
    #[arg(long)]
    password_stdin: bool,
    #[arg(long)]
    sync: bool,
}

const ABOUT: (&str, &str) = (
    "InkVault password manager: commands for the terminal and scripts",
    "Менеджер паролей InkVault: команды для терминала и скриптов",
);
const AUTHOR: (&str, &str) = (
    concat!(
        "Author: ",
        env!("CARGO_PKG_AUTHORS"),
        ", XMPP: tzx1z@inkov.dev, https://inkov.dev"
    ),
    concat!(
        "Автор: ",
        env!("CARGO_PKG_AUTHORS"),
        ", XMPP: tzx1z@inkov.dev, https://inkov.dev"
    ),
);
const SYNC: (&str, &str) = (
    "Send the change to the server right away and wait for the answer. If sending fails, the command exits with an error",
    "Сразу отправить изменение на сервер и дождаться ответа. Если отправить не удалось, команда завершается с ошибкой",
);
const QUERY: (&str, &str) = (
    "id, name or part of the name or URL",
    "id, название или часть названия либо адреса",
);
const USER: (&str, &str) = (
    "Item username, if several items match the query",
    "Логин записи, если под запрос подходит несколько",
);
const TIMEOUT: (&str, &str) = (
    "Lock after this many minutes without requests, 0 - only with the lock command",
    "Блокировка после стольких минут без запросов, 0 - только командой lock",
);
const UNLOCK_STDIN: (&str, &str) = (
    "Read passwords from stdin, one per line; for login - the XMPP password, then the master password",
    "Читать пароли из stdin по одному на строку; для login - пароль XMPP, затем мастер-пароль",
);
const JSON: (&str, &str) = ("Output in JSON", "Вывод в JSON");
const TAG: (&str, &str) = (
    "Add a tag, can be given several times. Nested tag - with /: work/servers",
    "Поставить тег, можно указать несколько раз. Вложенный тег - через /: работа/серверы",
);
const FAVORITE: (&str, &str) = ("Add to favorites", "Добавить в избранное");
const GENERATE: (&str, &str) = (
    "Generate the password. Another character set - via inkvault gen and --password-stdin",
    "Сгенерировать пароль. Другой набор символов - через inkvault gen и --password-stdin",
);
const GENERATE_LENGTH: (&str, &str) = (
    "Length of the generated password, 20 by default",
    "Длина сгенерированного пароля, по умолчанию 20",
);
const TOTP: (&str, &str) = (
    "Enter a TOTP secret: base32 or an otpauth://totp/... link",
    "Ввести секрет TOTP: base32 или ссылку otpauth://totp/...",
);

/// Справка: подкоманда, id аргумента (пусто - описание подкоманды), текст на английском и на русском.
const HELP: &[(&str, &str, (&str, &str))] = &[
    (
        "login",
        "",
        (
            "Sign in on this device. The vault must already be created in the web or Android client.",
            "Вход на этом устройстве. Хранилище уже должно быть создано в web- или Android-клиенте.",
        ),
    ),
    ("login", "jid", ("JID in the form name@server", "JID вида имя@сервер")),
    (
        "login",
        "server",
        (
            "Server address: host[:port] (STARTTLS) or tcp://127.0.0.1:port (no TLS, loopback only). \
             By default the address comes from the SRV records of the JID domain.",
            "Адрес сервера: host[:port] (STARTTLS) или tcp://127.0.0.1:port (без TLS, только loopback). \
             По умолчанию адрес берется из SRV домена JID.",
        ),
    ),
    ("login", "timeout", TIMEOUT),
    ("login", "password_stdin", UNLOCK_STDIN),
    (
        "login",
        "force",
        (
            "Sign in even if the device has unsent item changes: they will be deleted",
            "Войти, даже если на устройстве есть неотправленные изменения записей: они будут удалены",
        ),
    ),
    (
        "unlock",
        "",
        (
            "Unlock the vault: the agent keeps the keys in memory until it is locked",
            "Разблокировать хранилище: агент держит ключи в памяти до блокировки",
        ),
    ),
    ("unlock", "timeout", TIMEOUT),
    ("unlock", "password_stdin", UNLOCK_STDIN),
    ("lock", "", ("Lock the vault", "Заблокировать хранилище")),
    (
        "logout",
        "",
        (
            "Lock and delete the data of this device: sign-in, XMPP password and item cache",
            "Заблокировать и удалить данные этого устройства: вход, пароль XMPP и кэш записей",
        ),
    ),
    (
        "logout",
        "force",
        (
            "Delete even if the device has unsent item changes",
            "Удалить, даже если на устройстве есть неотправленные изменения записей",
        ),
    ),
    (
        "status",
        "",
        ("Agent and connection state", "Состояние агента и соединения"),
    ),
    ("status", "json", JSON),
    ("ls", "", ("List items without passwords", "Список записей без паролей")),
    (
        "ls",
        "query",
        (
            "Part of the name, URL, username or tag",
            "Часть названия, адреса, логина или тега",
        ),
    ),
    ("ls", "json", JSON),
    (
        "get",
        "",
        (
            "Item field value, the password by default. For a PIN + code password - the PIN with the current code",
            "Значение поля записи, по умолчанию пароль. Для пароля вида PIN + код - PIN с текущим кодом",
        ),
    ),
    ("get", "query", QUERY),
    ("get", "user", USER),
    (
        "get",
        "field",
        (
            "Field: name, url, username, password, totp, notes",
            "Поле: name, url, username, password, totp, notes",
        ),
    ),
    ("get", "json", ("The whole item in JSON", "Вся запись в JSON")),
    ("otp", "", ("Current TOTP code of the item", "Текущий код TOTP записи")),
    ("otp", "query", QUERY),
    ("otp", "user", USER),
    (
        "add",
        "",
        ("Add an item and print its id", "Добавить запись и вывести ее id"),
    ),
    ("add", "name", ("Item name", "Название записи")),
    ("add", "username", ("Username", "Логин")),
    ("add", "url", ("Website URL", "Адрес сайта")),
    ("add", "notes", ("Notes", "Заметка")),
    ("add", "tags", TAG),
    ("add", "favorite", FAVORITE),
    ("add", "generate", GENERATE),
    ("add", "length", GENERATE_LENGTH),
    ("add", "totp", TOTP),
    (
        "add",
        "pin_totp",
        (
            "PIN + code password: the item password is the PIN, get returns it with the current code. Implies --totp",
            "Пароль вида PIN + код: пароль записи - это PIN, get выдает его вместе с текущим кодом. Включает --totp",
        ),
    ),
    (
        "add",
        "password_stdin",
        (
            "Read from stdin one per line: the password (without --generate), then the TOTP secret (with --totp)",
            "Читать из stdin по одному на строку: пароль (без --generate), затем секрет TOTP (с --totp)",
        ),
    ),
    ("add", "sync", SYNC),
    ("edit", "", ("Change an item", "Изменить запись")),
    ("edit", "query", QUERY),
    ("edit", "user", USER),
    ("edit", "name", ("Name", "Название")),
    (
        "edit",
        "username",
        ("Username, an empty string removes it", "Логин, пустая строка удаляет"),
    ),
    (
        "edit",
        "url",
        (
            "Website URL, an empty string removes it",
            "Адрес сайта, пустая строка удаляет",
        ),
    ),
    (
        "edit",
        "notes",
        ("Notes, an empty string removes them", "Заметка, пустая строка удаляет"),
    ),
    ("edit", "tags", TAG),
    (
        "edit",
        "untag",
        (
            "Remove a tag, can be given several times",
            "Снять тег, можно указать несколько раз",
        ),
    ),
    ("edit", "favorite", FAVORITE),
    ("edit", "no_favorite", ("Remove from favorites", "Убрать из избранного")),
    ("edit", "password", ("Enter the password", "Ввести пароль")),
    ("edit", "generate", GENERATE),
    ("edit", "length", GENERATE_LENGTH),
    ("edit", "totp", TOTP),
    ("edit", "no_totp", ("Delete the TOTP secret", "Удалить секрет TOTP")),
    (
        "edit",
        "pin_totp",
        (
            "PIN + code password: the item password is the PIN, get returns it with the current code",
            "Пароль вида PIN + код: пароль записи - это PIN, get выдает его вместе с текущим кодом",
        ),
    ),
    (
        "edit",
        "no_pin_totp",
        (
            "Regular password instead of PIN + code",
            "Обычный пароль вместо PIN + код",
        ),
    ),
    (
        "edit",
        "password_stdin",
        (
            "Read from stdin one per line: the password (with --password), then the TOTP secret (with --totp)",
            "Читать из stdin по одному на строку: пароль (с --password), затем секрет TOTP (с --totp)",
        ),
    ),
    ("edit", "sync", SYNC),
    ("rm", "", ("Move an item to the trash", "Переместить запись в корзину")),
    ("rm", "query", QUERY),
    ("rm", "user", USER),
    ("rm", "force", ("Without confirmation", "Без подтверждения")),
    ("rm", "sync", SYNC),
    (
        "export",
        "",
        (
            "Encrypted export file to stdout: all items, including the trash and password history",
            "Зашифрованный файл экспорта в stdout: все записи, включая корзину и историю паролей",
        ),
    ),
    (
        "export",
        "master",
        (
            "Encrypt with the master password. By default the file is encrypted with a separate password: \
             such a file opens even if the master password is lost",
            "Зашифровать мастер-паролем. По умолчанию файл шифруется отдельным паролем: такой файл \
             откроется и при потере мастер-пароля",
        ),
    ),
    (
        "export",
        "password_stdin",
        ("Read the password from stdin", "Читать пароль из stdin"),
    ),
    (
        "import",
        "",
        (
            "Import an export file: items are merged with the vault, newer edits are not overwritten",
            "Импорт файла экспорта: записи сливаются с хранилищем, более новые правки не затираются",
        ),
    ),
    (
        "import",
        "file",
        (
            "Export file, without it or \"-\" - stdin",
            "Файл экспорта, без него или \"-\" - stdin",
        ),
    ),
    (
        "import",
        "password_stdin",
        (
            "Read the file password from stdin, only together with FILE",
            "Читать пароль файла из stdin, только вместе с FILE",
        ),
    ),
    ("import", "sync", SYNC),
    (
        "sync",
        "",
        (
            "Load the items from the server again",
            "Загрузить записи с сервера заново",
        ),
    ),
    (
        "max-items",
        "",
        (
            "Item limit of the vault node on the server, with N - change it. The trash counts toward the limit",
            "Лимит записей узла хранилища на сервере, с N - изменить его. Корзина входит в лимит",
        ),
    ),
    (
        "max-items",
        "value",
        (
            "New limit: not less than the number of items and not more than pep_max_items on the server. \
             Requires a connection to the server",
            "Новый лимит: не меньше числа записей и не больше pep_max_items на сервере. Нужна связь с сервером",
        ),
    ),
    (
        "passwd",
        "",
        (
            "Change the master password. Requires a connection to the server, items are not re-encrypted",
            "Сменить мастер-пароль. Нужна связь с сервером, записи не перешифровываются",
        ),
    ),
    (
        "passwd",
        "password_stdin",
        (
            "Read passwords from stdin one per line: the current one, then the new one",
            "Читать пароли из stdin по одному на строку: текущий, затем новый",
        ),
    ),
    (
        "gen",
        "",
        (
            "Generate a password, no vault needed",
            "Сгенерировать пароль, хранилище не нужно",
        ),
    ),
    ("gen", "length", ("Password length", "Длина пароля")),
    ("gen", "no_lower", ("Without lowercase letters", "Без строчных букв")),
    ("gen", "no_upper", ("Without uppercase letters", "Без заглавных букв")),
    ("gen", "no_digits", ("Without digits", "Без цифр")),
    ("gen", "no_symbols", ("Without symbols", "Без спецсимволов")),
    (
        "gen",
        "avoid_ambiguous",
        (
            "No look-alike characters: I, l, 1, O, 0, o, |",
            "Без похожих символов: I, l, 1, O, 0, o, |",
        ),
    ),
];

/// Язык сообщений по правилам POSIX: первая непустая переменная из LC_ALL, LC_MESSAGES, LANG.
fn lang_from(var: impl Fn(&str) -> Option<String>) -> Lang {
    ["LC_ALL", "LC_MESSAGES", "LANG"]
        .into_iter()
        .find_map(|name| var(name).filter(|value| !value.is_empty()))
        .map_or(Lang::En, |tag| Lang::from_tag(&tag))
}

/// Команда clap со справкой на языке lang. Встроенные тексты clap остаются английскими.
fn command(lang: Lang) -> clap::Command {
    let pick = |(en, ru): (&'static str, &'static str)| if lang == Lang::Ru { ru } else { en };
    let mut cmd = Cli::command().about(pick(ABOUT)).after_help(pick(AUTHOR));
    for &(sub, arg, text) in HELP {
        let text = pick(text);
        cmd = cmd.mut_subcommand(sub, |c| {
            if arg.is_empty() {
                c.about(text)
            } else {
                c.mut_arg(arg, |a| a.help(text))
            }
        });
    }
    cmd
}

fn main() -> ExitCode {
    let lang = lang_from(|name| std::env::var(name).ok());
    inkvault_core::lang::set(lang);
    let cli = Cli::from_arg_matches(&command(lang).get_matches()).unwrap_or_else(|err| err.exit());
    match run(cli.command) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("inkvault: {err}");
            ExitCode::FAILURE
        }
    }
}

fn run(command: Command) -> Result<(), String> {
    let store = Store::locate()?;
    match command {
        Command::Agent => agent::main(store),
        Command::Gen {
            length,
            no_lower,
            no_upper,
            no_digits,
            no_symbols,
            avoid_ambiguous,
        } => {
            let options = PasswordOptions {
                length,
                lower: !no_lower,
                upper: !no_upper,
                digits: !no_digits,
                symbols: !no_symbols,
                avoid_ambiguous,
            };
            println!("{}", *password::generate(&options).map_err(|e| e.to_string())?);
            Ok(())
        }
        Command::Login {
            jid,
            server,
            unlock,
            force,
        } => {
            check_unsent(&store, force)?;
            stop_agent(&store)?;
            let mut passwords = Passwords::new(unlock.password_stdin);
            let xmpp_password = passwords.read(&tr!("XMPP password: ", "Пароль XMPP: "))?;
            let master_password = passwords.read(&tr!("Master password: ", "Мастер-пароль: "))?;
            start_agent(&Start {
                master_password,
                timeout_min: unlock.timeout,
                login: Some(Login {
                    jid,
                    server,
                    xmpp_password,
                }),
            })
        }
        Command::Unlock(unlock) => {
            if agent_running(&store) {
                return Ok(());
            }
            require_login(&store)?;
            let master_password =
                Passwords::new(unlock.password_stdin).read(&tr!("Master password: ", "Мастер-пароль: "))?;
            start_agent(&Start {
                master_password,
                timeout_min: unlock.timeout,
                login: None,
            })
        }
        Command::Lock => stop_agent(&store),
        Command::Logout { force } => {
            check_unsent(&store, force)?;
            stop_agent(&store)?;
            store.clear()
        }
        Command::Status { json } => status(&store, json),
        Command::Ls { query, json } => {
            let Reply::List(entries) = call(&store, &Request::List { query })? else {
                return Err(unexpected_reply());
            };
            print_list(&entries, json);
            Ok(())
        }
        Command::Get { entry, field, json } => {
            let entry = find(&store, entry)?;
            if json {
                println!(
                    "{}",
                    *Zeroizing::new(serde_json::to_string_pretty(&entry).expect("запись в JSON"))
                );
                return Ok(());
            }
            let value = match field.as_deref() {
                Some(name) => Zeroizing::new(entry.field(name).to_owned()),
                None if entry.field(proto::PASSWORD_MODE) == proto::PIN_TOTP => {
                    Zeroizing::new(format!("{}{}", entry.field(proto::PASSWORD), totp(&entry)?))
                }
                None => Zeroizing::new(entry.field(proto::PASSWORD).to_owned()),
            };
            if value.is_empty() {
                return Err(tr!(
                    "item {} has no field {}",
                    "в записи {} нет поля {}",
                    entry.field(proto::NAME),
                    field.as_deref().unwrap_or(proto::PASSWORD)
                ));
            }
            println!("{}", *value);
            Ok(())
        }
        Command::Otp(entry) => {
            println!("{}", totp(&find(&store, entry)?)?);
            Ok(())
        }
        Command::Add(args) => add(&store, args),
        Command::Edit(args) => edit(&store, args),
        Command::Rm { entry, force, sync } => remove(&store, entry, force, sync),
        Command::Export { master, password_stdin } => export(&store, master, password_stdin),
        Command::Import {
            file,
            password_stdin,
            sync,
        } => import(&store, file, password_stdin, sync),
        Command::Sync => call(&store, &Request::Sync).map(|_| ()),
        Command::MaxItems { value } => {
            ensure_unlocked(&store)?;
            wait_connection(&store)?;
            if let Some(max_items) = value {
                request(&store, &Request::SetMaxItems { max_items })?;
            }
            let Reply::Status(status) = request(&store, &Request::Status)? else {
                return Err(unexpected_reply());
            };
            println!("{}", status.max_items);
            Ok(())
        }
        Command::Passwd { password_stdin } => {
            require_login(&store)?;
            let mut passwords = Passwords::new(password_stdin);
            let current = passwords.read(&tr!("Current master password: ", "Текущий мастер-пароль: "))?;
            let new = passwords.read(&tr!("New master password: ", "Новый мастер-пароль: "))?;
            // в терминале пароль вводится вслепую, опечатка в нем закрыла бы доступ к хранилищу
            if !password_stdin
                && *passwords.read(&tr!("New master password again: ", "Новый мастер-пароль еще раз: "))? != *new
            {
                return Err(tr!("the new passwords do not match", "новые пароли не совпадают"));
            }
            if !agent_running(&store) {
                start_agent(&Start {
                    master_password: current.clone(),
                    timeout_min: 15,
                    login: None,
                })?;
            }
            wait_connection(&store)?;
            request(&store, &Request::ChangePassword { current, new })?;
            println!("{}", tr!("master password changed", "мастер-пароль изменен"));
            Ok(())
        }
    }
}

/// Агент после разблокировки еще подключается к серверу: без соединения смена пароля и изменения
/// с --sync сразу отклоняются.
fn wait_connection(store: &Store) -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let Reply::Status(status) = request(store, &Request::Status)? else {
            return Err(unexpected_reply());
        };
        if status.connection != Connection::Connecting || Instant::now() > deadline {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or_default()
}

fn totp(entry: &Entry) -> Result<String, String> {
    let secret = entry.field(proto::TOTP);
    if secret.is_empty() {
        return Err(tr!(
            "item {} has no TOTP secret",
            "в записи {} нет секрета TOTP",
            entry.field(proto::NAME)
        ));
    }
    let totp = Totp::parse(secret).map_err(|e| e.to_string())?;
    Ok(totp.code(now_ms()))
}

fn add(store: &Store, args: AddArgs) -> Result<(), String> {
    let name = args.name.trim();
    if name.is_empty() {
        return Err(tr!(
            "the item name cannot be empty",
            "название записи не может быть пустым"
        ));
    }
    let mut tags = parse_tags(&args.tags)?;
    if args.favorite {
        tags.push(FAVORITE_TAG.to_owned());
    }

    // мастер-пароль спрашивается раньше пароля записи: пока вводится пароль записи, агент подключается
    ensure_unlocked(store)?;
    let mut passwords = Passwords::new(args.password_stdin);
    let password = if args.generator.generate {
        args.generator.password()?
    } else {
        passwords.confirmed(&password_label(args.pin_totp))?
    };
    let mut fields = BTreeMap::from([
        (proto::NAME.to_owned(), name.to_owned()),
        (proto::PASSWORD.to_owned(), password.as_str().to_owned()),
    ]);
    if args.totp || args.pin_totp {
        fields.insert(proto::TOTP.to_owned(), passwords.totp()?);
    }
    if args.pin_totp {
        fields.insert(proto::PASSWORD_MODE.to_owned(), proto::PIN_TOTP.to_owned());
    }
    for (field, value) in [
        (proto::USERNAME, args.username),
        (proto::URL, args.url),
        (proto::NOTES, args.notes),
    ] {
        if let Some(value) = value.filter(|v| !v.is_empty()) {
            fields.insert(field.to_owned(), value);
        }
    }

    let req = Request::Add {
        fields,
        tags,
        sync: args.sync,
    };
    println!("{}", save(store, &req, args.sync)?);
    Ok(())
}

fn edit(store: &Store, args: EditArgs) -> Result<(), String> {
    let mut tags: BTreeMap<String, bool> = parse_tags(&args.tags)?.into_iter().map(|t| (t, true)).collect();
    tags.extend(parse_tags(&args.untag)?.into_iter().map(|t| (t, false)));
    if args.favorite || args.no_favorite {
        tags.insert(FAVORITE_TAG.to_owned(), args.favorite);
    }
    let mut fields = BTreeMap::new();
    if let Some(name) = &args.name {
        if name.trim().is_empty() {
            return Err(tr!(
                "the item name cannot be empty",
                "название записи не может быть пустым"
            ));
        }
        fields.insert(proto::NAME.to_owned(), name.trim().to_owned());
    }
    for (field, value) in [
        (proto::USERNAME, args.username),
        (proto::URL, args.url),
        (proto::NOTES, args.notes),
    ] {
        if let Some(value) = value {
            fields.insert(field.to_owned(), value);
        }
    }
    if args.no_totp {
        fields.insert(proto::TOTP.to_owned(), String::new());
    }
    if args.pin_totp || args.no_pin_totp {
        let mode = if args.pin_totp { proto::PIN_TOTP } else { "" };
        fields.insert(proto::PASSWORD_MODE.to_owned(), mode.to_owned());
    }
    if fields.is_empty() && tags.is_empty() && !(args.password || args.generator.generate || args.totp) {
        return Err(tr!(
            "nothing to change is specified: inkvault edit --help",
            "не указано, что изменить: inkvault edit --help"
        ));
    }

    let entry = find(store, args.entry)?;
    let value = |field| fields.get(field).map_or(entry.field(field), String::as_str);
    let pin = value(proto::PASSWORD_MODE) == proto::PIN_TOTP;
    if pin && !args.totp && value(proto::TOTP).is_empty() {
        return Err(tr!(
            "a PIN + code password requires a TOTP secret, specify --totp",
            "для пароля вида PIN + код нужен секрет TOTP, укажите --totp"
        ));
    }
    let mut passwords = Passwords::new(args.password_stdin);
    if args.generator.generate {
        fields.insert(
            proto::PASSWORD.to_owned(),
            args.generator.password()?.as_str().to_owned(),
        );
    }
    if args.password {
        let password = passwords.confirmed(&password_label(pin))?;
        fields.insert(proto::PASSWORD.to_owned(), password.as_str().to_owned());
    }
    if args.totp {
        fields.insert(proto::TOTP.to_owned(), passwords.totp()?);
    }

    let req = Request::Edit {
        id: entry.id,
        fields,
        tags,
        sync: args.sync,
    };
    save(store, &req, args.sync).map(|_| ())
}

fn remove(store: &Store, entry: EntryQuery, force: bool, sync: bool) -> Result<(), String> {
    let entry = find(store, entry)?;
    if !force {
        // как пароли: вопрос задается в терминале, даже если stdin перенаправлен
        let mut tty = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/tty")
            .map_err(|_| {
                tr!(
                    "no terminal for confirmation, use --force",
                    "нет терминала для подтверждения, используйте --force"
                )
            })?;
        let username = entry.field(proto::USERNAME);
        let login = if username.is_empty() {
            String::new()
        } else {
            format!(" ({username})")
        };
        let question = tr!(
            "Move the item {}{login} to the trash? [y/N] ",
            "Переместить в корзину запись {}{login}? [y/N] ",
            entry.field(proto::NAME)
        );
        write!(tty, "{question}").map_err(|e| e.to_string())?;
        let mut answer = String::new();
        BufReader::new(&tty).read_line(&mut answer).map_err(|e| e.to_string())?;
        if !matches!(answer.trim().to_lowercase().as_str(), "y" | "yes" | "д" | "да") {
            return Err(tr!("deletion canceled", "удаление отменено"));
        }
    }
    save(store, &Request::Delete { id: entry.id, sync }, sync).map(|_| ())
}

/// Изменение записи. Без --sync агент сохраняет его на устройстве и отправляет, когда есть связь.
fn save(store: &Store, req: &Request, sync: bool) -> Result<String, String> {
    if sync {
        wait_connection(store)?;
    }
    let Reply::Saved(saved) = request(store, req)? else {
        return Err(unexpected_reply());
    };
    if saved.pending {
        warn_pending();
    }
    Ok(saved.id)
}

fn warn_pending() {
    eprintln!(
        "inkvault: {}",
        tr!(
            "the changes are saved on this device but not yet sent to the server, details: inkvault status",
            "изменения сохранены на этом устройстве, но еще не отправлены на сервер, подробности: inkvault status"
        )
    );
}

fn export(store: &Store, master: bool, password_stdin: bool) -> Result<(), String> {
    // зашифрованный файл в терминале бесполезен, а вопрос о пароле смешался бы с ним
    if std::io::stdout().is_terminal() {
        return Err(tr!(
            "the export file is written to stdout: redirect it, for example inkvault export > backup.ivx",
            "файл экспорта выводится в stdout: перенаправьте его, например inkvault export > backup.ivx"
        ));
    }
    ensure_unlocked(store)?;
    let mut passwords = Passwords::new(password_stdin);
    let password = if master {
        passwords.read(&tr!("Master password: ", "Мастер-пароль: "))?
    } else {
        passwords.confirmed(&tr!("File password", "Пароль файла"))?
    };
    let Reply::File(file) = request(store, &Request::Export { password, master })? else {
        return Err(unexpected_reply());
    };
    let mut out = std::io::stdout().lock();
    writeln!(out, "{file}")
        .and_then(|()| out.flush())
        .map_err(|e| format!("stdout: {e}"))
}

fn import(store: &Store, path: Option<String>, password_stdin: bool, sync: bool) -> Result<(), String> {
    let path = path.filter(|p| p != "-");
    if path.is_none() && password_stdin {
        return Err(tr!(
            "the file is read from stdin and the file password is entered in the terminal; \
             for --password-stdin specify the file path",
            "файл читается из stdin, пароль файла вводится в терминале; для --password-stdin укажите путь к файлу"
        ));
    }
    // на байт больше лимита: так файл сверх лимита отличается от файла ровно по лимиту
    let limit = proto::MAX_FILE as u64 + 1;
    let mut data = Vec::new();
    match &path {
        Some(path) => std::fs::File::open(path)
            .and_then(|f| f.take(limit).read_to_end(&mut data))
            .map_err(|e| format!("{path}: {e}"))?,
        None => std::io::stdin()
            .lock()
            .take(limit)
            .read_to_end(&mut data)
            .map_err(|e| format!("stdin: {e}"))?,
    };
    if data.is_empty() {
        return Err(tr!("the export file is empty", "файл экспорта пуст"));
    }
    if data.len() > proto::MAX_FILE {
        return Err(tr!(
            "the file is larger than {} MiB, it is not an InkVault export file",
            "файл больше {} МиБ, это не файл экспорта InkVault",
            proto::MAX_FILE / 1024 / 1024
        ));
    }
    let file = String::from_utf8(data).map_err(|_| {
        tr!(
            "the file is not UTF-8, it is not an InkVault export file",
            "файл не в UTF-8, это не файл экспорта InkVault"
        )
    })?;

    ensure_unlocked(store)?;
    let password = Passwords::new(password_stdin).read(&tr!("File password: ", "Пароль файла: "))?;
    if sync {
        wait_connection(store)?;
    }
    let Reply::Imported(imported) = request(store, &Request::Import { file, password, sync })? else {
        return Err(unexpected_reply());
    };
    let stats = imported.stats;
    let skipped = match stats.skipped {
        0 => String::new(),
        n => tr!(", skipped: {n}", ", пропущено: {n}"),
    };
    println!(
        "{}",
        tr!(
            "import: new {}, updated {}, unchanged {}{skipped}",
            "импорт: новых {}, обновлено {}, без изменений {}{skipped}",
            stats.added,
            stats.updated,
            stats.unchanged
        )
    );
    if imported.pending {
        warn_pending();
    }
    Ok(())
}

/// login и logout удаляют снимок, а с ним и изменения, которые еще не отправлены на сервер.
fn check_unsent(store: &Store, force: bool) -> Result<(), String> {
    match store.unsent() {
        n if n > 0 && !force => Err(tr!(
            "the device has unsent item changes: {n}. Send them with inkvault sync or delete them with --force",
            "на устройстве есть неотправленные изменения записей: {n}. \
             Отправьте их командой inkvault sync или удалите ключом --force"
        )),
        _ => Ok(()),
    }
}

/// Теги из аргументов. Пробелы и / по краям отбрасываются, как в web-клиенте.
fn parse_tags(tags: &[String]) -> Result<Vec<String>, String> {
    tags.iter()
        .map(|tag| tag.trim().trim_matches('/'))
        .filter(|tag| !tag.is_empty())
        .map(|tag| validate_tag(tag).map(|()| tag.to_owned()).map_err(|e| e.to_string()))
        .collect()
}

fn find(store: &Store, entry: EntryQuery) -> Result<Entry, String> {
    let EntryQuery { query, user } = entry;
    match call(store, &Request::Find { query, user })? {
        Reply::Entry(entry) => Ok(entry),
        _ => Err(unexpected_reply()),
    }
}

/// Пароли из терминала или, с --password-stdin, построчно из stdin.
struct Passwords {
    stdin: Option<std::io::StdinLock<'static>>,
}

impl Passwords {
    fn new(from_stdin: bool) -> Self {
        Self {
            stdin: from_stdin.then(|| std::io::stdin().lock()),
        }
    }

    fn read(&mut self, prompt: &str) -> Result<Zeroizing<String>, String> {
        let value = self.line(prompt)?;
        if value.is_empty() {
            return Err(empty_password());
        }
        Ok(value)
    }

    /// Пароль записи. В терминале вводится дважды: при вводе вслепую опечатку не видно.
    fn confirmed(&mut self, what: &str) -> Result<Zeroizing<String>, String> {
        let password = self.read(&format!("{what}: "))?;
        if self.stdin.is_none() && *self.read(&tr!("{what} again: ", "{what} еще раз: "))? != *password {
            return Err(tr!("the passwords do not match", "пароли не совпадают"));
        }
        Ok(password)
    }

    fn totp(&mut self) -> Result<String, String> {
        let secret = self.line(&tr!("TOTP secret: ", "Секрет TOTP: "))?;
        Totp::parse(&secret).map_err(|e| e.to_string())?;
        Ok(secret.trim().to_owned())
    }

    /// Строка без проверки на пустоту: для секрета TOTP причину ошибки точнее назовет разбор секрета.
    fn line(&mut self, prompt: &str) -> Result<Zeroizing<String>, String> {
        let mut value = Zeroizing::new(String::new());
        match &mut self.stdin {
            Some(stdin) => {
                stdin.read_line(&mut value).map_err(|e| format!("stdin: {e}"))?;
                let len = value.trim_end_matches(['\n', '\r']).len();
                value.truncate(len);
            }
            None => {
                *value = rpassword::prompt_password(prompt).map_err(|e| {
                    tr!(
                        "the password was not read from the terminal ({e}), use --password-stdin",
                        "пароль не прочитан из терминала ({e}), используйте --password-stdin"
                    )
                })?;
            }
        }
        Ok(value)
    }
}

fn require_login(store: &Store) -> Result<(), String> {
    match store.config()? {
        Some(_) => Ok(()),
        None => Err(no_login()),
    }
}

fn agent_running(store: &Store) -> bool {
    UnixStream::connect(&store.socket).is_ok()
}

/// Запускает агент и ждет его ответа о разблокировке. Пароли передаются через stdin, а не через
/// аргументы или окружение: их не видно в списке процессов.
fn start_agent(start: &Start) -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let mut child = std::process::Command::new(exe)
        .arg("agent")
        .current_dir("/")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        // своя группа процессов: Ctrl+C в терминале команды не завершает агент
        .process_group(0)
        .spawn()
        .map_err(|e| tr!("the agent did not start: {e}", "агент не запущен: {e}"))?;
    let mut line = Zeroizing::new(serde_json::to_string(start).expect("параметры запуска в JSON"));
    line.push('\n');
    let sent = child.stdin.take().expect("stdin агента").write_all(line.as_bytes());
    drop(line);
    let mut answer = String::new();
    if sent.is_ok() {
        let stdout = child.stdout.take().expect("stdout агента");
        let _ = BufReader::new(stdout).read_line(&mut answer);
    }
    match serde_json::from_str::<Reply>(&answer) {
        Ok(Reply::Done) => Ok(()),
        Ok(Reply::Error(err)) => {
            let _ = child.wait();
            Err(err)
        }
        _ => {
            let _ = child.wait();
            Err(no_agent_reply())
        }
    }
}

/// Блокирует хранилище и ждет, пока агент сохранит кэш и удалит сокет.
fn stop_agent(store: &Store) -> Result<(), String> {
    if !agent_running(store) {
        return Ok(());
    }
    request(store, &Request::Lock)?;
    let deadline = Instant::now() + Duration::from_secs(10);
    while store.socket.exists() {
        if Instant::now() > deadline {
            return Err(tr!("the agent did not exit within 10 s", "агент не завершился за 10 с"));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    Ok(())
}

fn request(store: &Store, request: &Request) -> Result<Reply, String> {
    let mut stream = UnixStream::connect(&store.socket)
        .map_err(|e| tr!("the agent is unavailable: {e}", "агент недоступен: {e}"))?;
    let mut line = Zeroizing::new(serde_json::to_string(request).expect("запрос в JSON"));
    line.push('\n');
    // агент обрезает более длинную строку, и запрос не разобрался бы
    if line.len() > proto::MAX_LINE {
        return Err(tr!(
            "the request to the agent is larger than {} MiB",
            "запрос к агенту больше {} МиБ",
            proto::MAX_LINE / 1024 / 1024
        ));
    }
    stream.write_all(line.as_bytes()).map_err(|e| e.to_string())?;
    let mut answer = Zeroizing::new(String::new());
    BufReader::new(stream.take(proto::MAX_LINE as u64))
        .read_line(&mut answer)
        .map_err(|e| e.to_string())?;
    match serde_json::from_str::<Reply>(&answer) {
        Ok(Reply::Error(err)) => Err(err),
        Ok(reply) => Ok(reply),
        Err(_) => Err(no_agent_reply()),
    }
}

/// Если хранилище заблокировано и есть терминал, спрашивает мастер-пароль и запускает агент.
fn ensure_unlocked(store: &Store) -> Result<(), String> {
    if agent_running(store) {
        return Ok(());
    }
    require_login(store)?;
    let master_password = rpassword::prompt_password(tr!("Master password: ", "Мастер-пароль: ")).map_err(|_| {
        tr!(
            "the vault is locked: run inkvault unlock",
            "хранилище заблокировано: выполните inkvault unlock"
        )
    })?;
    if master_password.is_empty() {
        return Err(empty_password());
    }
    start_agent(&Start {
        master_password: Zeroizing::new(master_password),
        timeout_min: 15,
        login: None,
    })
}

fn call(store: &Store, req: &Request) -> Result<Reply, String> {
    ensure_unlocked(store)?;
    request(store, req)
}

fn print_list(entries: &[Entry], json: bool) {
    if json {
        // пароли и секреты в список не попадают
        let safe: Vec<serde_json::Value> = entries
            .iter()
            .map(|e| {
                serde_json::json!({
                    "id": e.id,
                    "name": e.field(proto::NAME),
                    "username": e.field(proto::USERNAME),
                    "url": e.field(proto::URL),
                    "tags": e.tags,
                })
            })
            .collect();
        println!("{}", serde_json::Value::Array(safe));
        return;
    }
    let rows: Vec<[&str; 3]> = entries
        .iter()
        .map(|e| [e.field(proto::NAME), e.field(proto::USERNAME), e.field(proto::URL)])
        .collect();
    // в терминале колонки выравниваются, в pipe - разделены табуляцией
    let terminal = std::io::stdout().is_terminal();
    let width = |i: usize| rows.iter().map(|r| r[i].chars().count()).max().unwrap_or(0);
    let widths = [width(0), width(1)];
    let mut out = std::io::stdout().lock();
    for row in rows {
        let line = if terminal {
            format!(
                "{:w0$}  {:w1$}  {}",
                row[0],
                row[1],
                row[2],
                w0 = widths[0],
                w1 = widths[1]
            )
        } else {
            row.join("\t")
        };
        let _ = writeln!(out, "{}", line.trim_end());
    }
}

fn status(store: &Store, json: bool) -> Result<(), String> {
    if !agent_running(store) {
        // JID хранится в настройках открыто: учетную запись видно и без мастер-пароля
        let jid = store.config()?.map(|c| c.jid);
        if json {
            println!("{}", serde_json::json!({ "unlocked": false, "jid": jid }));
            return Ok(());
        }
        match jid {
            Some(jid) => {
                println!("{}", tr!("Account: {jid}", "Учетная запись: {jid}"));
                println!("{}", tr!("the vault is locked", "хранилище заблокировано"));
            }
            None => println!(
                "{}",
                tr!("not signed in on this device", "нет входа на этом устройстве")
            ),
        }
        return Ok(());
    }
    let Reply::Status(status) = request(store, &Request::Status)? else {
        return Err(unexpected_reply());
    };
    if json {
        let mut value = serde_json::to_value(&status).expect("состояние в JSON");
        value["unlocked"] = serde_json::Value::Bool(true);
        println!("{value}");
        return Ok(());
    }
    let connection = match &status.connection {
        Connection::Connecting => tr!("connecting", "подключение"),
        Connection::Online => tr!("online", "в сети"),
        Connection::Offline(None) => tr!("offline", "нет соединения"),
        Connection::Offline(Some(err)) => tr!("offline: {err}", "нет соединения: {err}"),
        Connection::Conflict => tr!(
            "sync stopped: the server has a different account",
            "синхронизация остановлена: на сервере другая учетная запись"
        ),
        Connection::Failed(err) => err.clone(),
    };
    let (jid, records, pending, max_items) = (&status.jid, status.records, status.pending, status.max_items);
    println!("{}", tr!("Account: {jid}", "Учетная запись: {jid}"));
    println!("{}", tr!("Connection: {connection}", "Соединение: {connection}"));
    println!(
        "{}",
        tr!(
            "Items: {records}, unsent changes: {pending}",
            "Записей: {records}, неотправленных изменений: {pending}"
        )
    );
    println!(
        "{}",
        tr!(
            "Node limit including the trash: {max_items}",
            "Лимит узла: {max_items} записей вместе с корзиной"
        )
    );
    let synced = match status.synced_ago_s {
        Some(s) => tr!("Last sync: {} ago", "Синхронизация: {} назад", duration(s)),
        None => tr!("Last sync: never", "Синхронизация: еще не было"),
    };
    println!("{synced}");
    let lock = match status.lock_in_s {
        Some(s) => tr!("Lock: in {}", "Блокировка: через {}", duration(s)),
        None => tr!("Lock: with inkvault lock", "Блокировка: командой inkvault lock"),
    };
    println!("{lock}");
    if !status.notices.is_empty() {
        println!("{}", tr!("Notices:", "Уведомления:"));
        for notice in &status.notices {
            println!("  {notice}");
        }
    }
    Ok(())
}

fn duration(seconds: u64) -> String {
    let (hours, minutes) = (seconds / 3600, seconds % 3600 / 60);
    match seconds {
        0..60 => tr!("{seconds} s", "{seconds} с"),
        60..3600 => tr!("{minutes} min", "{minutes} мин"),
        _ => tr!("{hours} h {minutes} min", "{hours} ч {minutes} мин"),
    }
}

fn unexpected_reply() -> String {
    tr!("unexpected agent reply", "неожиданный ответ агента")
}

fn no_agent_reply() -> String {
    tr!("the agent exited without a reply", "агент завершился без ответа")
}

fn empty_password() -> String {
    tr!("the password cannot be empty", "пароль не может быть пустым")
}

/// Текст для команд CLI и для агента.
fn no_login() -> String {
    tr!(
        "not signed in on this device: run inkvault login <JID>",
        "нет входа на этом устройстве: выполните inkvault login <JID>"
    )
}

/// Подпись пароля записи; для пароля вида PIN + код - PIN.
fn password_label(pin: bool) -> String {
    if pin {
        "PIN".to_owned()
    } else {
        tr!("Password", "Пароль")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn language_follows_posix_order() {
        let env = |pairs: &'static [(&'static str, &'static str)]| {
            move |name: &str| pairs.iter().find(|(n, _)| *n == name).map(|(_, v)| v.to_string())
        };
        assert_eq!(lang_from(env(&[])), Lang::En);
        assert_eq!(lang_from(env(&[("LANG", "ru_RU.UTF-8")])), Lang::Ru);
        assert_eq!(
            lang_from(env(&[("LANG", "ru_RU.UTF-8"), ("LC_MESSAGES", "C")])),
            Lang::En
        );
        assert_eq!(
            lang_from(env(&[("LC_ALL", "ru"), ("LC_MESSAGES", "en_US.UTF-8")])),
            Lang::Ru
        );
        // пустая переменная пропускается
        assert_eq!(lang_from(env(&[("LC_ALL", ""), ("LANG", "ru_RU.UTF-8")])), Lang::Ru);
    }

    #[test]
    fn help_is_complete_in_both_languages() {
        for lang in [Lang::En, Lang::Ru] {
            let cmd = command(lang);
            cmd.clone().debug_assert();
            for sub in cmd.get_subcommands().filter(|s| !s.is_hide_set()) {
                assert!(sub.get_about().is_some(), "{lang:?} {}", sub.get_name());
                for arg in sub.get_arguments() {
                    assert!(arg.get_help().is_some(), "{lang:?} {} {}", sub.get_name(), arg.get_id());
                }
            }
        }
        let about = |lang| {
            command(lang)
                .find_subcommand("login")
                .and_then(|c| c.get_about())
                .map(|a| a.to_string())
        };
        assert_ne!(about(Lang::En), about(Lang::Ru));
    }
}
