//! Терминальный клиент InkVault для команд и скриптов. Ключи хранилища держит агент, который
//! запускает `inkvault unlock`; остальные команды получают записи у него через unix-сокет.

#[cfg(not(unix))]
compile_error!("CLI работает в Linux и macOS: агенту нужен unix-сокет");

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

use clap::{Args, Parser, Subcommand};
use inkvault_core::otp::Totp;
use inkvault_core::password::{self, PasswordOptions};
use inkvault_core::record::{FAVORITE_TAG, validate_tag};
use zeroize::Zeroizing;

use proto::{Connection, Entry, Login, Reply, Request, Start};
use store::Store;

#[derive(Parser)]
#[command(
    name = "inkvault",
    version,
    about = "Менеджер паролей InkVault: команды для терминала и скриптов",
    after_help = concat!("Автор: ", env!("CARGO_PKG_AUTHORS"), ", XMPP: tzx1z@inkov.dev, https://inkov.dev")
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Вход на этом устройстве. Хранилище уже должно быть создано в web- или Android-клиенте.
    Login {
        /// JID вида имя@сервер
        jid: String,
        /// Адрес сервера: host[:port] (STARTTLS) или tcp://127.0.0.1:port (без TLS, только loopback).
        /// По умолчанию адрес берется из SRV домена JID.
        #[arg(long)]
        server: Option<String>,
        #[command(flatten)]
        unlock: UnlockArgs,
        /// Войти, даже если на устройстве есть неотправленные изменения записей: они будут удалены
        #[arg(long)]
        force: bool,
    },
    /// Разблокировать хранилище: агент держит ключи в памяти до блокировки
    Unlock(UnlockArgs),
    /// Заблокировать хранилище
    Lock,
    /// Заблокировать и удалить данные этого устройства: вход, пароль XMPP и кэш записей
    Logout {
        /// Удалить, даже если на устройстве есть неотправленные изменения записей
        #[arg(long)]
        force: bool,
    },
    /// Состояние агента и соединения
    Status {
        #[arg(long)]
        json: bool,
    },
    /// Список записей без паролей
    Ls {
        /// Часть названия, адреса, логина или тега
        query: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Значение поля записи, по умолчанию пароль. Для пароля вида PIN + код - PIN с текущим кодом
    Get {
        #[command(flatten)]
        entry: EntryQuery,
        /// Поле: name, url, username, password, totp, notes
        #[arg(short, long)]
        field: Option<String>,
        /// Вся запись в JSON
        #[arg(long, conflicts_with = "field")]
        json: bool,
    },
    /// Текущий код TOTP записи
    Otp(EntryQuery),
    /// Добавить запись и вывести ее id
    Add(AddArgs),
    /// Изменить запись
    Edit(EditArgs),
    /// Переместить запись в корзину
    Rm {
        #[command(flatten)]
        entry: EntryQuery,
        /// Без подтверждения
        #[arg(long)]
        force: bool,
        #[arg(long, help = SYNC_HELP)]
        sync: bool,
    },
    /// Зашифрованный файл экспорта в stdout: все записи, включая корзину и историю паролей
    Export {
        /// Зашифровать мастер-паролем. По умолчанию файл шифруется отдельным паролем: такой файл
        /// откроется и при потере мастер-пароля
        #[arg(long)]
        master: bool,
        /// Читать пароль из stdin
        #[arg(long)]
        password_stdin: bool,
    },
    /// Импорт файла экспорта: записи сливаются с хранилищем, более новые правки не затираются
    Import {
        /// Файл экспорта, без него или "-" - stdin
        file: Option<String>,
        /// Читать пароль файла из stdin, только вместе с FILE
        #[arg(long)]
        password_stdin: bool,
        #[arg(long, help = SYNC_HELP)]
        sync: bool,
    },
    /// Загрузить записи с сервера заново
    Sync,
    /// Лимит записей узла хранилища на сервере, с N - изменить его. Корзина входит в лимит
    MaxItems {
        /// Новый лимит: не меньше числа записей и не больше pep_max_items на сервере. Нужна связь с сервером
        value: Option<u32>,
    },
    /// Сменить мастер-пароль. Нужна связь с сервером, записи не перешифровываются
    Passwd {
        /// Читать пароли из stdin по одному на строку: текущий, затем новый
        #[arg(long)]
        password_stdin: bool,
    },
    /// Сгенерировать пароль, хранилище не нужно
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
        /// Без похожих символов: I, l, 1, O, 0, o, |
        #[arg(long)]
        avoid_ambiguous: bool,
    },
    #[command(hide = true)]
    Agent,
}

#[derive(Args)]
struct UnlockArgs {
    /// Блокировка после стольких минут без запросов, 0 - только командой lock
    #[arg(long, default_value_t = 15)]
    timeout: u64,
    /// Читать пароли из stdin по одному на строку; для login - пароль XMPP, затем мастер-пароль
    #[arg(long)]
    password_stdin: bool,
}

const SYNC_HELP: &str = "Сразу отправить изменение на сервер и дождаться ответа. \
    Если отправить не удалось, команда завершается с ошибкой";

/// Выбор записи, одинаковый для get, otp, edit и rm.
#[derive(Args)]
struct EntryQuery {
    /// id, название или часть названия либо адреса
    query: String,
    /// Логин записи, если под запрос подходит несколько
    #[arg(short, long)]
    user: Option<String>,
}

#[derive(Args)]
struct GenerateArgs {
    /// Сгенерировать пароль. Другой набор символов - через inkvault gen и --password-stdin
    #[arg(short, long)]
    generate: bool,
    /// Длина сгенерированного пароля, по умолчанию 20
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
    /// Название записи
    name: String,
    /// Логин
    #[arg(long)]
    username: Option<String>,
    /// Адрес сайта
    #[arg(long)]
    url: Option<String>,
    /// Заметка
    #[arg(long)]
    notes: Option<String>,
    /// Поставить тег, можно указать несколько раз. Вложенный тег - через /: работа/серверы
    #[arg(short = 't', long = "tag", value_name = "TAG")]
    tags: Vec<String>,
    /// Добавить в избранное
    #[arg(long)]
    favorite: bool,
    #[command(flatten)]
    generator: GenerateArgs,
    /// Ввести секрет TOTP: base32 или ссылку otpauth://totp/...
    #[arg(long)]
    totp: bool,
    /// Пароль вида PIN + код: пароль записи - это PIN, get выдает его вместе с текущим кодом. Включает --totp
    #[arg(long, conflicts_with = "generate")]
    pin_totp: bool,
    /// Читать из stdin по одному на строку: пароль (без --generate), затем секрет TOTP (с --totp)
    #[arg(long)]
    password_stdin: bool,
    #[arg(long, help = SYNC_HELP)]
    sync: bool,
}

#[derive(Args)]
struct EditArgs {
    #[command(flatten)]
    entry: EntryQuery,
    /// Название
    #[arg(long)]
    name: Option<String>,
    /// Логин, пустая строка удаляет
    #[arg(long)]
    username: Option<String>,
    /// Адрес сайта, пустая строка удаляет
    #[arg(long)]
    url: Option<String>,
    /// Заметка, пустая строка удаляет
    #[arg(long)]
    notes: Option<String>,
    /// Поставить тег, можно указать несколько раз. Вложенный тег - через /: работа/серверы
    #[arg(short = 't', long = "tag", value_name = "TAG")]
    tags: Vec<String>,
    /// Снять тег, можно указать несколько раз
    #[arg(long, value_name = "TAG")]
    untag: Vec<String>,
    /// Добавить в избранное
    #[arg(long, conflicts_with = "no_favorite")]
    favorite: bool,
    /// Убрать из избранного
    #[arg(long)]
    no_favorite: bool,
    /// Ввести пароль
    #[arg(short, long, conflicts_with = "generate")]
    password: bool,
    #[command(flatten)]
    generator: GenerateArgs,
    /// Ввести секрет TOTP: base32 или ссылку otpauth://totp/...
    #[arg(long, conflicts_with = "no_totp")]
    totp: bool,
    /// Удалить секрет TOTP
    #[arg(long)]
    no_totp: bool,
    /// Пароль вида PIN + код: пароль записи - это PIN, get выдает его вместе с текущим кодом
    #[arg(long, conflicts_with = "no_pin_totp")]
    pin_totp: bool,
    /// Обычный пароль вместо PIN + код
    #[arg(long)]
    no_pin_totp: bool,
    /// Читать из stdin по одному на строку: пароль (с --password), затем секрет TOTP (с --totp)
    #[arg(long)]
    password_stdin: bool,
    #[arg(long, help = SYNC_HELP)]
    sync: bool,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
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
            let xmpp_password = passwords.read("Пароль XMPP: ")?;
            let master_password = passwords.read("Мастер-пароль: ")?;
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
            let master_password = Passwords::new(unlock.password_stdin).read("Мастер-пароль: ")?;
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
                return Err("неожиданный ответ агента".to_owned());
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
                return Err(format!(
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
                return Err("неожиданный ответ агента".to_owned());
            };
            println!("{}", status.max_items);
            Ok(())
        }
        Command::Passwd { password_stdin } => {
            require_login(&store)?;
            let mut passwords = Passwords::new(password_stdin);
            let current = passwords.read("Текущий мастер-пароль: ")?;
            let new = passwords.read("Новый мастер-пароль: ")?;
            // в терминале пароль вводится вслепую, опечатка в нем закрыла бы доступ к хранилищу
            if !password_stdin && *passwords.read("Новый мастер-пароль еще раз: ")? != *new {
                return Err("новые пароли не совпадают".to_owned());
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
            println!("мастер-пароль изменен");
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
            return Err("неожиданный ответ агента".to_owned());
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
        return Err(format!("в записи {} нет секрета TOTP", entry.field(proto::NAME)));
    }
    let totp = Totp::parse(secret).map_err(|e| e.to_string())?;
    Ok(totp.code(now_ms()))
}

fn add(store: &Store, args: AddArgs) -> Result<(), String> {
    let name = args.name.trim();
    if name.is_empty() {
        return Err("название записи не может быть пустым".to_owned());
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
        passwords.confirmed(if args.pin_totp { "PIN" } else { "Пароль" })?
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
            return Err("название записи не может быть пустым".to_owned());
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
        return Err("не указано, что изменить: inkvault edit --help".to_owned());
    }

    let entry = find(store, args.entry)?;
    let value = |field| fields.get(field).map_or(entry.field(field), String::as_str);
    let pin = value(proto::PASSWORD_MODE) == proto::PIN_TOTP;
    if pin && !args.totp && value(proto::TOTP).is_empty() {
        return Err("для пароля вида PIN + код нужен секрет TOTP, укажите --totp".to_owned());
    }
    let mut passwords = Passwords::new(args.password_stdin);
    if args.generator.generate {
        fields.insert(
            proto::PASSWORD.to_owned(),
            args.generator.password()?.as_str().to_owned(),
        );
    }
    if args.password {
        let password = passwords.confirmed(if pin { "PIN" } else { "Пароль" })?;
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
            .map_err(|_| "нет терминала для подтверждения, используйте --force".to_owned())?;
        let username = entry.field(proto::USERNAME);
        let login = if username.is_empty() {
            String::new()
        } else {
            format!(" ({username})")
        };
        write!(
            tty,
            "Переместить в корзину запись {}{login}? [y/N] ",
            entry.field(proto::NAME)
        )
        .map_err(|e| e.to_string())?;
        let mut answer = String::new();
        BufReader::new(&tty).read_line(&mut answer).map_err(|e| e.to_string())?;
        if !matches!(answer.trim().to_lowercase().as_str(), "y" | "yes" | "д" | "да") {
            return Err("удаление отменено".to_owned());
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
        return Err("неожиданный ответ агента".to_owned());
    };
    if saved.pending {
        warn_pending();
    }
    Ok(saved.id)
}

fn warn_pending() {
    eprintln!(
        "inkvault: изменения сохранены на этом устройстве, но еще не отправлены на сервер, \
         подробности: inkvault status"
    );
}

fn export(store: &Store, master: bool, password_stdin: bool) -> Result<(), String> {
    // зашифрованный файл в терминале бесполезен, а вопрос о пароле смешался бы с ним
    if std::io::stdout().is_terminal() {
        return Err(
            "файл экспорта выводится в stdout: перенаправьте его, например inkvault export > backup.ivx".to_owned(),
        );
    }
    ensure_unlocked(store)?;
    let mut passwords = Passwords::new(password_stdin);
    let password = if master {
        passwords.read("Мастер-пароль: ")?
    } else {
        passwords.confirmed("Пароль файла")?
    };
    let Reply::File(file) = request(store, &Request::Export { password, master })? else {
        return Err("неожиданный ответ агента".to_owned());
    };
    let mut out = std::io::stdout().lock();
    writeln!(out, "{file}")
        .and_then(|()| out.flush())
        .map_err(|e| format!("stdout: {e}"))
}

fn import(store: &Store, path: Option<String>, password_stdin: bool, sync: bool) -> Result<(), String> {
    let path = path.filter(|p| p != "-");
    if path.is_none() && password_stdin {
        return Err(
            "файл читается из stdin, пароль файла вводится в терминале; для --password-stdin укажите путь к файлу"
                .to_owned(),
        );
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
        return Err("файл экспорта пуст".to_owned());
    }
    if data.len() > proto::MAX_FILE {
        return Err(format!(
            "файл больше {} МиБ, это не файл экспорта InkVault",
            proto::MAX_FILE / 1024 / 1024
        ));
    }
    let file = String::from_utf8(data).map_err(|_| "файл не в UTF-8, это не файл экспорта InkVault".to_owned())?;

    ensure_unlocked(store)?;
    let password = Passwords::new(password_stdin).read("Пароль файла: ")?;
    if sync {
        wait_connection(store)?;
    }
    let Reply::Imported(imported) = request(store, &Request::Import { file, password, sync })? else {
        return Err("неожиданный ответ агента".to_owned());
    };
    let stats = imported.stats;
    let skipped = match stats.skipped {
        0 => String::new(),
        n => format!(", пропущено: {n}"),
    };
    println!(
        "импорт: новых {}, обновлено {}, без изменений {}{skipped}",
        stats.added, stats.updated, stats.unchanged
    );
    if imported.pending {
        warn_pending();
    }
    Ok(())
}

/// login и logout удаляют снимок, а с ним и изменения, которые еще не отправлены на сервер.
fn check_unsent(store: &Store, force: bool) -> Result<(), String> {
    match store.unsent() {
        n if n > 0 && !force => Err(format!(
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
        _ => Err("неожиданный ответ агента".to_owned()),
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
            return Err("пароль не может быть пустым".to_owned());
        }
        Ok(value)
    }

    /// Пароль записи. В терминале вводится дважды: при вводе вслепую опечатку не видно.
    fn confirmed(&mut self, what: &str) -> Result<Zeroizing<String>, String> {
        let password = self.read(&format!("{what}: "))?;
        if self.stdin.is_none() && *self.read(&format!("{what} еще раз: "))? != *password {
            return Err("пароли не совпадают".to_owned());
        }
        Ok(password)
    }

    fn totp(&mut self) -> Result<String, String> {
        let secret = self.line("Секрет TOTP: ")?;
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
                *value = rpassword::prompt_password(prompt)
                    .map_err(|e| format!("пароль не прочитан из терминала ({e}), используйте --password-stdin"))?;
            }
        }
        Ok(value)
    }
}

fn require_login(store: &Store) -> Result<(), String> {
    match store.config()? {
        Some(_) => Ok(()),
        None => Err("нет входа на этом устройстве: выполните inkvault login <JID>".to_owned()),
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
        .map_err(|e| format!("агент не запущен: {e}"))?;
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
            Err("агент завершился без ответа".to_owned())
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
            return Err("агент не завершился за 10 с".to_owned());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    Ok(())
}

fn request(store: &Store, request: &Request) -> Result<Reply, String> {
    let mut stream = UnixStream::connect(&store.socket).map_err(|e| format!("агент недоступен: {e}"))?;
    let mut line = Zeroizing::new(serde_json::to_string(request).expect("запрос в JSON"));
    line.push('\n');
    // агент обрезает более длинную строку, и запрос не разобрался бы
    if line.len() > proto::MAX_LINE {
        return Err(format!("запрос к агенту больше {} МиБ", proto::MAX_LINE / 1024 / 1024));
    }
    stream.write_all(line.as_bytes()).map_err(|e| e.to_string())?;
    let mut answer = Zeroizing::new(String::new());
    BufReader::new(stream.take(proto::MAX_LINE as u64))
        .read_line(&mut answer)
        .map_err(|e| e.to_string())?;
    match serde_json::from_str::<Reply>(&answer) {
        Ok(Reply::Error(err)) => Err(err),
        Ok(reply) => Ok(reply),
        Err(_) => Err("агент завершился без ответа".to_owned()),
    }
}

/// Если хранилище заблокировано и есть терминал, спрашивает мастер-пароль и запускает агент.
fn ensure_unlocked(store: &Store) -> Result<(), String> {
    if agent_running(store) {
        return Ok(());
    }
    require_login(store)?;
    let master_password = rpassword::prompt_password("Мастер-пароль: ")
        .map_err(|_| "хранилище заблокировано: выполните inkvault unlock".to_owned())?;
    if master_password.is_empty() {
        return Err("пароль не может быть пустым".to_owned());
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
        if json {
            println!("{}", serde_json::json!({ "unlocked": false }));
        } else {
            println!("хранилище заблокировано");
        }
        return Ok(());
    }
    let Reply::Status(status) = request(store, &Request::Status)? else {
        return Err("неожиданный ответ агента".to_owned());
    };
    if json {
        let mut value = serde_json::to_value(&status).expect("состояние в JSON");
        value["unlocked"] = serde_json::Value::Bool(true);
        println!("{value}");
        return Ok(());
    }
    let connection = match &status.connection {
        Connection::Connecting => "подключение".to_owned(),
        Connection::Online => "в сети".to_owned(),
        Connection::Offline(None) => "нет соединения".to_owned(),
        Connection::Offline(Some(err)) => format!("нет соединения: {err}"),
        Connection::Conflict => "синхронизация остановлена: на сервере другая учетная запись".to_owned(),
        Connection::Failed(err) => err.clone(),
    };
    println!("Учетная запись: {}", status.jid);
    println!("Соединение: {connection}");
    println!(
        "Записей: {}, неотправленных изменений: {}",
        status.records, status.pending
    );
    println!("Лимит узла: {} записей вместе с корзиной", status.max_items);
    match status.synced_ago_s {
        Some(s) => println!("Синхронизация: {} назад", duration(s)),
        None => println!("Синхронизация: еще не было"),
    }
    match status.lock_in_s {
        Some(s) => println!("Блокировка: через {}", duration(s)),
        None => println!("Блокировка: командой inkvault lock"),
    }
    if !status.notices.is_empty() {
        println!("Уведомления:");
        for notice in &status.notices {
            println!("  {notice}");
        }
    }
    Ok(())
}

fn duration(seconds: u64) -> String {
    match seconds {
        0..60 => format!("{seconds} с"),
        60..3600 => format!("{} мин", seconds / 60),
        _ => format!("{} ч {} мин", seconds / 3600, seconds % 3600 / 60),
    }
}
