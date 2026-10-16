//! Агент: держит разблокированную учетную запись, движок синхронизации и соединение XMPP и
//! отвечает командам CLI через unix-сокет. Ключи есть только в памяти этого процесса.
//!
//! Запуск: команда CLI передает строку `Start` через stdin, агент разблокирует хранилище,
//! открывает сокет и отвечает одной строкой `Reply` в stdout. Дальше команда завершается,
//! а агент работает до блокировки, таймаута или сигнала.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs;
use std::io::{BufRead, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use inkvault_core::hlc::{format_node, generate_node_id};
use inkvault_core::sync::{Command, Event, Limits, Output, PublishOutcome, WarningKind};
use inkvault_core::{Account, AccountSync, CoreError, Record, SyncEngine, UnlockedAccount, open_local, seal_local};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::{Notify, mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio_xmpp::Stanza;
use tokio_xmpp::parsers::jid::{BareJid, FullJid};
use zeroize::Zeroizing;

use crate::proto::{self, Connection, Entry, Imported, Reply, Request, Saved, Start, Status};
use crate::store::{Config, Store};
use crate::xmpp::{self, Incoming, IqError, NS_VAULT, Server, Xmpp};

const MAX_NOTICES: usize = 20;
const XMPP_SECRET: &str = "xmpp-password";
const SYNC_TIMEOUT: Duration = Duration::from_secs(120);
// каждая запись публикуется отдельным запросом к серверу: восстановление тысяч записей идет минутами
const IMPORT_TIMEOUT: Duration = Duration::from_secs(30 * 60);

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or_default()
}

struct Shared {
    jid: String,
    account: UnlockedAccount,
    engine: SyncEngine,
    vault_id: String,
    connection: Connection,
    synced_at: Option<Instant>,
    notices: VecDeque<String>,
    last_used: Instant,
}

type State = Arc<Mutex<Shared>>;

fn lock(state: &State) -> MutexGuard<'_, Shared> {
    state.lock().expect("состояние агента")
}

impl Shared {
    fn notice(&mut self, text: String) {
        if self.notices.back() != Some(&text) {
            self.notices.push_back(text);
        }
        while self.notices.len() > MAX_NOTICES {
            self.notices.pop_front();
        }
    }

    /// Записи без удаленных, по названию.
    fn entries(&self) -> Vec<Entry> {
        let mut entries: Vec<Entry> = self
            .engine
            .records()
            .filter(|(_, record, _)| !record.is_deleted())
            .map(|(id, record, _)| Entry {
                id: id.to_owned(),
                fields: record
                    .fields
                    .iter()
                    .filter(|(_, f)| !f.value.is_empty())
                    .map(|(name, f)| (name.clone(), f.value.clone()))
                    .collect(),
                tags: record.tags().map(str::to_owned).collect(),
            })
            .collect();
        entries.sort_by_cached_key(|e| (e.field(proto::NAME).to_lowercase(), e.id.clone()));
        entries
    }

    /// Запись, которую можно изменить: она есть и не в корзине.
    fn live(&self, id: &str) -> Result<&Record, String> {
        self.engine
            .record(id)
            .filter(|record| !record.is_deleted())
            .ok_or_else(|| CoreError::NotFound.to_string())
    }

    /// Ошибка, если у другой записи то же название без учета регистра и тот же логин: get не различил бы их.
    fn ensure_unique(&self, id: &str, name: &str, username: &str) -> Result<(), String> {
        let name = name.to_lowercase();
        let same = self.engine.records().find(|(other, record, _)| {
            *other != id
                && !record.is_deleted()
                && record.get(proto::NAME).unwrap_or_default().to_lowercase() == name
                && record.get(proto::USERNAME).unwrap_or_default() == username
        });
        let Some((other, record, _)) = same else {
            return Ok(());
        };
        let name = record.get(proto::NAME).unwrap_or_default();
        Err(match username {
            "" => tr!(
                "the item {name} without a username already exists: {other}",
                "запись {name} без логина уже есть: {other}"
            ),
            _ => tr!(
                "the item {name} with the username {username} already exists: {other}",
                "запись {name} с логином {username} уже есть: {other}"
            ),
        })
    }

    fn status(&self, timeout: Option<Duration>) -> Status {
        Status {
            jid: self.jid.clone(),
            connection: self.connection.clone(),
            records: self
                .engine
                .records()
                .filter(|(_, record, _)| !record.is_deleted())
                .count(),
            pending: self.engine.pending(),
            max_items: self.engine.max_items(),
            synced_ago_s: self.synced_at.map(|t| t.elapsed().as_secs()),
            lock_in_s: timeout.map(|t| t.saturating_sub(self.last_used.elapsed()).as_secs()),
            notices: self.notices.iter().cloned().collect(),
        }
    }
}

/// Точка входа процесса агента (`inkvault agent`).
pub fn main(store: Store) -> Result<(), String> {
    let mut line = Zeroizing::new(String::new());
    std::io::stdin()
        .lock()
        .read_line(&mut line)
        .map_err(|e| format!("stdin: {e}"))?;
    let start: Start = serde_json::from_str(&line)
        .map_err(|e| tr!("invalid start parameters: {e}", "неверные параметры запуска: {e}"))?;
    drop(line);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    runtime.block_on(async move {
        let timeout = (start.timeout_min > 0).then(|| Duration::from_secs(start.timeout_min * 60));
        let listener = match store.ensure_dirs().and_then(|_| bind(&store.socket)) {
            Ok(listener) => listener,
            Err(err) => {
                respond(&Reply::Error(err.clone()));
                return Err(err);
            }
        };
        match open(&store, start).await {
            Ok(agent) => {
                respond(&Reply::Done);
                agent.serve(&store, listener, timeout).await;
                Ok(())
            }
            Err(err) => {
                let _ = fs::remove_file(&store.socket);
                respond(&Reply::Error(err.clone()));
                Err(err)
            }
        }
    })
}

fn respond(reply: &Reply) {
    let mut out = std::io::stdout().lock();
    let _ = writeln!(
        out,
        "{}",
        serde_json::to_string(reply).expect("ответ сериализуется в JSON")
    );
    let _ = out.flush();
}

struct Agent {
    state: State,
    xmpp: Xmpp,
    events: mpsc::UnboundedReceiver<Incoming>,
    connection: JoinHandle<()>,
    /// Сессия, установленная еще при входе: ее нужно обработать первой.
    online: Option<Option<u32>>,
    account_jid: BareJid,
}

fn bind(path: &Path) -> Result<UnixListener, String> {
    if std::os::unix::net::UnixStream::connect(path).is_ok() {
        return Err(tr!("the agent is already running", "агент уже запущен"));
    }
    // сокет от завершившегося агента
    let _ = fs::remove_file(path);
    let listener = UnixListener::bind(path).map_err(|e| format!("{}: {e}", path.display()))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(listener)
}

fn full_jid(jid: &BareJid, resource: &str) -> Result<FullJid, String> {
    format!("{jid}/{resource}").parse().map_err(|e| {
        tr!(
            "invalid XMPP resource {resource:?}: {e}",
            "неверный ресурс XMPP {resource:?}: {e}"
        )
    })
}

/// Внешняя ошибка - сбой задачи, внутренняя - ошибка ядра: по ней видно, что мастер-пароль неверный.
async fn unlock(account: Account, master: Zeroizing<String>) -> Result<Result<UnlockedAccount, CoreError>, String> {
    // Argon2id занимает поток на сотни миллисекунд
    tokio::task::spawn_blocking(move || account.unlock(&master))
        .await
        .map_err(|e| e.to_string())
}

fn first_vault(account: &UnlockedAccount) -> Result<String, String> {
    account
        .vaults()
        .next()
        .map(|(id, _)| id.to_owned())
        .ok_or_else(|| tr!("the account has no vaults", "в учетной записи нет хранилищ"))
}

async fn open(store: &Store, start: Start) -> Result<Agent, String> {
    let Start {
        master_password, login, ..
    } = start;

    if let Some(login) = login {
        let jid: BareJid = login
            .jid
            .trim()
            .parse()
            .map_err(|e| tr!("invalid JID {:?}: {e}", "неверный JID {:?}: {e}", login.jid))?;
        if jid.node().is_none() {
            return Err(tr!(
                "the JID must be in the form name@server",
                "JID нужно указать в виде имя@сервер"
            ));
        }
        let server = Server::parse(login.server.as_deref())?;
        let node = generate_node_id().map_err(|e| e.to_string())?;
        let resource = format!("cli-{}", &format_node(node)[..8]);
        let (xmpp, mut events, connection) =
            xmpp::connect(&server, full_jid(&jid, &resource)?, login.xmpp_password.clone(), false);
        let max_stanza_bytes = loop {
            match events.recv().await {
                Some(Incoming::Online { max_stanza_bytes, .. }) => break max_stanza_bytes,
                Some(Incoming::Failed(err)) => return Err(err),
                Some(_) => continue,
                None => {
                    return Err(tr!(
                        "the connection to the server was closed",
                        "соединение с сервером закрыто"
                    ));
                }
            }
        };
        let json = xmpp
            .fetch_account()
            .await
            .map_err(|e| {
                tr!(
                    "the vault account was not loaded: {e}",
                    "учетная запись хранилища не загружена: {e}"
                )
            })?
            .ok_or_else(|| {
                tr!(
                    "the server has no vault for this JID: create it in the web or Android client",
                    "на сервере нет хранилища для этого JID: создайте его в web- или Android-клиенте"
                )
            })?;
        let account = Account::from_json(&json).map_err(|e| e.to_string())?;
        let unlocked = unlock(account, master_password).await?.map_err(|e| e.to_string())?;
        let vault_id = first_vault(&unlocked)?;
        let vault_key = unlocked.vault_key(&vault_id).map_err(|e| e.to_string())?;
        let sealed = seal_local(vault_key.key.as_ref(), XMPP_SECRET, login.xmpp_password.as_bytes())
            .map_err(|e| e.to_string())?;
        // профиль мог принадлежать другой учетной записи: ее кэш новому ключу не нужен
        store.clear()?;
        store.save_config(&Config {
            jid: jid.to_string(),
            server: login.server.filter(|s| !s.trim().is_empty()),
            resource,
        })?;
        store.save_account(&unlocked.account().to_json_string())?;
        store.save_xmpp_password(&sealed)?;
        let engine = SyncEngine::new(vault_key, NS_VAULT, node, Limits::default());
        let state = new_state(jid.to_string(), unlocked, engine, vault_id);
        return Ok(Agent {
            state,
            xmpp,
            events,
            connection,
            online: Some(max_stanza_bytes),
            account_jid: jid,
        });
    }

    let config = store.config()?.ok_or_else(crate::no_login)?;
    let jid: BareJid = config
        .jid
        .parse()
        .map_err(|e| tr!("invalid JID in the settings: {e}", "неверный JID в настройках: {e}"))?;
    let account = Account::from_json(&store.account()?).map_err(|e| e.to_string())?;
    // копию с сервера без разблокировки не загрузить: пароль XMPP на устройстве зашифрован ключом хранилища
    let unlocked = unlock(account, master_password).await?.map_err(|err| match err {
        CoreError::WrongPassword => tr!(
            "{err}. If it was changed on another device, enter the previous one or run inkvault login again",
            "{err}. Если его сменили на другом устройстве, введите прежний или выполните inkvault login заново"
        ),
        err => err.to_string(),
    })?;
    let vault_id = first_vault(&unlocked)?;
    let vault_key = unlocked.vault_key(&vault_id).map_err(|e| e.to_string())?;
    let password = open_local(vault_key.key.as_ref(), XMPP_SECRET, &store.xmpp_password()?)
        .ok()
        .and_then(|p| String::from_utf8(p.to_vec()).ok())
        .map(Zeroizing::new)
        .ok_or_else(|| {
            tr!(
                "the XMPP password on this device cannot be opened: run inkvault login again",
                "пароль XMPP на устройстве не открывается: выполните inkvault login заново"
            )
        })?;
    let restored = store
        .snapshot(&vault_id)
        .and_then(|data| SyncEngine::restore(vault_key, NS_VAULT, Limits::default(), &data).ok());
    let engine = match restored {
        Some(engine) => engine,
        // снимка нет или он от другого ключа: записи загрузятся с сервера
        None => SyncEngine::new(
            unlocked.vault_key(&vault_id).map_err(|e| e.to_string())?,
            NS_VAULT,
            generate_node_id().map_err(|e| e.to_string())?,
            Limits::default(),
        ),
    };
    let server = Server::parse(config.server.as_deref())?;
    let (xmpp, events, connection) = xmpp::connect(&server, full_jid(&jid, &config.resource)?, password, true);
    let state = new_state(jid.to_string(), unlocked, engine, vault_id);
    Ok(Agent {
        state,
        xmpp,
        events,
        connection,
        online: None,
        account_jid: jid,
    })
}

fn new_state(jid: String, account: UnlockedAccount, engine: SyncEngine, vault_id: String) -> State {
    Arc::new(Mutex::new(Shared {
        jid,
        account,
        engine,
        vault_id,
        connection: Connection::Connecting,
        synced_at: None,
        notices: VecDeque::new(),
        last_used: Instant::now(),
    }))
}

type Done<T = ()> = oneshot::Sender<Result<T, String>>;

enum Control {
    Sync(Done),
    SetMaxItems {
        max_items: u32,
        done: Done,
    },
    ChangePassword {
        current: Zeroizing<String>,
        new: Zeroizing<String>,
        done: Done,
    },
    Add {
        fields: BTreeMap<String, String>,
        tags: Vec<String>,
        sync: bool,
        done: Done<Saved>,
    },
    Edit {
        id: String,
        fields: BTreeMap<String, String>,
        tags: BTreeMap<String, bool>,
        sync: bool,
        done: Done<Saved>,
    },
    Delete {
        id: String,
        sync: bool,
        done: Done<Saved>,
    },
    Import {
        file: String,
        password: Zeroizing<String>,
        sync: bool,
        done: Done<Imported>,
    },
}

impl Control {
    fn limit(&self) -> Duration {
        match self {
            Control::Import { .. } => IMPORT_TIMEOUT,
            _ => SYNC_TIMEOUT,
        }
    }
}

impl Agent {
    async fn serve(self, store: &Store, listener: UnixListener, timeout: Option<Duration>) {
        let store = Arc::new(Store {
            dir: store.dir.clone(),
            socket: store.socket.clone(),
        });
        let uid = fs::metadata(&store.dir).map(|m| m.uid()).ok();
        let shutdown = Arc::new(Notify::new());
        let (control_tx, control_rx) = mpsc::unbounded_channel();
        let sync = Syncer {
            state: self.state.clone(),
            store: store.clone(),
            xmpp: self.xmpp,
            control: control_rx,
            account_jid: self.account_jid,
            online: false,
        };
        let sync_task: JoinHandle<()> = tokio::spawn(sync.run(self.events, self.online));

        let signals = (
            signal(SignalKind::terminate()),
            signal(SignalKind::interrupt()),
            signal(SignalKind::hangup()),
        );
        // без обработчиков сигналов агент сразу переходит к сохранению кэша и выходу
        if let (Ok(mut term), Ok(mut int), Ok(mut hup)) = signals {
            let mut tick = tokio::time::interval(Duration::from_secs(1));
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        if let Ok((stream, _)) = accepted {
                            tokio::spawn(client(stream, uid, self.state.clone(), control_tx.clone(), shutdown.clone(), timeout));
                        }
                    }
                    _ = shutdown.notified() => break,
                    _ = term.recv() => break,
                    _ = int.recv() => break,
                    // агент запускается из терминала, но не должен завершаться при его закрытии
                    _ = hup.recv() => {}
                    _ = tick.tick() => {
                        if timeout.is_some_and(|t| lock(&self.state).last_used.elapsed() >= t) {
                            break;
                        }
                    }
                }
            }
        }

        sync_task.abort();
        let _ = sync_task.await;
        let (vault_id, snapshot, unsent) = {
            let state = lock(&self.state);
            (state.vault_id.clone(), state.engine.snapshot(), state.engine.pending())
        };
        if let Ok(data) = snapshot {
            let _ = store.save_snapshot(&vault_id, &data, unsent);
        }
        // после удаления сокета команды считают хранилище заблокированным
        let _ = fs::remove_file(&store.socket);
        drop(self.state);
        // без закрытия потока сервер держал бы сессию для восстановления (XEP-0198), и устройство
        // оставалось бы в сети еще несколько минут
        let _ = tokio::time::timeout(Duration::from_secs(2), self.connection).await;
    }
}

async fn client(
    stream: UnixStream,
    uid: Option<u32>,
    state: State,
    control: mpsc::UnboundedSender<Control>,
    shutdown: Arc<Notify>,
    timeout: Option<Duration>,
) {
    // сокет и так доступен только владельцу (каталог 0700, файл 0600), это вторая проверка
    if uid.is_none() || stream.peer_cred().ok().map(|c| c.uid()) != uid {
        return;
    }
    let (read, mut write) = stream.into_split();
    let mut reader = BufReader::new(read.take(proto::MAX_LINE as u64));
    // в запросах смены мастер-пароля и добавления записи - пароли
    let mut line = Zeroizing::new(String::new());
    if reader.read_line(&mut line).await.unwrap_or(0) == 0 {
        return;
    }
    let request = serde_json::from_str::<Request>(&line);
    if !matches!(request, Ok(Request::Status)) {
        lock(&state).last_used = Instant::now();
    }
    let lock_requested = matches!(request, Ok(Request::Lock));
    let reply = match request {
        Err(err) => Reply::Error(tr!("invalid request: {err}", "неверный запрос: {err}")),
        Ok(Request::Lock) => Reply::Done,
        Ok(Request::Sync) => perform(
            &control,
            Control::Sync,
            tr!("sync did not finish", "синхронизация не завершилась"),
        )
        .await
        .map_or_else(Reply::Error, |()| Reply::Done),
        Ok(Request::SetMaxItems { max_items }) => perform(
            &control,
            |done| Control::SetMaxItems { max_items, done },
            tr!(
                "changing the node limit did not finish",
                "изменение лимита узла не завершилось"
            ),
        )
        .await
        .map_or_else(Reply::Error, |()| Reply::Done),
        Ok(Request::ChangePassword { current, new }) => perform(
            &control,
            |done| Control::ChangePassword { current, new, done },
            tr!(
                "changing the master password did not finish",
                "смена мастер-пароля не завершилась"
            ),
        )
        .await
        .map_or_else(Reply::Error, |()| Reply::Done),
        Ok(Request::Add { fields, tags, sync }) => perform(
            &control,
            |done| Control::Add {
                fields,
                tags,
                sync,
                done,
            },
            tr!("adding the item did not finish", "добавление записи не завершилось"),
        )
        .await
        .map_or_else(Reply::Error, Reply::Saved),
        Ok(Request::Edit { id, fields, tags, sync }) => perform(
            &control,
            |done| Control::Edit {
                id,
                fields,
                tags,
                sync,
                done,
            },
            tr!("editing the item did not finish", "правка записи не завершилась"),
        )
        .await
        .map_or_else(Reply::Error, Reply::Saved),
        Ok(Request::Delete { id, sync }) => perform(
            &control,
            |done| Control::Delete { id, sync, done },
            tr!("deleting the item did not finish", "удаление записи не завершилось"),
        )
        .await
        .map_or_else(Reply::Error, Reply::Saved),
        Ok(Request::Export { password, master }) => export(&state, password, master)
            .await
            .map_or_else(Reply::Error, Reply::File),
        Ok(Request::Import { file, password, sync }) => perform(
            &control,
            |done| Control::Import {
                file,
                password,
                sync,
                done,
            },
            tr!("import did not finish", "импорт не завершился"),
        )
        .await
        .map_or_else(Reply::Error, Reply::Imported),
        Ok(Request::Status) => Reply::Status(lock(&state).status(timeout)),
        Ok(Request::List { query }) => {
            let entries = proto::filter(lock(&state).entries(), query.as_deref());
            Reply::List(entries.into_iter().map(Entry::public).collect())
        }
        Ok(Request::Find { query, user }) => {
            let entries = lock(&state).entries();
            match proto::find(&entries, &query, user.as_deref()) {
                Ok(entry) => Reply::Entry(entry.clone()),
                Err(err) => Reply::Error(err),
            }
        }
    };
    let mut json = Zeroizing::new(serde_json::to_string(&reply).expect("ответ сериализуется в JSON"));
    json.push('\n');
    let _ = write.write_all(json.as_bytes()).await;
    let _ = write.shutdown().await;
    if lock_requested {
        shutdown.notify_one();
    }
}

/// Файл экспорта. Под мастер-паролем - только после проверки пароля: иначе файл зашифровался бы
/// паролем с опечаткой.
async fn export(state: &State, password: Zeroizing<String>, master: bool) -> Result<String, String> {
    if master {
        let account = lock(state).account.account().clone();
        let check = password.clone();
        // Argon2id занимает поток на сотни миллисекунд
        tokio::task::spawn_blocking(move || account.unlock(&check).map(|_| ()))
            .await
            .map_err(|e| e.to_string())?
            .map_err(|e| e.to_string())?;
    }
    let file = lock(state)
        .engine
        .export(&password, now_ms())
        .map_err(|e| e.to_string())?;
    if file.len() > proto::MAX_FILE {
        return Err(tr!(
            "the export file is larger than {} MiB, import will not open it",
            "файл экспорта больше {} МиБ, его не откроет импорт",
            proto::MAX_FILE / 1024 / 1024
        ));
    }
    Ok(file)
}

/// Передает операцию задаче синхронизации и ждет ее результата.
async fn perform<T>(
    control: &mpsc::UnboundedSender<Control>,
    operation: impl FnOnce(Done<T>) -> Control,
    timeout: String,
) -> Result<T, String> {
    let (done, rx) = oneshot::channel();
    let operation = operation(done);
    let limit = operation.limit();
    let _ = control.send(operation);
    match tokio::time::timeout(limit, rx).await {
        Ok(Ok(result)) => result,
        _ => Err(timeout),
    }
}

/// Предупреждения движка за одну операцию: при загрузке узла их может быть по одному на запись.
#[derive(Default)]
struct Warnings(Vec<(WarningKind, usize, String)>);

impl Warnings {
    fn add(&mut self, events: &[Event]) {
        for event in events {
            if let Event::Warning { kind, detail, .. } = event {
                match self.0.iter_mut().find(|(k, ..)| k == kind) {
                    Some((_, count, _)) => *count += 1,
                    None => self.0.push((*kind, 1, detail.clone())),
                }
            }
        }
    }

    fn summaries(self) -> impl Iterator<Item = String> {
        self.0.into_iter().map(|(kind, count, detail)| match kind {
            WarningKind::MissingOnServer => tr!(
                "items returned to the server: {count}",
                "на сервер возвращено записей: {count}"
            ),
            WarningKind::Unreadable => tr!(
                "items from the server that could not be read: {count} ({detail})",
                "записей с сервера не удалось прочитать: {count} ({detail})"
            ),
            _ if count > 1 => tr!("{detail} (items: {count})", "{detail} (записей: {count})"),
            _ => detail,
        })
    }
}

struct Syncer {
    state: State,
    store: Arc<Store>,
    xmpp: Xmpp,
    control: mpsc::UnboundedReceiver<Control>,
    account_jid: BareJid,
    online: bool,
}

impl Syncer {
    fn shared(&self) -> MutexGuard<'_, Shared> {
        lock(&self.state)
    }

    fn notice(&self, text: String) {
        self.shared().notice(text);
    }

    async fn run(mut self, mut events: mpsc::UnboundedReceiver<Incoming>, online: Option<Option<u32>>) {
        if let Some(max_stanza_bytes) = online {
            self.on_online(false, max_stanza_bytes).await;
        }
        let mut closed = false;
        loop {
            tokio::select! {
                event = events.recv(), if !closed => match event {
                    Some(event) => self.handle(event).await,
                    None => closed = true,
                },
                control = self.control.recv() => match control {
                    Some(Control::Sync(done)) => {
                        let result = self.resync().await;
                        let _ = done.send(result);
                    }
                    Some(Control::SetMaxItems { max_items, done }) => {
                        let result = self.set_max_items(max_items).await;
                        let _ = done.send(result);
                    }
                    Some(Control::ChangePassword { current, new, done }) => {
                        let result = self.change_password(current, new).await;
                        let _ = done.send(result);
                    }
                    Some(Control::Add { fields, tags, sync, done }) => {
                        let result = self.add(fields, tags, sync).await;
                        let _ = done.send(result);
                    }
                    Some(Control::Edit { id, fields, tags, sync, done }) => {
                        let result = self.edit(id, fields, tags, sync).await;
                        let _ = done.send(result);
                    }
                    Some(Control::Delete { id, sync, done }) => {
                        let result = self.delete(id, sync).await;
                        let _ = done.send(result);
                    }
                    Some(Control::Import { file, password, sync, done }) => {
                        let result = self.import(file, password, sync).await;
                        let _ = done.send(result);
                    }
                    None => return,
                },
            }
        }
    }

    async fn handle(&mut self, event: Incoming) {
        match event {
            Incoming::Online {
                resumed,
                max_stanza_bytes,
            } => self.on_online(resumed, max_stanza_bytes).await,
            Incoming::Suspended => {
                self.online = false;
                let mut shared = self.shared();
                shared.engine.disconnected();
                if shared.connection != Connection::Conflict {
                    shared.connection = Connection::Offline(None);
                }
            }
            Incoming::Retry(err) => {
                self.online = false;
                let mut shared = self.shared();
                if shared.connection != Connection::Conflict {
                    shared.connection = Connection::Offline(Some(err));
                }
            }
            Incoming::Failed(err) => {
                self.online = false;
                let mut shared = self.shared();
                shared.engine.session_lost();
                shared.notice(err.clone());
                shared.connection = Connection::Failed(err);
            }
            Incoming::Stanza(stanza) => self.on_stanza(*stanza).await,
        }
    }

    async fn on_stanza(&mut self, stanza: Stanza) {
        match stanza {
            Stanza::Iq(iq) => {
                if let Some(answer) = xmpp::answer(iq) {
                    self.xmpp.send(Stanza::Iq(answer));
                }
            }
            Stanza::Message(message) => {
                // уведомления PEP приходят от своей учетной записи, чужие сообщения с ними игнорируются
                if !self.online || !xmpp::from_account(message.from.as_ref(), &self.account_jid) {
                    return;
                }
                for item in xmpp::notified_items(&message, NS_VAULT) {
                    let output = {
                        let mut shared = self.shared();
                        if shared.connection == Connection::Conflict {
                            return;
                        }
                        shared.engine.item_notified(item, now_ms())
                    };
                    if let Err(err) = self.apply(output).await {
                        self.notice(err);
                    }
                }
            }
            Stanza::Presence(_) => {}
        }
    }

    async fn on_online(&mut self, resumed: bool, max_stanza_bytes: Option<u32>) {
        self.online = true;
        if resumed {
            let output = {
                let mut shared = self.shared();
                if shared.connection == Connection::Conflict {
                    return;
                }
                shared.connection = Connection::Online;
                shared.engine.connected(true, max_stanza_bytes)
            };
            if let Err(err) = self.apply(output).await {
                self.notice(err);
            }
            return;
        }
        // до конца загрузки в статусе не должна оставаться причина прошлого обрыва
        self.shared().connection = Connection::Connecting;
        self.xmpp.send(Stanza::Presence(xmpp::presence()));
        if let Err(err) = self.full_sync(max_stanza_bytes).await {
            self.notice(err);
        }
    }

    fn require_online(&self) -> Result<(), String> {
        if self.online {
            return Ok(());
        }
        let shared = self.shared();
        Err(match &shared.connection {
            Connection::Failed(err) => err.clone(),
            Connection::Offline(Some(err)) => err.clone(),
            _ => tr!("no connection to the server", "нет соединения с сервером"),
        })
    }

    async fn resync(&mut self) -> Result<(), String> {
        self.require_online()?;
        self.full_sync(None).await
    }

    /// Новый лимит записей узла. Узел перенастраивается сразу, поэтому нужна связь с сервером.
    async fn set_max_items(&mut self, max_items: u32) -> Result<(), String> {
        self.require_online()?;
        let output = self
            .shared()
            .engine
            .set_max_items(max_items)
            .map_err(|e| e.to_string())?;
        self.apply(output).await?;
        if self.shared().engine.max_items() == max_items {
            Ok(())
        } else {
            Err(tr!(
                "the server did not accept the node limit of {max_items} items: \
                 pep_max_items on the server is lower, the administrator needs to raise it",
                "сервер не принял лимит узла {max_items} записей: на сервере pep_max_items меньше, \
                 администратору нужно его поднять"
            ))
        }
    }

    /// Смена мастер-пароля только при связи с сервером. Учетная запись сначала сверяется с сервером:
    /// смена на двух устройствах без сверки дала бы две версии с одним rev, и одна из них потерялась бы.
    async fn change_password(&mut self, current: Zeroizing<String>, new: Zeroizing<String>) -> Result<(), String> {
        self.require_online()?;
        self.sync_account().await?;
        let account = self.shared().account.account().clone();
        // два вывода Argon2id, проверка текущего пароля и новый, не держат блокировку состояния
        let changed = tokio::task::spawn_blocking(move || account.change_password(&current, &new))
            .await
            .map_err(|e| e.to_string())?
            .map_err(|e| e.to_string())?;
        let json = {
            let mut shared = self.shared();
            // версия с большим rev принимается сверкой так же, как новая версия с сервера
            shared.account.refresh(&changed).map_err(|e| e.to_string())?;
            shared.account.account().to_json_string()
        };
        self.store.save_account(&json)?;
        // копия на устройстве уже новая: при следующей сверке ядро выберет ее и потребует публикации
        self.xmpp.publish_account(&json).await.map_err(|e| {
            tr!(
                "the master password was changed on this device but not sent to the server ({e}), \
                 it will be sent on the next connection",
                "мастер-пароль изменен на этом устройстве, но не отправлен на сервер ({e}), \
                 он будет отправлен при следующем подключении"
            )
        })?;
        self.notice(tr!("master password changed", "мастер-пароль изменен"));
        Ok(())
    }

    /// Изменения записей сохраняются на устройстве и уходят на сервер, когда есть связь. С sync
    /// изменение принимается только после загрузки записей с сервера.
    fn require_writable(&self, sync: bool) -> Result<(), String> {
        if sync {
            self.require_online()?;
        }
        match &self.shared().connection {
            Connection::Online => Ok(()),
            // изменение ушло бы на сервер только после нового входа, а вход удаляет неотправленные изменения
            Connection::Conflict => Err(tr!(
                "sync stopped: the server has a different vault account, details: inkvault status",
                "синхронизация остановлена: на сервере другая учетная запись хранилища, подробности: inkvault status"
            )),
            Connection::Failed(err) => Err(err.clone()),
            // до конца загрузки записей движок не публикует
            _ if sync => Err(tr!(
                "sync with the server is not finished, details: inkvault status",
                "синхронизация с сервером не завершена, подробности: inkvault status"
            )),
            _ => Ok(()),
        }
    }

    async fn add(&mut self, fields: BTreeMap<String, String>, tags: Vec<String>, sync: bool) -> Result<Saved, String> {
        self.require_writable(sync)?;
        let (id, output, tagged) = {
            let mut shared = self.shared();
            let name = fields.get(proto::NAME).map(String::as_str).unwrap_or_default();
            if name.trim().is_empty() {
                return Err(no_name());
            }
            let username = fields.get(proto::USERNAME).map(String::as_str).unwrap_or_default();
            shared.ensure_unique("", name, username)?;
            let now = now_ms();
            let mut output = shared.engine.create("login", fields, now).map_err(|e| e.to_string())?;
            let id = output.item_id.clone().unwrap_or_default();
            // теги ставятся второй версией записи, как в web- и Android-клиентах
            let tags: BTreeMap<String, bool> = tags.into_iter().map(|tag| (tag, true)).collect();
            let tagged = shared.engine.edit(&id, &BTreeMap::new(), &tags, now).map(|edited| {
                output.commands.extend(edited.commands);
                output.events.extend(edited.events);
            });
            (id, output, tagged)
        };
        let pending = self.publish(BTreeSet::from([id.clone()]), output, sync).await?;
        tagged.map_err(|e| {
            tr!(
                "the item {id} was created without tags: {e}",
                "запись {id} создана без тегов: {e}"
            )
        })?;
        Ok(Saved { id, pending })
    }

    async fn edit(
        &mut self,
        id: String,
        fields: BTreeMap<String, String>,
        tags: BTreeMap<String, bool>,
        sync: bool,
    ) -> Result<Saved, String> {
        self.require_writable(sync)?;
        let output = {
            let mut shared = self.shared();
            let record = shared.live(&id)?;
            if fields.contains_key(proto::NAME) || fields.contains_key(proto::USERNAME) {
                let value = |field| {
                    fields
                        .get(field)
                        .map_or(record.get(field).unwrap_or_default(), String::as_str)
                };
                if value(proto::NAME).trim().is_empty() {
                    return Err(no_name());
                }
                shared.ensure_unique(&id, value(proto::NAME), value(proto::USERNAME))?;
            }
            shared
                .engine
                .edit(&id, &fields, &tags, now_ms())
                .map_err(|e| e.to_string())?
        };
        let pending = self.publish(BTreeSet::from([id.clone()]), output, sync).await?;
        Ok(Saved { id, pending })
    }

    async fn delete(&mut self, id: String, sync: bool) -> Result<Saved, String> {
        self.require_writable(sync)?;
        let output = {
            let mut shared = self.shared();
            shared.live(&id)?;
            shared.engine.delete_item(&id, now_ms()).map_err(|e| e.to_string())?
        };
        let pending = self.publish(BTreeSet::from([id.clone()]), output, sync).await?;
        Ok(Saved { id, pending })
    }

    /// Слияние по HLC, как при синхронизации: повторный импорт ничего не меняет, более новые правки
    /// хранилища не затираются.
    async fn import(&mut self, file: String, password: Zeroizing<String>, sync: bool) -> Result<Imported, String> {
        self.require_writable(sync)?;
        let output = self
            .shared()
            .engine
            .import(&file, &password, now_ms())
            .map_err(|e| e.to_string())?;
        let stats = output.imported.unwrap_or_default();
        let ids = output
            .events
            .iter()
            .filter_map(|event| match event {
                Event::ItemChanged { item_id } => Some(item_id.clone()),
                _ => None,
            })
            .collect();
        let pending = self.publish(ids, output, sync).await?;
        Ok(Imported { stats, pending })
    }

    /// Отправляет изменения записей ids, если есть связь, и сообщает, остались ли они неотправленными.
    /// С sync неотправленные изменения - ошибка, но и тогда они остаются на устройстве до следующей
    /// синхронизации.
    async fn publish(&mut self, ids: BTreeSet<String>, output: Output, sync: bool) -> Result<bool, String> {
        let applied = self.apply(output).await;
        let pending = self
            .shared()
            .engine
            .records()
            .any(|(id, _, pending)| pending && ids.contains(id));
        let changes = match (ids.len(), ids.first()) {
            (1, Some(id)) => tr!("the changes to the item {id}", "изменения записи {id}"),
            _ => tr!("the changes to the items", "изменения записей"),
        };
        match (applied, pending) {
            (Err(err), true) if sync => Err(tr!(
                "{changes} are saved on this device but not sent to the server ({err}), \
                 they will be sent on the next connection or with inkvault sync",
                "{changes} сохранены на этом устройстве, но не отправлены на сервер ({err}), \
                 они будут отправлены при следующем подключении или по команде inkvault sync"
            )),
            (Ok(()), true) if sync => Err(tr!(
                "{changes} are saved on this device, but the server did not accept them, details: inkvault status",
                "{changes} сохранены на этом устройстве, но сервер их не принял, \
                 подробности: inkvault status"
            )),
            // без sync или при отправленных записях ошибка остается в уведомлениях inkvault status
            (Err(err), _) => {
                self.notice(err);
                Ok(pending)
            }
            (Ok(()), _) => Ok(pending),
        }
    }

    /// Учетная запись сверяется раньше записей: при чужой учетной записи записи не загружаются и не публикуются.
    async fn full_sync(&mut self, max_stanza_bytes: Option<u32>) -> Result<(), String> {
        self.sync_account().await?;
        let output = {
            let mut shared = self.shared();
            // загрузка узла заново: публикации прошлой сессии уже без ответа
            shared.engine.session_lost();
            shared.engine.connected(false, max_stanza_bytes)
        };
        let result = self.apply(output).await;
        // "в сети" - только после загрузки записей: скрипт ждет этого состояния и сразу читает записи
        self.shared().connection = Connection::Online;
        result
    }

    async fn sync_account(&mut self) -> Result<(), String> {
        let server = self
            .xmpp
            .fetch_account()
            .await
            .map_err(|e| tr!("the account was not loaded: {e}", "учетная запись не загружена: {e}"))?;
        let (state, json) = {
            let mut shared = self.shared();
            let state = match &server {
                Some(json) => {
                    let account = Account::from_json(json)
                        .map_err(|e| tr!("the account on the server: {e}", "учетная запись на сервере: {e}"))?;
                    shared.account.refresh(&account).map_err(|e| e.to_string())?
                }
                None => AccountSync::Publish,
            };
            if state == AccountSync::Foreign {
                shared.connection = Connection::Conflict;
                shared.engine.disconnected();
                return Err(tr!(
                    "the server has a different vault account, sync stopped: \
                     resolve the conflict in the web or Android client and run inkvault login again",
                    "на сервере другая учетная запись хранилища, синхронизация остановлена: \
                     решите конфликт в web- или Android-клиенте и выполните inkvault login заново"
                ));
            }
            (state, shared.account.account().to_json_string())
        };
        if state != AccountSync::Same {
            self.store.save_account(&json)?;
        }
        match state {
            AccountSync::Publish => {
                self.xmpp.publish_account(&json).await.map_err(|e| {
                    tr!(
                        "the account was not published: {e}",
                        "учетная запись не опубликована: {e}"
                    )
                })?;
                self.notice(if server.is_some() {
                    tr!(
                        "the server had an old copy of the account, the current one was published",
                        "на сервере была старая копия учетной записи, опубликована актуальная"
                    )
                } else {
                    tr!(
                        "the account was restored on the server",
                        "учетная запись восстановлена на сервере"
                    )
                });
            }
            AccountSync::Updated => self.notice(tr!(
                "the account was updated from the server",
                "учетная запись обновлена с сервера"
            )),
            AccountSync::Same | AccountSync::Foreign => {}
        }
        Ok(())
    }

    /// Исполняет команды движка по очереди; команды из ответа на команду идут раньше остальных.
    async fn apply(&mut self, output: Output) -> Result<(), String> {
        let mut warnings = Warnings::default();
        let mut synced = false;
        let mut queue: VecDeque<Command> = VecDeque::new();
        let mut absorb = |output: Output, queue: &mut VecDeque<Command>| {
            warnings.add(&output.events);
            synced |= output.events.contains(&Event::Synced);
            for command in output.commands.into_iter().rev() {
                queue.push_front(command);
            }
        };
        absorb(output, &mut queue);
        let mut result = Ok(());
        while let Some(command) = queue.pop_front() {
            match self.execute(command).await {
                Ok(output) => absorb(output, &mut queue),
                Err(err) => {
                    result = Err(err);
                    break;
                }
            }
        }
        let (vault_id, snapshot, unsent) = {
            let mut shared = self.shared();
            if synced {
                shared.synced_at = Some(Instant::now());
            }
            for text in warnings.summaries() {
                shared.notice(text);
            }
            (
                shared.vault_id.clone(),
                shared.engine.snapshot(),
                shared.engine.pending(),
            )
        };
        match snapshot.map_err(|e| e.to_string()) {
            Ok(data) => {
                if let Err(err) = self.store.save_snapshot(&vault_id, &data, unsent) {
                    self.notice(cache_not_saved(&err));
                }
            }
            Err(err) => self.notice(cache_not_saved(&err)),
        }
        result
    }

    async fn execute(&self, command: Command) -> Result<Output, String> {
        Ok(match command {
            Command::FetchConfig { request, node } => {
                // без настроек узла движок не меняет его лимит, поэтому отказ сервера обмен не прерывает
                let max_items = match self.xmpp.node_max_items(&node).await {
                    Ok(max_items) => max_items,
                    Err(IqError::Stanza(err)) => {
                        self.notice(config_not_read(&xmpp::condition(&err)));
                        None
                    }
                    Err(err) => return Err(config_not_read(&err)),
                };
                self.shared().engine.config_fetched(request, max_items)
            }
            Command::FetchAll { node } => {
                let items = self
                    .xmpp
                    .fetch(&node)
                    .await
                    .map_err(|e| tr!("the items were not loaded: {e}", "записи не загружены: {e}"))?;
                self.shared().engine.items_fetched(items, now_ms())
            }
            Command::Publish {
                request,
                node,
                max_items,
                item,
            } => {
                let error = self
                    .xmpp
                    .publish(&node, max_items, &item)
                    .await
                    .map_err(|e| tr!("the item was not published: {e}", "запись не опубликована: {e}"))?;
                self.shared()
                    .engine
                    .publish_result(request, PublishOutcome::from_error(error.as_deref()))
            }
            Command::ConfigureNode {
                request,
                node,
                max_items,
            } => {
                let ok = match self.xmpp.configure(&node, max_items).await {
                    Ok(()) => true,
                    Err(IqError::Stanza(err)) => {
                        self.notice(config_not_changed(&xmpp::condition(&err)));
                        false
                    }
                    Err(err) => return Err(config_not_changed(&err)),
                };
                self.shared().engine.configure_result(request, ok)
            }
        })
    }
}

fn no_name() -> String {
    tr!("the item has no name", "у записи нет названия")
}

fn cache_not_saved(err: &str) -> String {
    tr!("the cache was not saved: {err}", "кэш не сохранен: {err}")
}

fn config_not_read(err: &dyn std::fmt::Display) -> String {
    tr!(
        "the node settings were not read: {err}",
        "настройки узла не прочитаны: {err}"
    )
}

fn config_not_changed(err: &dyn std::fmt::Display) -> String {
    tr!(
        "the node settings were not changed: {err}",
        "настройки узла не изменены: {err}"
    )
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use inkvault_core::sync::WarningReason;

    use super::*;

    // язык процесса в тестах не меняется: они идут параллельно, тексты - на английском по умолчанию
    #[test]
    fn warnings_are_summarized_per_kind() {
        let warning = |reason: WarningReason, detail: &str| Event::Warning {
            kind: reason.kind(),
            item_id: None,
            detail: detail.to_owned(),
            reason,
        };
        let unreadable = || WarningReason::Unreadable {
            error: "decrypt_failed".to_owned(),
        };
        let mut warnings = Warnings::default();
        warnings.add(&[
            warning(unreadable(), "decryption failed"),
            warning(unreadable(), "decryption failed"),
            warning(WarningReason::ClockAhead { hlc: "0".to_owned() }, "timestamp is ahead"),
            Event::Synced,
        ]);
        let summaries: Vec<String> = warnings.summaries().collect();
        assert_eq!(
            summaries,
            vec![
                "items from the server that could not be read: 2 (decryption failed)".to_owned(),
                "timestamp is ahead".to_owned(),
            ]
        );
    }

    #[test]
    fn entries_hide_deleted_records_and_empty_fields() {
        let account = UnlockedAccount::create("correct horse", 1_700_000_000_000).unwrap();
        let vault_id = first_vault(&account).unwrap();
        let mut engine = SyncEngine::new(account.vault_key(&vault_id).unwrap(), NS_VAULT, 1, Limits::default());
        let fields = |pairs: &[(&str, &str)]| -> BTreeMap<String, String> {
            pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
        };
        let kept = engine
            .create(
                "login",
                fields(&[("name", "b-site"), ("password", "pw"), ("notes", "")]),
                1,
            )
            .unwrap()
            .item_id
            .unwrap();
        let gone = engine
            .create("login", fields(&[("name", "a-site")]), 2)
            .unwrap()
            .item_id
            .unwrap();
        engine.delete_item(&gone, 3).unwrap();
        let shared = Shared {
            jid: "alice@vault.test".into(),
            account,
            engine,
            vault_id,
            connection: Connection::Connecting,
            synced_at: None,
            notices: VecDeque::new(),
            last_used: Instant::now(),
        };
        let entries = shared.entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].id, kept);
        assert!(!entries[0].fields.contains_key("notes"));
        assert_eq!(shared.status(None).records, 1);
    }
}
