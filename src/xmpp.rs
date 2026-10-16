//! Соединение агента с сервером XMPP и операции с узлами PEP. Формат узлов общий для всех
//! клиентов (docs/protocol.md в inkvault-core): элемент entry с версией ключа и шифротекстом в base64.

use std::borrow::Cow;
use std::collections::{BTreeSet, HashMap};
use std::fmt;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_util::StreamExt;
use inkvault_core::sync::RemoteItem;
use sasl::common::Credentials;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio_xmpp::connect::{DnsConfig, ServerConnector, StartTlsServerConnector, TcpServerConnector};
use tokio_xmpp::minidom::Element;
use tokio_xmpp::minidom::rxml::NcName;
use tokio_xmpp::parsers::caps::{self, Caps};
use tokio_xmpp::parsers::disco::{DiscoInfoResult, Identity};
use tokio_xmpp::parsers::hashes::Algo;
use tokio_xmpp::parsers::iq::Iq;
use tokio_xmpp::parsers::jid::{BareJid, FullJid, Jid};
use tokio_xmpp::parsers::message::Message;
use tokio_xmpp::parsers::ns;
use tokio_xmpp::parsers::presence::Presence;
use tokio_xmpp::parsers::stanza_error::{DefinedCondition, ErrorType, StanzaError};
use tokio_xmpp::parsers::stream_features::StreamFeatures;
use tokio_xmpp::stanzastream::{self, StanzaStream, StreamEvent};
use tokio_xmpp::xmlstream::{StreamHeader, Timeouts, XmppStream};
use tokio_xmpp::{Error, Stanza};
use zeroize::Zeroizing;

pub const NS_VAULT: &str = "urn:inkvault:vault:0";
pub const NS_ACCOUNT: &str = "urn:inkvault:account:0";
const NS_PUBSUB: &str = "http://jabber.org/protocol/pubsub";
const NS_OWNER: &str = "http://jabber.org/protocol/pubsub#owner";
const NS_EVENT: &str = "http://jabber.org/protocol/pubsub#event";
const NS_DATA: &str = "jabber:x:data";
const CAPS_NODE: &str = "https://inkvault.dev/cli";
const DEFAULT_PORT: u16 = 5222;
const IQ_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_RETRY_DELAY: Duration = Duration::from_secs(30);
const QUEUE_DEPTH: usize = 16;

/// Куда подключаться.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Server {
    /// Адрес из записи SRV домена JID, STARTTLS.
    Srv,
    StartTls {
        host: String,
        port: u16,
    },
    /// Без TLS: только адрес loopback, например локальный тестовый сервер.
    Plain(SocketAddr),
}

impl Server {
    /// "host", "host:port", "[::1]:port" - STARTTLS; "tcp://127.0.0.1:port" - без TLS.
    pub fn parse(value: Option<&str>) -> Result<Self, String> {
        let Some(value) = value.map(str::trim).filter(|v| !v.is_empty()) else {
            return Ok(Self::Srv);
        };
        if let Some(addr) = value.strip_prefix("tcp://") {
            let addr: SocketAddr = addr.parse().map_err(|_| {
                tr!(
                    "an address without TLS is given as tcp://IP:port, got {value}",
                    "адрес без TLS указывается как tcp://IP:порт, получено {value}"
                )
            })?;
            if !addr.ip().is_loopback() {
                return Err(tr!(
                    "sign-in without TLS is only allowed to a loopback address (127.0.0.1 or ::1)",
                    "вход без TLS разрешен только на адрес loopback (127.0.0.1 или ::1)"
                ));
            }
            return Ok(Self::Plain(addr));
        }
        if let Ok(addr) = value.parse::<SocketAddr>() {
            return Ok(Self::StartTls {
                host: addr.ip().to_string(),
                port: addr.port(),
            });
        }
        let (host, port) = match value.rsplit_once(':') {
            Some((host, port)) if !host.contains(':') => {
                let port = port
                    .parse()
                    .map_err(|_| tr!("invalid port in the address {value}", "неверный порт в адресе {value}"))?;
                (host, port)
            }
            _ => (value.trim_start_matches('[').trim_end_matches(']'), DEFAULT_PORT),
        };
        if host.is_empty() || host.contains('/') {
            return Err(tr!(
                "invalid server address: {value}",
                "неверный адрес сервера: {value}"
            ));
        }
        Ok(Self::StartTls {
            host: host.to_owned(),
            port,
        })
    }
}

/// События соединения для агента.
#[derive(Debug)]
pub enum Incoming {
    /// Сессия установлена. resumed - восстановлена без потерь (XEP-0198), уведомления не терялись.
    Online {
        resumed: bool,
        max_stanza_bytes: Option<u32>,
    },
    /// Связь прервана, сессию еще можно восстановить.
    Suspended,
    Stanza(Box<Stanza>),
    /// Подключиться не удалось, следующая попытка будет позже.
    Retry(String),
    /// Вход невозможен, например неверный пароль XMPP. Повторов не будет.
    Failed(String),
}

#[derive(Debug)]
pub enum IqError {
    Stanza(Box<StanzaError>),
    Lost,
    Timeout,
}

impl IqError {
    fn is_item_not_found(&self) -> bool {
        matches!(self, Self::Stanza(e) if e.defined_condition == DefinedCondition::ItemNotFound)
    }
}

impl fmt::Display for IqError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Stanza(e) => f.write_str(&condition(e)),
            Self::Lost => f.write_str(&tr!("connection lost", "соединение прервано")),
            Self::Timeout => f.write_str(&tr!(
                "the server did not respond within {} s",
                "сервер не ответил за {} с",
                IQ_TIMEOUT.as_secs()
            )),
        }
    }
}

/// Специфичное условие PubSub (precondition-not-met) важнее общего (conflict); текст сервера объясняет причину.
pub fn condition(error: &StanzaError) -> String {
    let name = match &error.other {
        Some(app) => app.name().to_owned(),
        None => Element::from(error.defined_condition.clone()).name().to_owned(),
    };
    match error.texts.values().next() {
        Some(text) => format!("{name}: {text}"),
        None => name,
    }
}

type Pending = Arc<Mutex<HashMap<String, oneshot::Sender<Iq>>>>;

#[derive(Clone)]
pub struct Xmpp {
    out: mpsc::UnboundedSender<Stanza>,
    pending: Pending,
    next_id: Arc<AtomicU64>,
}

/// Открывает соединение. Переподключение после обрыва - внутри StanzaStream. retry = false - первая
/// неудача входа окончательная (команда login), иначе попытки повторяются, пока не будет ошибки авторизации.
/// Задача соединения закрывает поток и завершается, когда освобождены все копии `Xmpp`.
pub fn connect(
    server: &Server,
    jid: FullJid,
    password: Zeroizing<String>,
    retry: bool,
) -> (Xmpp, mpsc::UnboundedReceiver<Incoming>, JoinHandle<()>) {
    let (events_tx, events_rx) = mpsc::unbounded_channel();
    let account = jid.to_bare();
    let stream = match server {
        Server::Srv => {
            let dns = DnsConfig::srv_default_client(jid.domain().as_str());
            open(
                StartTlsServerConnector::from(dns),
                true,
                jid,
                password,
                retry,
                events_tx.clone(),
            )
        }
        Server::StartTls { host, port } => {
            let dns = DnsConfig::no_srv(host, *port);
            open(
                StartTlsServerConnector::from(dns),
                true,
                jid,
                password,
                retry,
                events_tx.clone(),
            )
        }
        Server::Plain(addr) => {
            let dns = DnsConfig::addr(&addr.to_string());
            open(TcpServerConnector(dns), false, jid, password, retry, events_tx.clone())
        }
    };
    let (out_tx, out_rx) = mpsc::unbounded_channel();
    let pending = Pending::default();
    let task = tokio::spawn(run(stream, out_rx, events_tx, pending.clone(), account));
    let xmpp = Xmpp {
        out: out_tx,
        pending,
        next_id: Arc::new(AtomicU64::new(1)),
    };
    (xmpp, events_rx, task)
}

fn open<C: ServerConnector>(
    connector: C,
    tls: bool,
    jid: FullJid,
    password: Zeroizing<String>,
    retry: bool,
    events: mpsc::UnboundedSender<Incoming>,
) -> StanzaStream {
    let connected = Arc::new(AtomicBool::new(false));
    let password = Arc::new(password);
    let reconnect = move |_location: Option<String>, slot: oneshot::Sender<stanzastream::Connection>| {
        let (connector, jid, password) = (connector.clone(), jid.clone(), password.clone());
        let (events, connected) = (events.clone(), connected.clone());
        tokio::spawn(async move {
            let mut delay = Duration::from_secs(1);
            loop {
                match login(connector.clone(), tls, &jid, &password).await {
                    Ok((features, stream)) => {
                        connected.store(true, Ordering::Relaxed);
                        // ошибка - поток уже закрыт, новое соединение закрывается вместе с ним
                        let _ = slot.send(stanzastream::Connection {
                            stream: stream.box_stream(),
                            features,
                            identity: jid.into(),
                        });
                        return;
                    }
                    Err(err) => {
                        let fatal = matches!(err, Error::Auth(_)) || !(retry || connected.load(Ordering::Relaxed));
                        let text = describe(&err);
                        if fatal {
                            // без slot поток завершается и больше не переподключается
                            let _ = events.send(Incoming::Failed(text));
                            return;
                        }
                        let _ = events.send(Incoming::Retry(text));
                        tokio::time::sleep(delay).await;
                        delay = (delay * 2).min(MAX_RETRY_DELAY);
                    }
                }
            }
        });
    };
    StanzaStream::new(Box::new(reconnect), QUEUE_DEPTH)
}

fn describe(err: &Error) -> String {
    match err {
        Error::Auth(_) => tr!(
            "XMPP sign-in failed, check the JID and the XMPP password ({err})",
            "вход в XMPP не выполнен, проверьте JID и пароль XMPP ({err})"
        ),
        other => tr!("server unavailable: {other}", "сервер недоступен: {other}"),
    }
}

/// Вход без SASL2: SCRAM, а PLAIN только внутри TLS. ANONYMOUS не используется никогда.
async fn login<C: ServerConnector>(
    connector: C,
    tls: bool,
    jid: &FullJid,
    password: &str,
) -> Result<(StreamFeatures, XmppStream<C::Stream>), Error> {
    let (stream, channel_binding) = connector
        .connect(&jid.clone().into(), ns::JABBER_CLIENT, Timeouts::default())
        .await?;
    let (features, stream) = stream.recv_features().await?;
    let mechanisms: BTreeSet<String> = features
        .sasl_mechanisms
        .into_iter()
        .filter(|m| m.starts_with("SCRAM-") || (tls && m == "PLAIN"))
        .collect();
    let username = jid.node().map(|n| n.as_str()).unwrap_or_default();
    let credentials = Credentials::default()
        .with_username(username)
        .with_password(password)
        .with_channel_binding(channel_binding);
    let stream = tokio_xmpp::client_login(stream, mechanisms, credentials).await?;
    let stream = stream
        .send_header(StreamHeader {
            to: Some(Cow::Borrowed(jid.domain().as_str())),
            from: None,
            id: None,
        })
        .await?;
    Ok(stream.recv_features().await?)
}

async fn run(
    mut stream: StanzaStream,
    mut out: mpsc::UnboundedReceiver<Stanza>,
    events: mpsc::UnboundedSender<Incoming>,
    pending: Pending,
    account: BareJid,
) {
    loop {
        tokio::select! {
            event = stream.next() => {
                let incoming = match event {
                    None => break,
                    Some(stanzastream::Event::Stream(StreamEvent::Reset { features, .. })) => {
                        // новая сессия: ответы на запросы прошлой уже не придут
                        pending.lock().expect("очередь запросов").clear();
                        let max_stanza_bytes = features.limits.and_then(|l| l.max_bytes).map(|n| n.get());
                        Incoming::Online { resumed: false, max_stanza_bytes }
                    }
                    Some(stanzastream::Event::Stream(StreamEvent::Resumed)) => {
                        Incoming::Online { resumed: true, max_stanza_bytes: None }
                    }
                    Some(stanzastream::Event::Stream(StreamEvent::Suspended)) => Incoming::Suspended,
                    Some(stanzastream::Event::Stanza(Stanza::Iq(iq))) => match route(iq, &pending, &account) {
                        Some(iq) => Incoming::Stanza(Box::new(Stanza::Iq(iq))),
                        None => continue,
                    },
                    Some(stanzastream::Event::Stanza(other)) => Incoming::Stanza(Box::new(other)),
                };
                if events.send(incoming).is_err() {
                    break;
                }
            }
            stanza = out.recv() => match stanza {
                Some(stanza) => {
                    stream.send(Box::new(stanza)).await;
                }
                None => {
                    stream.close().await;
                    return;
                }
            },
        }
    }
    pending.lock().expect("очередь запросов").clear();
}

/// Ответ на свой запрос передается ожидающему. Запросы идут к своей учетной записи без 'to',
/// поэтому ответ приходит без 'from' или от bare JID учетной записи; остальное - подделка.
fn route(iq: Iq, pending: &Pending, account: &BareJid) -> Option<Iq> {
    let (id, from) = match &iq {
        Iq::Result { id, from, .. } | Iq::Error { id, from, .. } => (id.clone(), from.clone()),
        _ => return Some(iq),
    };
    if !from_account(from.as_ref(), account) {
        return None;
    }
    if let Some(waiter) = pending.lock().expect("очередь запросов").remove(&id) {
        let _ = waiter.send(iq);
    }
    None
}

pub fn from_account(from: Option<&Jid>, account: &BareJid) -> bool {
    from.is_none_or(|j| j.resource().is_none() && j.to_bare() == *account)
}

fn ncname(name: &str) -> NcName {
    NcName::try_from(name).expect("имя атрибута XML")
}

fn element(name: &str, ns: &str, attrs: &[(&str, &str)]) -> tokio_xmpp::minidom::ElementBuilder {
    attrs
        .iter()
        .fold(Element::builder(name, ns), |b, (k, v)| b.attr(ncname(k), *v))
}

fn form(form_type: &str, fields: &[(&str, String)]) -> Element {
    let hidden = element("field", NS_DATA, &[("var", "FORM_TYPE"), ("type", "hidden")])
        .append(element("value", NS_DATA, &[]).append(form_type))
        .build();
    let fields = fields.iter().map(|(name, value)| {
        element("field", NS_DATA, &[("var", name)])
            .append(element("value", NS_DATA, &[]).append(value.as_str()))
            .build()
    });
    element("x", NS_DATA, &[("type", "submit")])
        .append(hidden)
        .append_all(fields)
        .build()
}

// Параметры узлов InkVault: при расхождении с ними сервер отклоняет публикацию
fn node_options(max_items: u32) -> Vec<(&'static str, String)> {
    vec![
        ("pubsub#access_model", "whitelist".to_owned()),
        ("pubsub#persist_items", "true".to_owned()),
        ("pubsub#max_items", max_items.to_string()),
    ]
}

fn max_items_of(pubsub: &Element) -> Option<u32> {
    pubsub
        .get_child("configure", NS_OWNER)?
        .get_child("x", NS_DATA)?
        .children()
        .find(|f| f.is("field", NS_DATA) && f.attr("var") == Some("pubsub#max_items"))?
        .get_child("value", NS_DATA)?
        .text()
        .parse()
        .ok()
}

fn publish_payload(node: &str, item_id: &str, entry: Element, max_items: u32) -> Element {
    let publish = element("publish", NS_PUBSUB, &[("node", node)])
        .append(element("item", NS_PUBSUB, &[("id", item_id)]).append(entry))
        .build();
    let options = element("publish-options", NS_PUBSUB, &[])
        .append(form(
            "http://jabber.org/protocol/pubsub#publish-options",
            &node_options(max_items),
        ))
        .build();
    element("pubsub", NS_PUBSUB, &[])
        .append(publish)
        .append(options)
        .build()
}

fn items_request(node: &str) -> Element {
    element("pubsub", NS_PUBSUB, &[])
        .append(element("items", NS_PUBSUB, &[("node", node)]))
        .build()
}

fn entry_of(item: &Element) -> Option<RemoteItem> {
    let entry = item.get_child("entry", NS_VAULT)?;
    Some(RemoteItem {
        id: item.attr("id")?.to_owned(),
        key_version: entry.attr("key")?.parse().ok()?,
        ciphertext: entry.text(),
    })
}

/// Элементы item из уведомления PEP об узле `node`.
pub fn notified_items(message: &Message, node: &str) -> Vec<RemoteItem> {
    message
        .payloads
        .iter()
        .filter(|p| p.is("event", NS_EVENT))
        .filter_map(|event| event.get_child("items", NS_EVENT))
        .filter(|items| items.attr("node") == Some(node))
        .flat_map(|items| items.children().filter(|c| c.is("item", NS_EVENT)))
        .filter_map(entry_of)
        .collect()
}

fn identity() -> Identity {
    Identity::new("client", "console", "en", "InkVault")
}

fn disco_info(node: Option<String>) -> DiscoInfoResult {
    let features = [
        ns::DISCO_INFO.to_owned(),
        ns::CAPS.to_owned(),
        format!("{NS_VAULT}+notify"),
    ];
    DiscoInfoResult {
        node,
        identities: vec![identity()],
        features: features.into_iter().collect(),
        extensions: Vec::new(),
    }
}

/// Presence с caps (XEP-0115): по ним сервер узнает о +notify и присылает уведомления узла хранилища.
pub fn presence() -> Presence {
    let hash = caps::hash_caps(&caps::compute_disco(&disco_info(None)), Algo::Sha_1).expect("SHA-1 поддерживается");
    Presence::available().with_payload(Caps::new(CAPS_NODE, hash))
}

/// Ответ на входящий запрос IQ: disco#info для проверки caps, на остальное - service-unavailable.
pub fn answer(iq: Iq) -> Option<Iq> {
    match iq {
        Iq::Get { from, id, payload, .. } if payload.is("query", ns::DISCO_INFO) => {
            let node = payload.attr("node").map(str::to_owned);
            let result: Element = disco_info(node).into();
            Some(Iq::Result {
                from: None,
                to: from,
                id,
                payload: Some(result),
            })
        }
        Iq::Get { from, id, .. } | Iq::Set { from, id, .. } => Some(Iq::Error {
            from: None,
            to: from,
            id,
            error: StanzaError::new(ErrorType::Cancel, DefinedCondition::ServiceUnavailable, "en", ""),
            payload: None,
        }),
        Iq::Result { .. } | Iq::Error { .. } => None,
    }
}

impl Xmpp {
    pub fn send(&self, stanza: Stanza) {
        let _ = self.out.send(stanza);
    }

    async fn request(&self, set: bool, payload: Element) -> Result<Option<Element>, IqError> {
        let id = format!("iv{}", self.next_id.fetch_add(1, Ordering::Relaxed));
        let (tx, rx) = oneshot::channel();
        self.pending.lock().expect("очередь запросов").insert(id.clone(), tx);
        let iq = if set {
            Iq::Set {
                from: None,
                to: None,
                id: id.clone(),
                payload,
            }
        } else {
            Iq::Get {
                from: None,
                to: None,
                id: id.clone(),
                payload,
            }
        };
        self.send(Stanza::Iq(iq));
        let reply = tokio::time::timeout(IQ_TIMEOUT, rx).await;
        self.pending.lock().expect("очередь запросов").remove(&id);
        match reply {
            Ok(Ok(Iq::Result { payload, .. })) => Ok(payload),
            Ok(Ok(Iq::Error { error, .. })) => Err(IqError::Stanza(Box::new(error))),
            Ok(Ok(_) | Err(_)) => Err(IqError::Lost),
            Err(_) => Err(IqError::Timeout),
        }
    }

    /// Все элементы узла. Узла еще нет - элементов нет.
    pub async fn fetch(&self, node: &str) -> Result<Vec<RemoteItem>, IqError> {
        let payload = match self.request(false, items_request(node)).await {
            Ok(payload) => payload,
            Err(err) if err.is_item_not_found() => return Ok(Vec::new()),
            Err(err) => return Err(err),
        };
        Ok(payload
            .as_ref()
            .and_then(|p| p.get_child("items", NS_PUBSUB))
            .map(|items| {
                items
                    .children()
                    .filter(|c| c.is("item", NS_PUBSUB))
                    .filter_map(entry_of)
                    .collect()
            })
            .unwrap_or_default())
    }

    /// Публикация записи. Ok(None) - успех, Ok(Some(условие)) - отказ сервера.
    pub async fn publish(&self, node: &str, max_items: u32, item: &RemoteItem) -> Result<Option<String>, IqError> {
        let key = item.key_version.to_string();
        let entry = element("entry", NS_VAULT, &[("v", "1"), ("key", &key)])
            .append(item.ciphertext.as_str())
            .build();
        match self
            .request(true, publish_payload(node, &item.id, entry, max_items))
            .await
        {
            Ok(_) => Ok(None),
            Err(IqError::Stanza(e)) => Ok(Some(condition(&e))),
            Err(err) => Err(err),
        }
    }

    /// Лимит записей узла из его настроек (запрос владельца). Узла еще нет - None.
    pub async fn node_max_items(&self, node: &str) -> Result<Option<u32>, IqError> {
        let configure = element("configure", NS_OWNER, &[("node", node)]).build();
        let payload = element("pubsub", NS_OWNER, &[]).append(configure).build();
        match self.request(false, payload).await {
            Ok(payload) => Ok(payload.as_ref().and_then(max_items_of)),
            Err(err) if err.is_item_not_found() => Ok(None),
            Err(err) => Err(err),
        }
    }

    pub async fn configure(&self, node: &str, max_items: u32) -> Result<(), IqError> {
        let configure = element("configure", NS_OWNER, &[("node", node)])
            .append(form(
                "http://jabber.org/protocol/pubsub#node_config",
                &node_options(max_items),
            ))
            .build();
        let payload = element("pubsub", NS_OWNER, &[]).append(configure).build();
        self.request(true, payload).await.map(|_| ())
    }

    /// Учетная запись из узла PEP (JSON ядра) или None, если узла еще нет.
    pub async fn fetch_account(&self) -> Result<Option<String>, IqError> {
        let payload = match self.request(false, items_request(NS_ACCOUNT)).await {
            Ok(payload) => payload,
            Err(err) if err.is_item_not_found() => return Ok(None),
            Err(err) => return Err(err),
        };
        Ok(payload
            .as_ref()
            .and_then(|p| p.get_child("items", NS_PUBSUB))
            .and_then(|items| items.get_child("item", NS_PUBSUB))
            .and_then(|item| item.get_child("account", NS_ACCOUNT))
            .map(Element::text))
    }

    pub async fn publish_account(&self, json: &str) -> Result<(), IqError> {
        let account = element("account", NS_ACCOUNT, &[("v", "1")]).append(json).build();
        self.request(true, publish_payload(NS_ACCOUNT, "current", account, 1))
            .await
            .map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_address() {
        assert_eq!(Server::parse(None), Ok(Server::Srv));
        assert_eq!(Server::parse(Some(" ")), Ok(Server::Srv));
        assert_eq!(
            Server::parse(Some("xmpp.example.org")),
            Ok(Server::StartTls {
                host: "xmpp.example.org".into(),
                port: 5222
            })
        );
        assert_eq!(
            Server::parse(Some("xmpp.example.org:5223")),
            Ok(Server::StartTls {
                host: "xmpp.example.org".into(),
                port: 5223
            })
        );
        assert_eq!(
            Server::parse(Some("[2001:db8::1]:5222")),
            Ok(Server::StartTls {
                host: "2001:db8::1".into(),
                port: 5222
            })
        );
        assert_eq!(
            Server::parse(Some("tcp://127.0.0.1:15222")),
            Ok(Server::Plain("127.0.0.1:15222".parse().unwrap()))
        );
        assert!(Server::parse(Some("tcp://192.0.2.1:5222")).is_err());
        assert!(Server::parse(Some("tcp://localhost:5222")).is_err());
        assert!(Server::parse(Some("example.org:port")).is_err());
    }

    #[test]
    fn response_sender_is_checked() {
        let account: BareJid = "alice@vault.test".parse().unwrap();
        assert!(from_account(None, &account));
        assert!(from_account(Some(&"alice@vault.test".parse().unwrap()), &account));
        assert!(!from_account(Some(&"alice@vault.test/web".parse().unwrap()), &account));
        assert!(!from_account(Some(&"mallory@vault.test".parse().unwrap()), &account));
        assert!(!from_account(Some(&"vault.test".parse().unwrap()), &account));
    }

    #[test]
    fn notification_items() {
        let xml = "<message xmlns='jabber:client' from='alice@vault.test' type='headline'>\
            <event xmlns='http://jabber.org/protocol/pubsub#event'><items node='urn:inkvault:vault:0'>\
            <item id='0192a3f5-0000-7000-8000-000000000002'><entry xmlns='urn:inkvault:vault:0' v='1' key='1'>AAEC</entry></item>\
            <item id='broken'><entry xmlns='urn:inkvault:vault:0' v='1' key='x'>AAEC</entry></item>\
            </items></event></message>";
        let message = Message::try_from(xml.parse::<Element>().unwrap()).unwrap();
        let items = notified_items(&message, NS_VAULT);
        assert_eq!(
            items,
            vec![RemoteItem {
                id: "0192a3f5-0000-7000-8000-000000000002".into(),
                key_version: 1,
                ciphertext: "AAEC".into(),
            }]
        );
        assert!(notified_items(&message, NS_ACCOUNT).is_empty());
    }

    #[test]
    fn node_config_max_items() {
        // ответ Prosody на запрос настроек узла владельцем, сокращенный
        let xml = "<pubsub xmlns='http://jabber.org/protocol/pubsub#owner'><configure node='urn:inkvault:vault:0'>\
            <x xmlns='jabber:x:data' type='form'>\
            <field var='FORM_TYPE' type='hidden'><value>http://jabber.org/protocol/pubsub#node_config</value></field>\
            <field var='pubsub#max_items' type='text-single'><value>256</value></field>\
            <field var='pubsub#access_model' type='list-single'><value>whitelist</value></field>\
            </x></configure></pubsub>";
        assert_eq!(max_items_of(&xml.parse().unwrap()), Some(256));
        let no_limit = "<pubsub xmlns='http://jabber.org/protocol/pubsub#owner'><configure node='n'/></pubsub>";
        assert_eq!(max_items_of(&no_limit.parse().unwrap()), None);
    }

    #[test]
    fn publish_stanza_matches_web_format() {
        let item = RemoteItem {
            id: "id-1".into(),
            key_version: 2,
            ciphertext: "AAEC".into(),
        };
        let entry = element("entry", NS_VAULT, &[("v", "1"), ("key", "2")])
            .append(item.ciphertext.as_str())
            .build();
        let payload = publish_payload(NS_VAULT, &item.id, entry, 10000);
        let publish = payload.get_child("publish", NS_PUBSUB).unwrap();
        assert_eq!(publish.attr("node"), Some(NS_VAULT));
        let item_el = publish.get_child("item", NS_PUBSUB).unwrap();
        assert_eq!(entry_of(item_el), Some(item));
        let fields: Vec<(String, String)> = payload
            .get_child("publish-options", NS_PUBSUB)
            .unwrap()
            .get_child("x", NS_DATA)
            .unwrap()
            .children()
            .map(|f| {
                (
                    f.attr("var").unwrap().to_owned(),
                    f.get_child("value", NS_DATA).unwrap().text(),
                )
            })
            .collect();
        assert!(fields.contains(&("pubsub#max_items".into(), "10000".into())));
        assert!(fields.contains(&("pubsub#access_model".into(), "whitelist".into())));
    }

    #[test]
    fn disco_answer_echoes_node() {
        let query = "<iq xmlns='jabber:client' type='get' id='q1' from='vault.test'>\
            <query xmlns='http://jabber.org/protocol/disco#info' node='https://inkvault.dev/cli#abc'/></iq>";
        let iq = Iq::try_from(query.parse::<Element>().unwrap()).unwrap();
        let Some(Iq::Result {
            payload: Some(payload), ..
        }) = answer(iq)
        else {
            panic!("ожидался результат disco#info");
        };
        let info = DiscoInfoResult::try_from(payload).unwrap();
        assert_eq!(info.node.as_deref(), Some("https://inkvault.dev/cli#abc"));
        assert!(info.features.contains("urn:inkvault:vault:0+notify"));
    }
}
