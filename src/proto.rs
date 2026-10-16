//! Протокол между командами CLI и агентом: одна строка JSON с запросом и одна с ответом.
//! Агент запускается командой, которая передает ему пароли строкой `Start` через stdin.

use std::collections::BTreeMap;

use inkvault_core::sync::ImportStats;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

pub const NAME: &str = "name";
pub const URL: &str = "url";
pub const USERNAME: &str = "username";
pub const PASSWORD: &str = "password";
pub const TOTP: &str = "totp";
pub const NOTES: &str = "notes";
pub const PASSWORD_MODE: &str = "password_mode";
/// Пароль вида PIN + текущий код TOTP: PIN хранится в поле password.
pub const PIN_TOTP: &str = "pin_totp";
/// Самый большой файл экспорта, как в web- и Android-клиентах.
pub const MAX_FILE: usize = 64 * 1024 * 1024;
/// Самая длинная строка запроса или ответа: файл экспорта и остальной JSON. Защита от бесконечной
/// строки в сокете.
pub const MAX_LINE: usize = MAX_FILE + 64 * 1024;

#[derive(Serialize, Deserialize)]
pub struct Start {
    pub master_password: Zeroizing<String>,
    /// Блокировка после стольких минут без запросов, 0 - без блокировки по времени.
    pub timeout_min: u64,
    pub login: Option<Login>,
}

#[derive(Serialize, Deserialize)]
pub struct Login {
    pub jid: String,
    pub server: Option<String>,
    pub xmpp_password: Zeroizing<String>,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum Request {
    Status,
    List {
        query: Option<String>,
    },
    Find {
        query: String,
        user: Option<String>,
    },
    Sync,
    SetMaxItems {
        max_items: u32,
    },
    ChangePassword {
        current: Zeroizing<String>,
        new: Zeroizing<String>,
    },
    /// Новая запись: непустые поля и теги.
    Add {
        fields: BTreeMap<String, String>,
        tags: Vec<String>,
        sync: bool,
    },
    /// Изменения записи: пустое значение удаляет поле, false снимает тег.
    Edit {
        id: String,
        fields: BTreeMap<String, String>,
        tags: BTreeMap<String, bool>,
        sync: bool,
    },
    /// Перемещение записи в корзину.
    Delete {
        id: String,
        sync: bool,
    },
    /// Файл экспорта. master - пароль файла совпадает с мастер-паролем и проверяется.
    Export {
        password: Zeroizing<String>,
        master: bool,
    },
    Import {
        file: String,
        password: Zeroizing<String>,
        sync: bool,
    },
    Lock,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Reply {
    Status(Status),
    List(Vec<Entry>),
    Entry(Entry),
    Saved(Saved),
    File(String),
    Imported(Imported),
    Done,
    Error(String),
}

/// Изменение записи сохранено на устройстве. С sync в запросе неотправленное изменение - ошибка,
/// без него pending показывает, что изменение еще не отправлено на сервер.
#[derive(Debug, Serialize, Deserialize)]
pub struct Saved {
    pub id: String,
    pub pending: bool,
}

/// Итог импорта. pending - как в `Saved`.
#[derive(Debug, Serialize, Deserialize)]
pub struct Imported {
    pub stats: ImportStats,
    pub pending: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub id: String,
    pub fields: BTreeMap<String, String>,
    pub tags: Vec<String>,
}

impl Entry {
    pub fn field(&self, name: &str) -> &str {
        self.fields.get(name).map(String::as_str).unwrap_or_default()
    }

    /// Запись для списка: без пароля, секрета TOTP и заметки.
    pub fn public(mut self) -> Self {
        self.fields
            .retain(|name, _| [NAME, URL, USERNAME].contains(&name.as_str()));
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", content = "detail", rename_all = "snake_case")]
pub enum Connection {
    Connecting,
    Online,
    /// Нет связи с сервером, агент повторяет попытки. Текст - причина последней неудачи.
    Offline(Option<String>),
    /// На сервере чужая учетная запись: синхронизация остановлена до решения пользователя.
    Conflict,
    /// Вход невозможен, повторов нет.
    Failed(String),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Status {
    pub jid: String,
    pub connection: Connection,
    pub records: usize,
    pub pending: usize,
    /// Лимит записей узла на сервере, корзина входит в него.
    pub max_items: u32,
    pub synced_ago_s: Option<u64>,
    pub lock_in_s: Option<u64>,
    pub notices: Vec<String>,
}

fn contains(haystack: &str, needle_lower: &str) -> bool {
    haystack.to_lowercase().contains(needle_lower)
}

/// Записи для списка: часть названия, адреса, логина или тега.
pub fn filter(entries: Vec<Entry>, query: Option<&str>) -> Vec<Entry> {
    let Some(query) = query.map(str::to_lowercase).filter(|q| !q.is_empty()) else {
        return entries;
    };
    entries
        .into_iter()
        .filter(|e| {
            [NAME, URL, USERNAME].iter().any(|f| contains(e.field(f), &query))
                || e.tags.iter().any(|t| contains(t, &query))
        })
        .collect()
}

/// Одна запись по запросу: id, точное название без учета регистра или единственное совпадение по
/// части названия или адреса. Несколько совпадений - ошибка: скрипт не должен получить пароль
/// от другой записи.
pub fn find<'a>(entries: &'a [Entry], query: &str, user: Option<&str>) -> Result<&'a Entry, String> {
    let candidates: Vec<&Entry> = entries
        .iter()
        .filter(|e| user.is_none_or(|u| e.field(USERNAME) == u))
        .collect();
    if let Some(entry) = candidates.iter().find(|e| e.id == query) {
        return Ok(entry);
    }
    let query_lower = query.to_lowercase();
    let exact: Vec<&Entry> = candidates
        .iter()
        .copied()
        .filter(|e| e.field(NAME).to_lowercase() == query_lower)
        .collect();
    let found = if exact.is_empty() {
        candidates
            .into_iter()
            .filter(|e| contains(e.field(NAME), &query_lower) || contains(e.field(URL), &query_lower))
            .collect()
    } else {
        exact
    };
    match found.as_slice() {
        [one] => Ok(one),
        [] => Err(tr!("item not found: {query}", "запись не найдена: {query}")),
        many => {
            let list: Vec<String> = many
                .iter()
                .take(10)
                .map(|e| format!("  {} ({}) {}", e.field(NAME), e.field(USERNAME), e.id))
                .collect();
            Err(tr!(
                "items matching {query:?}: {}, refine the name or specify --user\n{}",
                "под запрос {query:?} подходит записей: {}, уточните название или укажите --user\n{}",
                many.len(),
                list.join("\n")
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(id: &str, name: &str, username: &str, url: &str) -> Entry {
        Entry {
            id: id.into(),
            fields: [(NAME, name), (USERNAME, username), (URL, url)]
                .into_iter()
                .map(|(k, v)| (k.to_owned(), v.to_owned()))
                .collect(),
            tags: vec!["работа/серверы".into()],
        }
    }

    fn sample() -> Vec<Entry> {
        vec![
            entry("1", "github.com", "alice", "https://github.com"),
            entry("2", "GitHub Enterprise", "alice", "https://git.corp"),
            entry("3", "prod-db", "postgres", ""),
            entry("4", "prod-db", "readonly", ""),
        ]
    }

    #[test]
    fn exact_name_wins_over_substring() {
        let entries = sample();
        assert_eq!(find(&entries, "GITHUB.COM", None).unwrap().id, "1");
        assert_eq!(find(&entries, "enterprise", None).unwrap().id, "2");
        assert_eq!(find(&entries, "git.corp", None).unwrap().id, "2");
        assert_eq!(find(&entries, "3", None).unwrap().id, "3");
    }

    #[test]
    fn ambiguous_and_missing_are_errors() {
        let entries = sample();
        let err = find(&entries, "prod-db", None).unwrap_err();
        assert!(err.contains("\"prod-db\": 2"), "{err}");
        assert!(find(&entries, "github", None).is_err());
        assert!(
            find(&entries, "gitlab", None)
                .unwrap_err()
                .starts_with("item not found")
        );
        assert_eq!(find(&entries, "prod-db", Some("readonly")).unwrap().id, "4");
        assert!(find(&entries, "prod-db", Some("nobody")).is_err());
    }

    #[test]
    fn filter_by_any_visible_field() {
        assert_eq!(filter(sample(), Some("POSTGRES")).len(), 1);
        assert_eq!(filter(sample(), Some("серверы")).len(), 4);
        assert_eq!(filter(sample(), Some("")).len(), 4);
        assert_eq!(filter(sample(), None).len(), 4);
    }

    #[test]
    fn public_entry_has_no_secrets() {
        let mut full = entry("1", "github.com", "alice", "https://github.com");
        full.fields.insert(PASSWORD.into(), "pw".into());
        full.fields.insert(TOTP.into(), "JBSWY3DPEHPK3PXP".into());
        let public = full.clone().public();
        assert_eq!(public.fields.len(), 3);
        assert_eq!(public.field(PASSWORD), "");
        assert_eq!(public.field(TOTP), "");
        assert_eq!(public.field(USERNAME), "alice");
    }

    #[test]
    fn request_wire_format() {
        let json = serde_json::to_string(&Request::Find {
            query: "github".into(),
            user: None,
        })
        .unwrap();
        assert_eq!(json, r#"{"cmd":"find","query":"github","user":null}"#);
        assert_eq!(
            serde_json::from_str::<Request>(r#"{"cmd":"lock"}"#).unwrap(),
            Request::Lock
        );
    }
}
