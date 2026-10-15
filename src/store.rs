//! Файлы CLI на устройстве. В учетной записи только соль и обернутые ключи, пароль XMPP и снимок
//! хранилища зашифрованы ключом из vault key: без мастер-пароля их не открыть.

use std::fs::{self, DirBuilder, OpenOptions};
use std::io::{ErrorKind, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

const CONFIG: &str = "config.json";
const ACCOUNT: &str = "account.json";
const XMPP_PASSWORD: &str = "xmpp-password";
const UNSENT: &str = "unsent";
const SNAPSHOT_EXT: &str = "snapshot";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub jid: String,
    /// Адрес сервера, если он не определяется по SRV домена JID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,
    /// Постоянный ресурс XMPP: перезапуски агента не плодят сессии на сервере.
    pub resource: String,
}

pub struct Store {
    pub dir: PathBuf,
    pub socket: PathBuf,
}

fn io_error(path: &Path, err: std::io::Error) -> String {
    format!("{}: {err}", path.display())
}

impl Store {
    /// INKVAULT_HOME задает отдельный профиль, например для тестов. Иначе данные в каталоге данных
    /// пользователя, сокет агента - в XDG_RUNTIME_DIR, если он есть.
    pub fn locate() -> Result<Self, String> {
        if let Some(home) = std::env::var_os("INKVAULT_HOME") {
            let dir = PathBuf::from(home);
            return Ok(Self {
                socket: dir.join("agent.sock"),
                dir,
            });
        }
        let dirs = directories::ProjectDirs::from("dev", "inkov", "inkvault")
            .ok_or("не удалось определить домашний каталог пользователя")?;
        let dir = dirs.data_dir().to_path_buf();
        let socket = dirs
            .runtime_dir()
            .map(|d| d.join("agent.sock"))
            .unwrap_or_else(|| dir.join("agent.sock"));
        Ok(Self { dir, socket })
    }

    pub fn ensure_dirs(&self) -> Result<(), String> {
        private_dir(&self.dir)?;
        if let Some(parent) = self.socket.parent() {
            private_dir(parent)?;
        }
        Ok(())
    }

    pub fn config(&self) -> Result<Option<Config>, String> {
        let path = self.dir.join(CONFIG);
        match fs::read(&path) {
            Ok(data) => serde_json::from_slice(&data)
                .map(Some)
                .map_err(|e| format!("{}: {e}", path.display())),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
            Err(e) => Err(io_error(&path, e)),
        }
    }

    pub fn save_config(&self, config: &Config) -> Result<(), String> {
        let json = serde_json::to_vec_pretty(config).expect("настройки сериализуются в JSON");
        write_private(&self.dir.join(CONFIG), &json)
    }

    pub fn account(&self) -> Result<String, String> {
        let path = self.dir.join(ACCOUNT);
        fs::read_to_string(&path).map_err(|e| io_error(&path, e))
    }

    pub fn save_account(&self, json: &str) -> Result<(), String> {
        write_private(&self.dir.join(ACCOUNT), json.as_bytes())
    }

    pub fn xmpp_password(&self) -> Result<Vec<u8>, String> {
        let path = self.dir.join(XMPP_PASSWORD);
        fs::read(&path).map_err(|e| io_error(&path, e))
    }

    pub fn save_xmpp_password(&self, sealed: &[u8]) -> Result<(), String> {
        write_private(&self.dir.join(XMPP_PASSWORD), sealed)
    }

    pub fn snapshot(&self, vault_id: &str) -> Option<Vec<u8>> {
        fs::read(self.snapshot_path(vault_id).ok()?).ok()
    }

    /// Снимок зашифрован ключом хранилища, а число неотправленных изменений записывается рядом
    /// открытым текстом: login и logout проверяют его без мастер-пароля.
    pub fn save_snapshot(&self, vault_id: &str, data: &[u8], unsent: usize) -> Result<(), String> {
        write_private(&self.snapshot_path(vault_id)?, data)?;
        match unsent {
            0 => remove(&self.dir.join(UNSENT)),
            n => write_private(&self.dir.join(UNSENT), n.to_string().as_bytes()),
        }
    }

    /// Изменения записей из снимка, которые еще не отправлены на сервер.
    pub fn unsent(&self) -> usize {
        fs::read_to_string(self.dir.join(UNSENT))
            .ok()
            .and_then(|count| count.trim().parse().ok())
            .unwrap_or(0)
    }

    // id хранилища приходит с сервера и становится именем файла
    fn snapshot_path(&self, vault_id: &str) -> Result<PathBuf, String> {
        if vault_id.is_empty() || !vault_id.chars().all(|c| c.is_ascii_hexdigit() || c == '-') {
            return Err(format!("недопустимый id хранилища: {vault_id:?}"));
        }
        Ok(self.dir.join(format!("{vault_id}.{SNAPSHOT_EXT}")))
    }

    pub fn clear_snapshots(&self) -> Result<(), String> {
        let entries = match fs::read_dir(&self.dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(io_error(&self.dir, e)),
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_some_and(|ext| ext == SNAPSHOT_EXT) {
                remove(&path)?;
            }
        }
        Ok(())
    }

    /// Удаляет все данные профиля: настройки, учетную запись, пароль XMPP и снимки.
    pub fn clear(&self) -> Result<(), String> {
        for name in [CONFIG, ACCOUNT, XMPP_PASSWORD, UNSENT] {
            remove(&self.dir.join(name))?;
        }
        self.clear_snapshots()
    }
}

fn remove(path: &Path) -> Result<(), String> {
    match fs::remove_file(path) {
        Err(e) if e.kind() != ErrorKind::NotFound => Err(io_error(path, e)),
        _ => Ok(()),
    }
}

fn private_dir(dir: &Path) -> Result<(), String> {
    DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .map_err(|e| io_error(dir, e))?;
    // каталог мог существовать раньше с более широкими правами
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).map_err(|e| io_error(dir, e))
}

/// Запись через временный файл: обрыв на середине не оставляет поврежденный файл.
fn write_private(path: &Path, data: &[u8]) -> Result<(), String> {
    let name = path.file_name().expect("путь к файлу").to_string_lossy();
    let tmp = path.with_file_name(format!("{name}.tmp"));
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)
        .map_err(|e| io_error(&tmp, e))?;
    file.write_all(data)
        .and_then(|_| file.sync_all())
        .map_err(|e| io_error(&tmp, e))?;
    fs::rename(&tmp, path).map_err(|e| io_error(path, e))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_store(name: &str) -> Store {
        let dir = std::env::temp_dir().join(format!("inkvault-cli-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        Store {
            socket: dir.join("agent.sock"),
            dir,
        }
    }

    #[test]
    fn files_are_private_and_cleared() {
        let store = temp_store("files");
        store.ensure_dirs().unwrap();
        let config = Config {
            jid: "alice@vault.test".into(),
            server: None,
            resource: "cli-0123abcd".into(),
        };
        store.save_config(&config).unwrap();
        store
            .save_snapshot("0192a3f4-0000-7000-8000-000000000001", b"x", 2)
            .unwrap();
        assert_eq!(store.config().unwrap(), Some(config));
        assert_eq!(store.unsent(), 2);
        store
            .save_snapshot("0192a3f4-0000-7000-8000-000000000001", b"x", 0)
            .unwrap();
        assert_eq!(store.unsent(), 0);
        let mode = fs::metadata(store.dir.join(CONFIG)).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        assert_eq!(fs::metadata(&store.dir).unwrap().permissions().mode() & 0o777, 0o700);
        store.clear().unwrap();
        assert_eq!(store.config().unwrap(), None);
        assert_eq!(store.unsent(), 0);
        assert!(store.snapshot("0192a3f4-0000-7000-8000-000000000001").is_none());
        fs::remove_dir_all(&store.dir).unwrap();
    }

    #[test]
    fn vault_id_cannot_escape_directory() {
        let store = temp_store("escape");
        assert!(store.save_snapshot("../config", b"x", 0).is_err());
        assert!(store.save_snapshot("", b"x", 0).is_err());
    }
}
