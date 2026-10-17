# InkVault CLI

[Русская версия](README.ru.md)

Terminal client for InkVault, a self-hosted password manager with end-to-end encryption and sync over XMPP.

The vault lives on your own XMPP server (for example, Prosody) in the PEP nodes of your account. The server stores only ciphertext, and the master password never leaves the device. The web and Android clients use the same format, so records added in the terminal show up on other devices right away.

The client is made for the terminal and for scripts: passwords go to stdout, lists come as a table or JSON, and secrets are read from stdin.

## Features

- An agent in the style of ssh-agent: run `inkvault unlock` once, and commands work without the master password until the vault is locked.
- Reading, adding, editing and deleting records, tags and favorites.
- TOTP codes and PIN + one-time code passwords.
- Password generator.
- Encrypted export and import, compatible with the web and Android clients.
- Offline mode: records are read from an encrypted cache, and changes are sent once the connection is back.
- Master password change.
- Viewing and changing the record limit of the vault node on the server.
- Messages and help in English and Russian. The language comes from the first non-empty variable of `LC_ALL`, `LC_MESSAGES`, `LANG`: Russian for a `ru` locale (for example, `ru_RU.UTF-8`), English for anything else. The built-in argument parser texts (`Usage`, `error:`) are always in English.

Linux and macOS are supported. Windows is not: the agent needs a unix socket.

## Installation

Prebuilt binaries for Linux x86_64 and aarch64 are on the [releases](https://github.com/tzx1z/inkvault-cli/releases) page. The binaries are statically linked with musl and run on any distribution. Download the archive for your architecture and `SHA256SUMS`, check the archive and put `inkvault` into a directory on `PATH`:

```sh
sha256sum --ignore-missing -c SHA256SUMS
tar -xzf inkvault-cli-<version>-x86_64-unknown-linux-musl.tar.gz
install -m 755 inkvault-cli-<version>-x86_64-unknown-linux-musl/inkvault ~/.local/bin/
```

On macOS and other platforms, install from [crates.io](https://crates.io/crates/inkvault-cli) (Rust 1.85 or newer):

```sh
cargo install --locked inkvault-cli
```

## Getting started

A vault is created in the web or Android client. The CLI signs in to an existing vault.

```sh
inkvault login alice@example.org     # XMPP password and master password are entered in the terminal
inkvault ls                          # list of records
inkvault get github.com              # record password to stdout
inkvault get github.com -f username  # another field
inkvault otp github.com              # current TOTP code
inkvault lock                        # unload the keys from memory
```

If the vault is locked and a terminal is available, any command asks for the master password and starts the agent. Without a terminal the command fails.

The server address comes from the SRV record of the JID domain. A different address is set at login: `inkvault login alice@example.org --server xmpp.example.org:5222`. The connection uses STARTTLS.

## Examples

```sh
# copy a password to the clipboard
inkvault get github.com | wl-copy

# new record with a generated 32-character password, a tag and the favorite flag
inkvault add gitlab.com --username alice --url https://gitlab.com -g -l 32 -t work/git --favorite

# record with the password from stdin, for example in a script
printf '%s\n' "$DB_PASSWORD" | inkvault add prod-db --username postgres --password-stdin --sync

# PIN + code password: get returns the PIN together with the current code
inkvault add vpn --username bob --pin-totp

# edit: new username, remove a tag, generate a new password
inkvault edit gitlab.com --username alice2 --untag work/git -g

# several records with the same name: pick one by username
inkvault get mail.example.org -u bob

# move to trash without confirmation
inkvault rm old-site --force

# backup encrypted with a separate password
inkvault export > backup-$(date +%F).ivx
inkvault export | rclone rcat remote:inkvault/backup-$(date +%F).ivx

# import: records are merged into the vault, newer edits are kept
inkvault import backup-2026-10-15.ivx
rclone cat remote:inkvault/backup.ivx | inkvault import

# agent state for scripts
inkvault status --json

# password without a vault
inkvault gen -l 24 --no-symbols --avoid-ambiguous

# node record limit: show it, then raise it after increasing pep_max_items on the server
inkvault max-items
inkvault max-items 10000
```

## Commands

| Command | Action |
|---------|--------|
| `login JID` | sign in on this device |
| `unlock` | unlock the vault, the agent keeps the keys in memory |
| `lock` | lock the vault |
| `logout` | lock and delete the device data: login, XMPP password and cache |
| `status` | account (JID), agent and connection state |
| `ls [QUERY]` | list of records without passwords, filtered by name, URL, username or tag |
| `get QUERY` | field value, the password by default; `--json` prints the whole record |
| `otp QUERY` | current TOTP code |
| `add NAME` | add a record and print its id |
| `edit QUERY` | edit a record |
| `rm QUERY` | move a record to the trash |
| `export` | encrypted export file to stdout |
| `import [FILE]` | import an export file, from stdin without a file |
| `sync` | reload the records from the server |
| `max-items [N]` | record limit of the vault node, with `N` - change it |
| `passwd` | change the master password |
| `gen` | generate a password |

Details on options: `inkvault --help` and `inkvault COMMAND --help`.

A record is selected by id, by exact name or by a single match with part of the name or URL. If several records match, the command fails and asks to narrow it down by username with `-u`.

Options shared by commands:

- `--password-stdin` - read passwords and secrets from stdin, one per line.
- `--sync` - wait until the change is sent to the server. Without a connection, a change with `--sync` is not saved and the command fails.
- `--force` - skip a check or confirmation that would otherwise stop the command.
- `--json` - JSON output.

## Security

- The master password and record passwords are never passed as command line arguments, since arguments are visible in the process list. They are entered in the terminal or read from stdin.
- The agent listens on a unix socket in `$XDG_RUNTIME_DIR/inkvault`: the directory is 0700, the socket is 0600, and the peer uid is checked.
- The agent locks the vault after 15 minutes without requests (`--timeout` of `unlock` and `login`, 0 means only by `lock`) and on SIGTERM.
- The XMPP password is stored on the device encrypted with the vault key: it cannot be read without the master password.
- Login uses SCRAM, PLAIN only inside TLS. Without TLS (`--server tcp://127.0.0.1:port`) the client connects only to a loopback address, this mode is for the test server.
- Change notifications are accepted only from your own account.

## Data on the device

| Path | Contents |
|------|----------|
| `~/.local/share/inkvault` | login, encrypted XMPP password, copy of the account, encrypted record cache |
| `$XDG_RUNTIME_DIR/inkvault` | agent socket |

Another profile is selected with the `INKVAULT_HOME` variable. Files are written through a temporary file with mode 0600.

`login` and `logout` delete the cache together with unsent changes, so with such changes they require `--force`.

## Limitations

- A vault is created in the web or Android client.
- The trash is not shown in the CLI: restoring and emptying the trash are done in the web and Android clients.
- Login without SASL2 and FAST: the client stores the XMPP password (encrypted), not a token.
- If the master password was changed on another device, the CLI opens the vault with the old password until it connects to the server, then accepts the new account. The other option is to run `inkvault login` again.

## Server requirements

Prosody 13 or another XMPP server with PEP (XEP-0163) and `publish-options`.

The client works with the default Prosody settings: a new vault is created with a limit of 256 records, which is the default `pep_max_items`. Records in the trash count toward the limit. For vaults larger than 256 records, raise the limit on the server:

```lua
pep_max_items = 10000
```

After that, raise the vault node limit once from any client, for example `inkvault max-items 10000`. The other clients read the node limit from the server and follow it. The server rejects a limit above `pep_max_items`, and the client does not set a limit below the number of records: lowering it would make the server delete the oldest records.

## Development

```sh
git clone https://github.com/tzx1z/inkvault-cli.git
cd inkvault-cli
cargo build
cargo test
cargo fmt --check
python3 -I tools/licenses.py   # dependency licenses
```

The core is the [`inkvault-core`](https://crates.io/crates/inkvault-core) crate from crates.io. To build the CLI with a local copy of [inkvault-core](https://github.com/tzx1z/inkvault-core) next to it:

```sh
cargo build --config 'patch.crates-io.inkvault-core.path="../inkvault-core/core"'
```

Such a build rewrites the core entry in `Cargo.lock`, restore it with `git checkout Cargo.lock` before committing.

The end-to-end test runs the CLI against a test Prosody: the vault is created by the core Node tool `@inkov-dev/inkvault-testkit`, and the CLI works with it through the agent. The tool and the `registry.gitlab.com/inkvault/inkvault-core/test-prosody` image of the same version come from the private GitLab registries of `inkvault-core` and require a GitLab token: a personal access token with the `read_api` and `read_registry` scopes or a deploy token with the `read_package_registry` and `read_registry` scopes. Requires podman and Node.js 22:

```sh
podman login registry.gitlab.com                                          # once
npm config set -- //gitlab.com/api/v4/projects/inkvault%2Finkvault-core/packages/npm/:_authToken <token>    # once
(cd tests && npm ci)
tests/e2e.sh
```

### Release pipeline

Releases are built in GitLab CI (`.gitlab-ci.yml`), GitHub only receives the code and the binaries. Commits to `main` and merge requests run the format check, the tests and the license check. A `vX.Y.Z` tag runs:

1. `test`: checks that the tag matches the version in `Cargo.toml`, then the same checks as on `main`.
2. `binary-x86_64` and `binary-aarch64`: static release builds on the amd64 and arm64 GitLab runners, stored as `inkvault-cli-X.Y.Z-<target>.tar.gz` job artifacts with `inkvault`, `LICENSE` and `README.md`.
3. `publish-crates`: publishes `inkvault-cli` to crates.io with Trusted Publishing. A version that is already on crates.io is skipped.
4. `publish-github`: pushes the tagged commit to `main` and the tag to GitHub, then creates a GitHub release with the archives and `SHA256SUMS`. The release notes are the tag annotation. A rerun does not create a second release.

Settings:

- GitLab: `v*` tags are protected, since `GH_TOKEN` is protected.
- GitLab CI/CD variable `GH_TOKEN`, protected and masked: fine-grained GitHub token with Contents: read and write access to `tzx1z/inkvault-cli`. Without it the tag pipeline stops after `publish-crates`.
- crates.io, `inkvault-cli` settings - Trusted Publishing: GitLab, namespace `inkvault`, project `inkvault-cli`, workflow filepath `.gitlab-ci.yml`, no environment. The job gets a short-lived publish token over OIDC, no crates.io token is stored in GitLab. Trusted Publishing can only be configured for an existing crate, so the first version is published manually with `cargo publish`.

The GitHub `main` branch only moves forward to the tagged commit: if it has commits that are not in GitLab, the push is rejected.

## License

[GNU AGPL v3.0](LICENSE) (`AGPL-3.0-only`). Copyright (C) 2026 Evgeny Inkov.

## Contact

Evgeny Inkov: [me@inkov.dev](mailto:me@inkov.dev), XMPP [tzx1z@inkov.dev](xmpp:tzx1z@inkov.dev), [inkov.dev](https://inkov.dev)
