# Getting Started — Developer

This guide covers building KeyMaster Avatar from source, the crate
structure, and `.deb` packaging.

## Prerequisites

- Rust (stable, recent)
- System libraries:

```bash
sudo apt install build-essential pkg-config libssl-dev
```

## Build

```bash
git clone https://github.com/DarkWebDivingClub/club.dwdc.keymaster.avatar.git
cd club.dwdc.keymaster.avatar
cargo build --release
```

The binaries are in `target/release/`. Install them:

```bash
sudo install -t /usr/local/bin \
  target/release/keymaster-avatar \
  target/release/km-ssh-sa \
  target/release/km-gpg-sa \
  target/release/km-nostr-sa \
  target/release/scd-shim
```

## Build strfry (Nostr relay)

```bash
git clone https://github.com/DarkWebDivingClub/strfry.git
cd strfry
make setup-golpe
make -j$(nproc)
sudo install -m 755 strfry /usr/local/bin/
```

## Crate structure

This is a Rust workspace with the following crates:

| Crate | Binary | Description |
|-------|--------|-------------|
| avatar | keymaster-avatar | Avatar daemon — relay connection, session management, QR display |
| km-ssh-sa | km-ssh-sa | SSH service avatar — bridges SSH-agent protocol to Avatar |
| km-gpg-sa | km-gpg-sa | GPG service avatar — bridges Assuan protocol to Avatar |
| km-nostr-sa | km-nostr-sa | Nostr service avatar — bridges Nostr signing to Avatar |
| avatar-protocol | (library) | Shared protocol types, config loading, BIP-32 derivation |
| scd-shim | scd-shim | Smartcard daemon shim for GPG agent |
| pkcs11-gpg | (library) | PKCS#11 module for GPG |
| km-nostr-client | (library) | Typed Rust client for km-nostr-sa |

## Avatar seed and key derivation

The avatar generates a 32-byte seed on first startup and stores it
at `~/.config/keymaster-avatar/seed` (or `/var/lib/keymaster-avatar/seed`
under systemd). All transport keys are derived deterministically
from this seed using BIP-32:

```
Master seed (32 bytes)
└── m/0 — Login keys
    ├── Login xpriv/xpub (BIP-32 extended keys)
    └── Nostr transport identity (secp256k1)
```

The login xpub is included in the QR descriptor. Deleting the seed
file and restarting generates a new identity.

## Configuration

Three layers, in order of precedence:

1. CLI arguments (highest)
2. `~/.config/keymaster-avatar/<binary>.toml` (user config)
3. `/etc/keymaster-avatar/<binary>.toml` (system config)

Key config fields for `avatar.toml`:

```toml
relay = "ws://localhost:7777"
log_level = "info"
seed_file = "/var/lib/keymaster-avatar/seed"
local_api_socket = "/run/keymaster-avatar"
allowlist = "/etc/keymaster-avatar/allowlist"
service_avatar_dir = "/usr/lib/keymaster-avatar/bin"
users_file = "/etc/keymaster-avatar/users.toml"
descriptor_path = "/run/keymaster-avatar/descriptor.json"
```

## Systemd unit files

When building from source, create unit files manually. Reference
the `debian/` directory on the `packaging/ubuntu/resolute` branch.

Key systemd directives for `km-avatar.service`:

```ini
[Service]
RuntimeDirectory=keymaster-avatar   # /run/keymaster-avatar/ (transient)
StateDirectory=keymaster-avatar     # /var/lib/keymaster-avatar/ (persistent)
```

User services (`km-ssh-sa`, `km-gpg-sa`, `km-nostr-sa`) use
`$XDG_RUNTIME_DIR` for sockets.

## Optional: host-based KeyMaster

For testing without a phone, build the Java KeyMaster daemon and
KeyVault CLI:

```bash
# Requires JDK 21 and Maven
git clone https://github.com/DarkWebDivingClub/club.dwdc.keymaster.git
cd club.dwdc.keymaster
mvn -pl club.dwdc.keymaster.cli,club.dwdc.keymaster.daemon,club.dwdc.keymaster.desktop \
  -am package -DskipTests

git clone https://github.com/DarkWebDivingClub/club.dwdc.keyvault.git
cd club.dwdc.keyvault
mvn -pl club.dwdc.keyvault.cli -am package -DskipTests
```

## Building a `.deb`

The `packaging/ubuntu/resolute` branch carries Debian packaging on
top of master:

```bash
git checkout packaging/ubuntu/resolute
git merge master
dpkg-buildpackage -b -us -uc
```

The `.deb` lands in the parent directory.

## Protocol

Avatar and service avatars communicate over JSON-RPC 2.0 on Unix
sockets. Avatar communicates with KeyMaster (phone or host daemon)
over the Nostr relay using NIP-44 encryption (kind 23235 events).

See [doc/deployment-sequence.md](doc/deployment-sequence.md) for
a sequence diagram of the attach flow.

## Tests

```bash
cargo test
```

End-to-end tests are in a separate repository:

```bash
cd ~/git/club.dwdc.keymaster.e2etest
mvn test
```
