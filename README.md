# KeyMaster Avatar

The Avatar is the desktop-side component of KeyMaster. It bridges
SSH, GPG, and Nostr signing to your phone over a Nostr relay. Desktop
applications talk to local service avatars, which forward
cryptographic operations through the relay to the KeyMaster app on
your phone, where the private keys live. Your keys never leave the
phone.

```
+-----------+    +------------+    +-----------+    +----------+
| Desktop   |--->| Service    |--->| km-avatar |--->| Nostr    |
| apps      |    | avatars    |    |           |    | relay    |
| (ssh,gpg) |    | (km-ssh-sa |    | (system   |    | (strfry) |
|           |    |  km-gpg-sa |    |  service) |    |          |
|           |    |  km-nostr- |    |           |    |          |
|           |    |  sa)       |    |           |    |          |
+-----------+    +------------+    +-----------+    +----+-----+
                                                        |
                                                    network
                                                        |
                                                   +----+-----+
                                                   | KeyMaster|
                                                   | Android  |
                                                   | app      |
                                                   | (phone)  |
                                                   +----------+
```

## Components

| Component | Type | Description |
|-----------|------|-------------|
| strfry | System service | Nostr relay on port 7777 |
| km-avatar | System service | Avatar daemon, per-user API sockets |
| km-ssh-sa | User service | SSH agent bridged to Avatar |
| km-gpg-sa | User service | GPG agent bridged to Avatar |
| km-nostr-sa | User service | Nostr signing bridged to Avatar |

## Getting Started

- **[Getting Started — Newbie](getting-started-newbi.md)** —
  Install, configure, connect your phone, and verify everything
  works. Start here.
- **[Getting Started — Developer](getting-started-developer.md)** —
  Build from source, crate structure, packaging.
- **[Reconnect Guide](doc/RECONNECT.md)** — Diagnose and fix
  broken connections after sleep, travel, or network changes.
- **[KeyMaster Android](https://github.com/DarkWebDivingClub/club.dwdc.keymaster.android)** —
  The phone app (needed for the phone-as-signer setup).

## License

This project is licensed under the GNU General Public License v3.0
only (`GPL-3.0-only`). See [LICENSE](LICENSE).
