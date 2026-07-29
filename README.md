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

## Requirements

- Debian 13 (Trixie) or Ubuntu 24.04 (Noble) on amd64
- An Android phone running the KeyMaster app (see the
  [KeyMaster Android README](https://github.com/DarkWebDivingClub/club.dwdc.keymaster.android))
- Network path from phone to desktop (USB cable with ADB, or same
  WiFi network)
- `qrencode` for displaying the QR code the phone scans:

```bash
sudo apt install qrencode
```

## Install

### Option A: Install from `.deb` packages

If you have pre-built `.deb` files:

| Package | Provides | Description |
|---------|----------|-------------|
| `strfry` | strfry | Nostr relay (system service) |
| `keymaster-avatar` | keymaster-avatar, km-ssh-sa, km-gpg-sa, km-nostr-sa | Avatar daemon and service avatars |

```bash
sudo dpkg -i strfry_*.deb
sudo dpkg -i keymaster-avatar_*.deb
```

### Option B: Build from source

Install build dependencies:

```bash
sudo apt install build-essential pkg-config libssl-dev
```

Build the Avatar and service avatars:

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

Build and install strfry (the Nostr relay) separately:

```bash
git clone https://github.com/DarkWebDivingClub/strfry.git
cd strfry
make setup-golpe
make -j$(nproc)
sudo install -m 755 strfry /usr/local/bin/
```

When building from source, you will also need to create the systemd
unit files manually. See the `debian/` directory on the
`packaging/ubuntu/resolute` branch for reference.

### Verify

```bash
which keymaster-avatar km-ssh-sa km-gpg-sa km-nostr-sa
```

You should see four paths printed, one per line.

### Optional: host-based KeyMaster

If you want to run KeyMaster on the desktop instead of the phone
(for testing or development), also install these packages. They are
**not needed** when using the phone as your KeyMaster.

From `.deb` files:

| Package | Provides | Description |
|---------|----------|-------------|
| `keymaster-desktop` | km-daemon, km-cli | KeyMaster daemon and CLI |
| `keyvault-cli` | kv-cli | Seed management CLI |

```bash
sudo dpkg -i keymaster-desktop_*.deb
sudo dpkg -i keyvault-cli_*.deb
```

Or build from source:

```bash
git clone https://github.com/DarkWebDivingClub/club.dwdc.keymaster.git
cd club.dwdc.keymaster
mvn -pl club.dwdc.keymaster.cli,club.dwdc.keymaster.daemon,club.dwdc.keymaster.desktop \
  -am package -DskipTests

git clone https://github.com/DarkWebDivingClub/club.dwdc.keyvault.git
cd club.dwdc.keyvault
mvn -pl club.dwdc.keyvault.cli -am package -DskipTests
```

## Configure User Mapping

The Avatar needs to know which phone identities map to which Unix
users on the desktop. Edit `/etc/keymaster-avatar/users.toml`:

```bash
sudo tee /etc/keymaster-avatar/users.toml << 'EOF'
[[user]]
npub = "your-64-character-hex-public-key-here"
unix_user = "alice"
EOF
```

Replace `your-64-character-hex-public-key-here` with the hex public
key shown on the KeyMaster app's home screen. Tap the copy button
next to "Public Key (hex)" to copy it. Replace `alice` with your
Unix username.

You can add multiple `[[user]]` entries if several people use the
same machine.

## Configure Relay URL

The default relay URL is `ws://localhost:7777`. This works when the
phone reaches the desktop via USB (ADB reverse) because the phone's
`localhost` is forwarded to the desktop.

If the phone connects over WiFi instead, change the relay URL to
the desktop's LAN IP:

```bash
# Find the desktop's LAN IP
ip -4 addr show | grep 'inet ' | grep -v '127.0.0.1'

# Edit the avatar config (replace 192.168.1.42 with your actual IP)
sudo sed -i 's|ws://localhost:7777|ws://192.168.1.42:7777|' \
  /etc/keymaster-avatar/avatar.toml

# Restart the avatar to regenerate the descriptor
sudo systemctl restart km-avatar
```

## Enable System Services

Start the Nostr relay and the Avatar daemon:

```bash
sudo systemctl enable --now strfry
sudo systemctl enable --now km-avatar
```

Verify both are running:

```bash
sudo systemctl status strfry
sudo systemctl status km-avatar
```

You should see `active (running)` for both. Check that the Avatar
generated its descriptor:

```bash
cat /run/keymaster-avatar/descriptor.json
```

You should see JSON containing `relay`, `login_xpub`, and
`services` fields.

## Enable User Services

Start the three service avatars. These run as your user and connect
to the Avatar daemon:

```bash
systemctl --user enable --now km-ssh-sa
systemctl --user enable --now km-gpg-sa
systemctl --user enable --now km-nostr-sa
```

Verify all three are running:

```bash
systemctl --user status km-ssh-sa km-gpg-sa km-nostr-sa
```

You should see `active (running)` for all three. The service avatars
will wait for a phone to attach before they can handle requests.
This is normal.

## Connect the Phone

### Phone connectivity

The phone must be able to reach the Nostr relay running on the
desktop. Choose one of these methods.

#### Method A: USB via ADB reverse (recommended)

Connect the phone via USB cable with USB debugging enabled. Forward
the phone's `localhost:7777` to the desktop's relay:

```bash
adb reverse tcp:7777 tcp:7777
```

No config changes are needed — the descriptor's default
`ws://localhost:7777` works as-is on the phone.

The mapping is lost when the USB cable is disconnected or the phone
reboots. Re-run the `adb reverse` command to restore it.

#### Method B: Same WiFi network

If both devices are on the same WiFi network and you changed the
relay URL in `avatar.toml` (see "Configure Relay URL" above), no
further action is needed. Make sure the desktop's firewall allows
incoming connections on port 7777.

### Display the QR code

On the desktop, display the Avatar descriptor as a QR code:

```bash
qrencode -t UTF8 < /run/keymaster-avatar/descriptor.json
```

A QR code appears in the terminal.

### Attach from the phone

1. Open the **KeyMaster** app on the phone
2. Tap **Attach to Avatar** on the Avatar card
3. Point the camera at the QR code on the desktop
4. In the confirmation dialog, select your identity
   (e.g. `alice@atlanta.com`)
5. Tap **Attach**

You should see:
- On the phone: the Avatar card shows a green dot and "Connected".
  The notification bar shows "Attached to relay".
- On the desktop:

```bash
ls -la /run/keymaster-avatar/api-$(id -u).sock
```

You should see a socket file owned by your user with mode `0700`.

### Optional: attach from the host

If you installed `keymaster-desktop` and `keyvault-cli`, you can
run KeyMaster on the desktop instead of the phone. Import a seed
and create an identity first:

```bash
echo "your twelve or twenty-four word seed phrase here" | kv-cli seed import
km-cli identity create alice@atlanta.com
```

Then attach:

```bash
km-cli attach /run/keymaster-avatar/descriptor.json \
  --identity alice@atlanta.com --policy auto
```

You should see: `Attached. Session: <sessionId>`

## Set Environment Variables

The service avatars expose sockets that SSH and GPG clients need to
find. Set these in your current shell:

```bash
export SSH_AUTH_SOCK=$XDG_RUNTIME_DIR/keymaster-ssh-agent.sock
export GNUPGHOME=$XDG_RUNTIME_DIR/gnupg-keymaster
export NOSTR_SA_SOCK=$XDG_RUNTIME_DIR/keymaster-nostr-sa.sock
```

After logging out and back in, these are set automatically by
`/etc/profile.d/keymaster.sh` and
`/usr/lib/environment.d/50-keymaster.conf`. You only need the manual
`export` commands for your current terminal session.

## Verify SSH

```bash
ssh-add -l
```

You should see one or more lines like:

```
256 SHA256:xxxx alice@atlanta.com (ED25519)
```

To test a real SSH connection, export the public key and add it to
a remote host's `~/.ssh/authorized_keys`:

```bash
ssh-add -L > /tmp/keymaster-ssh.pub
cat /tmp/keymaster-ssh.pub
# Copy this key to the remote host's authorized_keys
```

## Verify GPG

List the GPG keys:

```bash
gpg --list-keys alice@atlanta.com
```

You should see a key with your identity's email address.

Test signing:

```bash
echo "test" | gpg --clearsign
```

You should see a PGP signed message:

```
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA512

test
-----BEGIN PGP SIGNATURE-----
...
-----END PGP SIGNATURE-----
```

## Verify Nostr

Check that the Nostr service avatar socket exists:

```bash
ls -la $NOSTR_SA_SOCK
```

You should see a socket file. To verify signing works, send a
`get_public_keys` request:

```bash
echo '{"jsonrpc":"2.0","method":"get_public_keys","params":{},"id":1}' | \
  python3 -c "
import socket, struct, sys, json
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect('$(echo $NOSTR_SA_SOCK)')
req = sys.stdin.read().encode()
s.sendall(struct.pack('>I', len(req)) + req)
n = struct.unpack('>I', s.recv(4))[0]
d = b''
while len(d) < n:
    d += s.recv(n - len(d))
print(json.dumps(json.loads(d), indent=2))
s.close()
"
```

You should see a JSON response with a `result` array containing
one or more 64-character hex public keys.

## Quick Health Check

Run this one-liner to check all three services:

```bash
ssh-add -l && \
  gpg --list-keys >/dev/null 2>&1 && \
  ls "$NOSTR_SA_SOCK" >/dev/null 2>&1 && \
  echo "All services OK" || echo "FAILED -- check service status"
```

If it prints `All services OK`, everything is working. If it prints
`FAILED`, see [Troubleshooting](#troubleshooting) below or the
[Reconnect Guide](doc/RECONNECT.md).

## Troubleshooting

### `ssh-add -l` prints "Could not open a connection"

`SSH_AUTH_SOCK` is not set or points to the wrong socket.

```bash
export SSH_AUTH_SOCK=$XDG_RUNTIME_DIR/keymaster-ssh-agent.sock
ssh-add -l
```

### `ssh-add -l` prints "The agent has no identities"

The SSH service avatar is running but no phone is attached.

1. Check that the per-user API socket exists:

```bash
ls /run/keymaster-avatar/api-$(id -u).sock
```

2. If missing, attach from the phone (see "Connect the Phone").
3. If present, restart the SSH service avatar:

```bash
systemctl --user restart km-ssh-sa
```

### `gpg: signing failed: No secret key`

`GNUPGHOME` is not set or km-gpg-sa is not connected.

```bash
export GNUPGHOME=$XDG_RUNTIME_DIR/gnupg-keymaster
gpg --list-keys
```

If the key list is empty, restart the GPG service avatar:

```bash
systemctl --user restart km-gpg-sa
```

### `descriptor.json` not found

The Avatar daemon is not running or failed to start.

```bash
sudo systemctl status km-avatar
journalctl -u km-avatar --no-pager -n 20
```

### Phone shows "Reconnecting..." for more than 60 seconds

The phone cannot reach the relay. Check your connectivity method:

- **USB:** Run `adb reverse tcp:7777 tcp:7777` again. The mapping
  is lost after USB disconnect or phone reboot.
- **WiFi:** Verify the desktop's IP has not changed. Check that port
  7777 is not blocked by a firewall.

See [doc/RECONNECT.md](doc/RECONNECT.md) for the full reconnection
procedure.

### Permission denied on the API socket

The hex public key in `users.toml` does not match the identity
attached from the phone. Copy the correct hex key from the
KeyMaster app and update `/etc/keymaster-avatar/users.toml`.

## Architecture

| Component | Type | Description |
|-----------|------|-------------|
| strfry | System service | Nostr relay on port 7777 |
| km-avatar | System service | Avatar daemon, per-user API sockets |
| km-ssh-sa | User service | SSH agent bridged to Avatar |
| km-gpg-sa | User service | GPG agent bridged to Avatar |
| km-nostr-sa | User service | Nostr signing bridged to Avatar |
| km-daemon | User service | KeyMaster daemon (host-based only) |
| km-cli | CLI | Control the daemon (host-based only) |

See [doc/deployment-sequence.md](doc/deployment-sequence.md) for
a sequence diagram of the attach flow.

## Development

This is a Rust workspace with the following crates:

| Crate | Binary | Description |
|-------|--------|-------------|
| avatar | keymaster-avatar | Avatar daemon |
| km-ssh-sa | km-ssh-sa | SSH service avatar |
| km-gpg-sa | km-gpg-sa | GPG service avatar |
| km-nostr-sa | km-nostr-sa | Nostr service avatar |
| avatar-protocol | (library) | Shared protocol types |
| scd-shim | scd-shim | Smartcard daemon shim for GPG |
| pkcs11-gpg | (library) | PKCS#11 module for GPG |
| km-nostr-client | (library) | Nostr client library |

Build:

```bash
cargo build
cargo test
```

For `.deb` packaging, see the `packaging/ubuntu/resolute` branch.

## License

This project is licensed under the GNU General Public License v3.0
only (`GPL-3.0-only`). See [LICENSE](LICENSE).
