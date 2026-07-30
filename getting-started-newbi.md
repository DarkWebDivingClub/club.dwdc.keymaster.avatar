# Getting Started with KeyMaster Avatar

KeyMaster Avatar lets desktop applications (SSH, GPG, Git, Nostr
clients) use cryptographic keys stored on your phone. The phone
holds the private keys and signs remotely — nothing secret is ever
stored on the desktop.

This guide takes you from a fresh install to working SSH, GPG, and
Nostr signing.

## 1. Requirements

- Debian 13 (Trixie) or Ubuntu 24.04 (Noble) on amd64
- An Android phone with the KeyMaster app installed
  (see [KeyMaster Android](https://github.com/DarkWebDivingClub/club.dwdc.keymaster.android))
- A network path from phone to desktop (USB cable, WiFi, or
  remote tunnel)

Install `qrencode` for displaying the QR code the phone scans:

```bash
sudo apt install qrencode
```

## 2. Install

### From `.deb` packages

```bash
sudo dpkg -i strfry_*.deb
sudo dpkg -i keymaster-avatar_*.deb
```

### From source

See [Getting Started — Developer](getting-started-developer.md)
for build instructions.

### Verify

```bash
which keymaster-avatar km-ssh-sa km-gpg-sa km-nostr-sa
```

You should see four paths printed, one per line.

## 3. Configure user mapping

The Avatar maps phone identities to Unix users. Edit
`/etc/keymaster-avatar/users.toml`:

```bash
sudo tee /etc/keymaster-avatar/users.toml << 'EOF'
[[user]]
npub = "your-64-character-hex-public-key-here"
unix_user = "alice"
EOF
```

Replace the npub with the hex public key from the KeyMaster app's
home screen (tap the copy button next to "Public Key (hex)").
Replace `alice` with your Unix username.

## 4. Enable system services

```bash
sudo systemctl enable --now strfry
sudo systemctl enable --now km-avatar
```

Verify:

```bash
sudo systemctl status strfry km-avatar
```

You should see `active (running)` for both. Check the descriptor:

```bash
cat /run/keymaster-avatar/descriptor.json
```

You should see JSON with `relay`, `login_xpub`, and `services`.

## 5. Enable user services

```bash
systemctl --user enable --now km-ssh-sa
systemctl --user enable --now km-gpg-sa
systemctl --user enable --now km-nostr-sa
```

Verify:

```bash
systemctl --user status km-ssh-sa km-gpg-sa km-nostr-sa
```

All three should be `active (running)`. They will wait for a phone
to attach before handling requests — this is normal.

## 6. Connect the phone

The phone must reach the Nostr relay on the desktop. Choose the
method that matches your situation.

### At home or office — USB via ADB reverse

Connect the phone via USB with USB debugging enabled:

```bash
adb reverse tcp:7777 tcp:7777
```

The descriptor's default `ws://localhost:7777` works as-is. Re-run
this command after USB disconnect or phone reboot.

### At home or office — same WiFi

If both devices are on the same WiFi, set the relay URL to the
desktop's LAN IP:

```bash
# Find the desktop's LAN IP
ip -4 addr show | grep 'inet ' | grep -v '127.0.0.1'

# Update avatar config (replace 192.168.1.42 with your IP)
sudo sed -i 's|ws://.*:7777|ws://192.168.1.42:7777|' \
  /etc/keymaster-avatar/avatar.toml

# Restart to regenerate the descriptor
sudo systemctl restart km-avatar
```

Make sure the firewall allows incoming connections on port 7777.

### Traveling — phone on hotel/cafe WiFi

When you are away from home, the desktop's LAN IP changes with
every network. You have two options:

**Option A: USB cable (simplest).** Plug in the phone and run
`adb reverse tcp:7777 tcp:7777`. This always works regardless of
what network you are on.

**Option B: Expose the relay over an SSH tunnel.** If the phone
cannot be connected via USB, forward port 7777 through an SSH
tunnel to a server the phone can reach:

```bash
# From the desktop, forward local strfry to a remote server
ssh -R 7777:localhost:7777 you@your-server.example.com
```

Then create a modified QR code pointing at the server:

```bash
cat /run/keymaster-avatar/descriptor.json \
  | sed 's|ws://[^"]*|ws://your-server.example.com:7777|' \
  | qrencode -t UTF8
```

The server must allow inbound connections on port 7777. The tunnel
must stay open while the phone is attached.

### Display the QR code

```bash
qrencode -t UTF8 < /run/keymaster-avatar/descriptor.json
```

### Attach from the phone

1. Open the **KeyMaster** app
2. Tap **Attach to Avatar** on the Avatar card
3. Point the camera at the QR code
4. Select your identity (e.g. `alice@atlanta.com`)
5. Tap **Attach**

You should see:
- Phone: green dot and "Connected", notification "Attached to relay"
- Desktop:

```bash
ls -la /run/keymaster-avatar/api-$(id -u).sock
# Should show a socket file owned by your user
```

## 7. Set environment variables

```bash
export SSH_AUTH_SOCK=$XDG_RUNTIME_DIR/keymaster-ssh-agent.sock
export GNUPGHOME=$XDG_RUNTIME_DIR/gnupg-keymaster
export NOSTR_SA_SOCK=$XDG_RUNTIME_DIR/keymaster-nostr-sa.sock
```

After logging out and back in, these are set automatically. You
only need the manual `export` for your current terminal session.

## 8. Verify SSH

```bash
ssh-add -l
```

You should see:

```
256 SHA256:xxxx alice@atlanta.com (ED25519)
```

## 9. Verify GPG

```bash
gpg --list-keys alice@atlanta.com
echo "test" | gpg --clearsign
```

You should see a PGP signed message.

## 10. Verify Nostr

```bash
ls -la $NOSTR_SA_SOCK
```

The socket file should exist.

## Quick health check

```bash
ssh-add -l && \
  gpg --list-keys >/dev/null 2>&1 && \
  ls "$NOSTR_SA_SOCK" >/dev/null 2>&1 && \
  echo "All services OK" || echo "FAILED -- check service status"
```

## Reset the Avatar

### Light reset (keep keys, re-attach phone)

Restart services without losing the avatar's transport identity.
The phone must re-scan the QR code afterward.

```bash
sudo systemctl restart km-avatar
systemctl --user restart km-ssh-sa km-gpg-sa km-nostr-sa
```

Verify the descriptor was regenerated:

```bash
cat /run/keymaster-avatar/descriptor.json
```

Display the QR and re-attach from the phone:

```bash
qrencode -t UTF8 < /run/keymaster-avatar/descriptor.json
```

### Hard reset (new identity)

Delete the avatar's seed file to generate a fresh transport
identity. The avatar gets a new public key, so you must also
update `users.toml` with the new key if you use an allowlist.

```bash
# Stop everything
sudo systemctl stop km-avatar
systemctl --user stop km-ssh-sa km-gpg-sa km-nostr-sa

# Delete the seed (system service location)
sudo rm -f /var/lib/keymaster-avatar/seed

# Restart (a new seed is generated automatically)
sudo systemctl start km-avatar
systemctl --user start km-ssh-sa km-gpg-sa km-nostr-sa

# Display new QR and re-attach from phone
qrencode -t UTF8 < /run/keymaster-avatar/descriptor.json
```

### What gets reset

| Component | Light reset | Hard reset |
|-----------|:-----------:|:----------:|
| Avatar transport keypair | Same | New |
| Active sessions | Cleared | Cleared |
| Descriptor / QR code | Regenerated | Regenerated |
| Seed file | Kept | Deleted and regenerated |
| Config files | Kept | Kept |

## Troubleshooting

| Problem | Fix |
|---------|-----|
| `ssh-add -l` says "Could not open a connection" | `export SSH_AUTH_SOCK=$XDG_RUNTIME_DIR/keymaster-ssh-agent.sock` |
| `ssh-add -l` says "no identities" | Phone not attached. Re-scan QR and attach. |
| `gpg: No secret key` | `export GNUPGHOME=$XDG_RUNTIME_DIR/gnupg-keymaster` and restart km-gpg-sa |
| `descriptor.json` not found | `sudo systemctl restart km-avatar` |
| Phone stuck on "Reconnecting..." | USB: re-run `adb reverse tcp:7777 tcp:7777`. WiFi: check IP and firewall. |
| Permission denied on API socket | npub in `users.toml` does not match the phone's identity |

See [doc/RECONNECT.md](doc/RECONNECT.md) for the full reconnection
procedure after sleep, travel, or network changes.
