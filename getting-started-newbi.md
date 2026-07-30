# Getting Started with KeyMaster Avatar

KeyMaster Avatar lets desktop applications (SSH, GPG, Git, Nostr
clients) use cryptographic keys stored on your phone. The phone
holds the private keys and signs remotely — nothing secret is ever
stored on the desktop.

You can also run KeyMaster on the desktop itself (without a phone)
using `keymaster-desktop`. This guide focuses on the phone-based
setup. The host-based option is covered at the end.

This guide takes you from a fresh install to working SSH, GPG, and
Nostr signing.

## 1. Requirements

- Debian 13 (Trixie) or Ubuntu 24.04 (Noble) on amd64
- An Android phone with the KeyMaster app installed and configured
  (see [Getting Started with KeyMaster Android](https://github.com/DarkWebDivingClub/club.dwdc.keymaster.android/blob/master/getting-started-newbi.md))
- Phone and desktop on the same WiFi network

Install `qrencode` for displaying the QR code the phone scans:

```bash
sudo apt install qrencode
```

## 2. Add the APT repository

```bash
curl -fsSL https://apt.dwdc.club/dwdc-apt-repo.gpg \
  | sudo tee /usr/share/keyrings/dwdc-apt.gpg > /dev/null

echo "deb [signed-by=/usr/share/keyrings/dwdc-apt.gpg] https://apt.dwdc.club resolute alfa" \
  | sudo tee /etc/apt/sources.list.d/dwdc.list

sudo apt update
```

## 3. Install

```bash
sudo apt install strfry keymaster-avatar
```

If the packages are not yet available in the APT repository,
install from `.deb` files instead:

```bash
sudo dpkg -i strfry_*.deb
sudo dpkg -i keymaster-avatar_*.deb
```

Verify the binaries are installed:

```bash
which keymaster-avatar km-ssh-sa km-gpg-sa km-nostr-sa
```

You should see four paths printed, one per line.

## 4. Configure user mapping

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

## 5. Configure relay URL

The default relay URL is `ws://localhost:7777`. Change it to the
desktop's WiFi IP so the phone can reach the relay:

```bash
# Find the desktop's WiFi IP
ip -4 addr show | grep 'inet ' | grep -v '127.0.0.1'

# Update avatar config (replace 192.168.1.42 with your IP)
sudo sed -i 's|ws://.*:7777|ws://192.168.1.42:7777|' \
  /etc/keymaster-avatar/avatar.toml
```

Make sure the firewall allows incoming connections on port 7777.

## 6. Enable system services

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
The relay URL should match the IP you configured.

## 7. Enable user services

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

## 8. Set up the phone

If you have not yet installed and configured the KeyMaster Android
app, follow the
[Getting Started with KeyMaster Android](https://github.com/DarkWebDivingClub/club.dwdc.keymaster.android/blob/master/getting-started-newbi.md)
guide to:

1. Install the app
2. Generate or import a BIP-39 seed phrase
3. Create an identity (e.g. `alice@atlanta.com`)

Come back here once the app is running and shows your identity on
the home screen.

## 9. Connect the phone

Display the QR code on the desktop:

```bash
qrencode -t UTF8 < /run/keymaster-avatar/descriptor.json
```

On the phone:

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
```

You should see a socket file owned by your user.

## 10. Set environment variables

```bash
export SSH_AUTH_SOCK=$XDG_RUNTIME_DIR/keymaster-ssh-agent.sock
export GNUPGHOME=$XDG_RUNTIME_DIR/gnupg-keymaster
export NOSTR_SA_SOCK=$XDG_RUNTIME_DIR/keymaster-nostr-sa.sock
```

After logging out and back in, these are set automatically. You
only need the manual `export` for your current terminal session.

## 11. Verify SSH

```bash
ssh-add -l
```

You should see:

```
256 SHA256:xxxx alice@atlanta.com (ED25519)
```

## 12. Verify GPG

```bash
gpg --list-keys alice@atlanta.com
echo "test" | gpg --clearsign
```

You should see a PGP signed message.

## 13. Verify Nostr

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

## Optional: host-based KeyMaster

Instead of using the phone, you can run KeyMaster directly on the
desktop. Install the additional packages:

```bash
sudo apt install keymaster-desktop keyvault-cli
```

Or from `.deb` files:

```bash
sudo dpkg -i keymaster-desktop_*.deb
sudo dpkg -i keyvault-cli_*.deb
```

Enable the daemon, import a seed, create an identity, and attach:

```bash
systemctl --user enable --now km-daemon
echo "your twenty-four word seed phrase here" | kv-cli seed import
km-cli identity create alice@atlanta.com
km-cli attach /run/keymaster-avatar/descriptor.json \
  --identity alice@atlanta.com --policy auto
```

You should see: `Attached. Session: <sessionId>`

Then continue with step 10 (environment variables) and the
verification steps.

## Troubleshooting

| Problem | Fix |
|---------|-----|
| `ssh-add -l` says "Could not open a connection" | `export SSH_AUTH_SOCK=$XDG_RUNTIME_DIR/keymaster-ssh-agent.sock` |
| `ssh-add -l` says "no identities" | Phone not attached. Re-scan QR and attach. |
| `gpg: No secret key` | `export GNUPGHOME=$XDG_RUNTIME_DIR/gnupg-keymaster` and restart km-gpg-sa |
| `descriptor.json` not found | `sudo systemctl restart km-avatar` |
| Phone stuck on "Reconnecting..." | Check that the desktop's WiFi IP has not changed. Check firewall on port 7777. |
| Permission denied on API socket | npub in `users.toml` does not match the phone's identity |

See [doc/RECONNECT.md](doc/RECONNECT.md) for the full reconnection
procedure after sleep or network changes.
