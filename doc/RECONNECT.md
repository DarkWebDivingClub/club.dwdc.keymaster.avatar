# Reconnecting After Disconnection

This guide covers how to diagnose and fix a broken connection
between the KeyMaster phone app and the desktop Avatar.

## When You Need This Guide

- `ssh-add -l` returns "The agent has no identities"
- `gpg --clearsign` hangs or says "No secret key"
- The phone's Avatar card shows a red dot ("Disconnected")
- The laptop just woke from sleep or suspend
- You changed WiFi networks or connected/disconnected a VPN

## Check Connection Status

### On the phone

Open the KeyMaster app and look at the Avatar card:

| Status | Dot | Meaning |
|--------|-----|---------|
| Connected | Green | Working normally |
| Reconnecting... | Amber | Auto-reconnecting, wait 10-30 seconds |
| Disconnected | Red | Manual action needed |
| Not attached | None | No active session |

### On the desktop

```bash
# Check if the per-user API socket exists
ls -la /run/keymaster-avatar/api-$(id -u).sock

# Check system services
sudo systemctl status km-avatar

# Check user services
systemctl --user status km-ssh-sa km-gpg-sa km-nostr-sa

# Quick health check
ssh-add -l && \
  gpg --list-keys >/dev/null 2>&1 && \
  ls "$NOSTR_SA_SOCK" >/dev/null 2>&1 && \
  echo "All services OK" || echo "FAILED"
```

## After Sleep/Wake (Automatic)

The phone auto-reconnects after the laptop sleeps and wakes. This
is what you should see:

1. Wake the laptop (open the lid or press the power button)
2. The phone briefly shows "Reconnecting..." (amber dot)
3. Within 10-30 seconds, the phone shows "Connected" (green dot)
4. The phone vibrates briefly when the connection is restored
5. SSH and GPG work again without re-scanning the QR code

Verify:

```bash
ssh-add -l
echo "test" | gpg --clearsign
```

If the phone stays on "Reconnecting..." for more than 60 seconds,
continue with the manual steps below.

## Manual Reconnect -- Desktop Side

### Step 1: Restart the Avatar daemon

```bash
sudo systemctl restart km-avatar
```

Verify it started:

```bash
sudo systemctl status km-avatar
```

You should see `active (running)`. Check the descriptor:

```bash
cat /run/keymaster-avatar/descriptor.json
```

You should see JSON with `relay`, `login_xpub`, and `services`.

### Step 2: Restart the service avatars

```bash
systemctl --user restart km-ssh-sa km-gpg-sa km-nostr-sa
```

Verify:

```bash
systemctl --user status km-ssh-sa km-gpg-sa km-nostr-sa
```

All three should be `active (running)`.

## Manual Reconnect -- Phone Side

### If the Avatar card shows "Disconnected" or a stale session

1. Tap **Detach** to clear the stale session
2. On the desktop, display the QR code:

```bash
qrencode -t UTF8 < /run/keymaster-avatar/descriptor.json
```

3. On the phone, tap **Attach to Avatar**
4. Scan the QR code displayed in the terminal
5. Select your identity (e.g. `alice@atlanta.com`)
6. Tap **Attach**

You should see the Avatar card change to a green dot and
"Connected". The notification bar should show "Attached to relay".

### If using km-cli (host-based KeyMaster)

```bash
km-cli attach /run/keymaster-avatar/descriptor.json \
  --identity alice@atlanta.com --policy auto
```

You should see: `Attached. Session: <sessionId>`

## Verify After Reconnect

Run all three checks:

```bash
# SSH
ssh-add -l
# You should see: 256 SHA256:... alice@atlanta.com (ED25519)

# GPG
gpg --list-keys alice@atlanta.com
echo "test" | gpg --clearsign
# You should see -----BEGIN PGP SIGNED MESSAGE-----

# Nostr
ls -la $NOSTR_SA_SOCK
# The socket file should exist
```

Quick one-liner:

```bash
ssh-add -l && \
  gpg --list-keys alice@atlanta.com >/dev/null 2>&1 && \
  ls "$NOSTR_SA_SOCK" >/dev/null 2>&1 && \
  echo "All services OK" || echo "FAILED"
```

## Troubleshooting

### `ssh-add -l` prints "Could not open a connection"

`SSH_AUTH_SOCK` is not set or points to the wrong socket.

```bash
export SSH_AUTH_SOCK=$XDG_RUNTIME_DIR/keymaster-ssh-agent.sock
ssh-add -l
```

After logging out and back in, the variable is set automatically.

### `ssh-add -l` prints "The agent has no identities"

The SSH service avatar is running but no phone is attached.

1. Check the per-user API socket:

```bash
ls /run/keymaster-avatar/api-$(id -u).sock
```

2. If missing: re-attach from the phone (see above)
3. If present: restart the service avatar:

```bash
systemctl --user restart km-ssh-sa
```

### `gpg: signing failed: No secret key`

`GNUPGHOME` is not set or km-gpg-sa lost its connection.

```bash
export GNUPGHOME=$XDG_RUNTIME_DIR/gnupg-keymaster
gpg --list-keys
```

If the key list is empty:

```bash
systemctl --user restart km-gpg-sa
```

### Phone stays on "Reconnecting..." indefinitely

The phone cannot reach the relay. Check your connectivity method:

- **USB:** The ADB reverse mapping is lost after USB disconnect or
  phone reboot. Re-run:

```bash
adb reverse tcp:7777 tcp:7777
```

- **WiFi:** Verify the IP in `/etc/keymaster-avatar/avatar.toml`
  matches the desktop's current IP. If the IP changed, update the
  config and restart:

```bash
sudo systemctl restart km-avatar
# Then re-display QR and re-scan from phone
```

- **Firewall:** Make sure port 7777 is not blocked.

### `descriptor.json` is empty or missing

The Avatar daemon is not running or failed to start:

```bash
sudo systemctl restart km-avatar
journalctl -u km-avatar --no-pager -n 20
```

### Service avatar logs show "connection refused"

The per-user API socket has not been created yet. This happens when
no phone is attached. Attach from the phone first, then restart the
service avatars:

```bash
systemctl --user restart km-ssh-sa km-gpg-sa km-nostr-sa
```
