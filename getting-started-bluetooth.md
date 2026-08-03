# Getting Started with KeyMaster Avatar over Bluetooth PAN

This guide sets up KeyMaster Avatar using Bluetooth PAN instead of
WiFi. The phone connects to the laptop over a dedicated Bluetooth
network, leaving the laptop's WiFi free for internet (cafe hotspots,
etc.).

If you want the simpler WiFi setup, see
[getting-started-newbi.md](getting-started-newbi.md) instead.

## 1. Requirements

- Ubuntu 26.04 (Resolute) or Debian 13 (Trixie) on amd64
- A working Bluetooth adapter on the laptop
- An Android phone with the KeyMaster app installed and configured
  (see [Getting Started with KeyMaster Android](https://github.com/DarkWebDivingClub/club.dwdc.keymaster.android/blob/master/getting-started-newbi.md))
- Phone and laptop paired over Bluetooth

Known issue: Samsung S24 Ultra (Android 15, One UI 7) BT PAN is
broken — the phone never creates a usable `bt-pan` interface.
MediaTek-based phones work correctly.

Install prerequisites:

```bash
sudo apt install qrencode dnsmasq python3-dbus python3-gi
```

## 2. Add the APT repository

### Ubuntu 26.04 (Resolute)

```bash
curl -fsSL https://apt.dwdc.club/dwdc-apt-repo.gpg \
  | sudo tee /usr/share/keyrings/dwdc-apt.gpg > /dev/null

echo "deb [signed-by=/usr/share/keyrings/dwdc-apt.gpg] https://apt.dwdc.club resolute alfa" \
  | sudo tee /etc/apt/sources.list.d/dwdc.list

sudo apt update
```

### Debian 13 (Trixie)

```bash
curl -fsSL https://apt.dwdc.club/dwdc-apt-repo.gpg \
  | sudo tee /usr/share/keyrings/dwdc-apt.gpg > /dev/null

echo "deb [signed-by=/usr/share/keyrings/dwdc-apt.gpg] https://apt.dwdc.club trixie alfa" \
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

## 4. Set up Bluetooth PAN on the laptop

### 4a. Create the NAP script

Create `/usr/local/bin/bt-nap.py`:

```bash
sudo tee /usr/local/bin/bt-nap.py << 'PYEOF'
#!/usr/bin/env python3
"""Register BlueZ NAP profile with a dedicated bridge.

BlueZ 5.85 requires a valid bridge name when registering a NAP -- passing
an empty string causes bnep_add_to_bridge() to fail with ENODEV.

This script creates a bridge (bt-nap-br) with the PAN subnet IP, so
BlueZ can add bnep* interfaces as ports.  dnsmasq serves DHCP on the
bridge.
"""

import signal
import subprocess
import sys

import dbus
from gi.repository import GLib

BRIDGE = "bt-nap-br"
BRIDGE_IP = "10.44.0.1/24"


def ensure_bridge():
    """Create the bridge with IP if it doesn't exist."""
    rc = subprocess.call(
        ["ip", "link", "show", BRIDGE],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if rc != 0:
        subprocess.check_call(["ip", "link", "add", BRIDGE, "type", "bridge",
                                "stp_state", "0", "forward_delay", "0"])
        subprocess.check_call(["ip", "addr", "add", BRIDGE_IP, "dev", BRIDGE])
        subprocess.check_call(["ip", "link", "set", BRIDGE, "up"])
        print(f"Created bridge {BRIDGE} with {BRIDGE_IP}", flush=True)
    else:
        # Ensure IP and link are up
        subprocess.call(["ip", "addr", "add", BRIDGE_IP, "dev", BRIDGE],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.call(["ip", "link", "set", BRIDGE, "up"],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def remove_bridge():
    """Remove the bridge."""
    subprocess.call(
        ["ip", "link", "del", BRIDGE],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def main():
    ensure_bridge()

    bus = dbus.SystemBus()
    adapter = dbus.Interface(
        bus.get_object("org.bluez", "/org/bluez/hci0"),
        "org.bluez.NetworkServer1",
    )

    adapter.Register("nap", BRIDGE)
    print(f"NAP registered (bridge={BRIDGE})", flush=True)

    loop = GLib.MainLoop()

    def shutdown(signum, frame):
        print("Shutting down NAP", flush=True)
        try:
            adapter.Unregister("nap")
        except dbus.DBusException:
            pass
        remove_bridge()
        loop.quit()

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    loop.run()


if __name__ == "__main__":
    main()
PYEOF
sudo chmod +x /usr/local/bin/bt-nap.py
```

The script creates a bridge (`bt-nap-br`) with STP disabled and
zero forward delay, assigns 10.44.0.1/24, and registers it as the
BlueZ NAP. BlueZ 5.85 requires a valid bridge name — passing an
empty string fails with ENODEV.

### 4b. Create the systemd unit

```bash
sudo tee /etc/systemd/system/bt-nap.service << 'EOF'
[Unit]
Description=Bluetooth NAP (PAN on bnep0)
After=bluetooth.service
Requires=bluetooth.service

[Service]
Type=simple
ExecStart=/usr/local/bin/bt-nap.py
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
sudo systemctl daemon-reload
sudo systemctl enable --now bt-nap.service
```

Verify:

```bash
sudo systemctl status bt-nap.service
```

You should see "NAP registered (bridge=bt-nap-br)".

### 4c. Configure dnsmasq for DHCP

```bash
sudo tee /etc/dnsmasq.d/pan0.conf << 'EOF'
interface=bt-nap-br
bind-interfaces
dhcp-range=10.44.0.2,10.44.0.10,255.255.255.0,24h
dhcp-option=3,10.44.0.1
dhcp-option=6
port=0
except-interface=lo
EOF
sudo systemctl restart dnsmasq
sudo systemctl enable dnsmasq
```

Notes:
- `interface=bt-nap-br` scopes DHCP to the bridge interface
- `dhcp-option=3,10.44.0.1` sends a gateway -- Android requires
  this or it will not configure the interface
- `dhcp-option=6` sends empty DNS (no DNS over BT PAN)
- `port=0` disables DNS to avoid conflict with systemd-resolved

## 5. Pair the phone

Run a pairing agent on the laptop (accepts PIN confirmation
automatically):

```bash
sudo tee /tmp/bt-pair-agent.py << 'PYEOF'
#!/usr/bin/env python3
"""BlueZ pairing agent -- auto-accepts all requests."""
import dbus, dbus.service, dbus.mainloop.glib
from gi.repository import GLib

AGENT_PATH = "/test/agent"

class Agent(dbus.service.Object):
    @dbus.service.method("org.bluez.Agent1", in_signature="ou")
    def RequestConfirmation(self, device, passkey):
        print(f"Auto-accepting passkey {passkey:06d} for {device}")

    @dbus.service.method("org.bluez.Agent1", in_signature="os")
    def AuthorizeService(self, device, uuid):
        print(f"Authorizing service {uuid} for {device}")

    @dbus.service.method("org.bluez.Agent1", in_signature="o")
    def RequestAuthorization(self, device):
        print(f"Authorizing {device}")

    @dbus.service.method("org.bluez.Agent1", in_signature="")
    def Cancel(self):
        pass

    @dbus.service.method("org.bluez.Agent1", in_signature="")
    def Release(self):
        pass

dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
bus = dbus.SystemBus()
agent = Agent(bus, AGENT_PATH)
mgr = dbus.Interface(bus.get_object("org.bluez", "/org/bluez"),
                     "org.bluez.AgentManager1")
mgr.RegisterAgent(AGENT_PATH, "KeyboardDisplay")
mgr.RequestDefaultAgent(AGENT_PATH)
print("Agent running -- pair from phone now")
GLib.MainLoop().run()
PYEOF
python3 /tmp/bt-pair-agent.py
```

In another terminal, make the laptop discoverable:

```bash
bluetoothctl discoverable-timeout 0
bluetoothctl discoverable on
```

On the phone: Settings -> Bluetooth -> find your laptop -> pair.
Confirm the PIN on the phone (laptop auto-accepts).

After pairing, trust the phone and disable discoverable:

```bash
bluetoothctl trust <PHONE_MAC>
bluetoothctl discoverable off
```

You can stop the pairing agent with Ctrl-C. It is only needed
during initial pairing.

## 6. Connect the phone to BT PAN

On the phone: Settings -> Bluetooth -> your laptop (gear icon) ->
"Internet access" (Internetåtkomst) -> ON.

The phone **must** initiate the connection — do not use
`bluetoothctl connect` from the laptop (it fails with
`br-connection-create-socket` because it tries the phone's NAP
profile in the wrong direction).

Verify on the laptop:

```bash
ip addr show bt-nap-br            # should show inet 10.44.0.1/24
cat /var/lib/misc/dnsmasq.leases  # should show phone's MAC + IP
ping -c 3 10.44.0.x               # phone (check leases for actual IP)
```

**Always verify with ping.** The first BNEP session after pairing
can be one-directional — DHCP succeeds but ping fails. If this
happens, toggle "Internet access" off and on. The second session
works.

If dnsmasq was not running when the phone connected, restart it:

```bash
sudo systemctl restart dnsmasq
```

Then toggle "Internet access" off and on again on the phone.

## 7. Configure user mapping

Edit `/etc/keymaster-avatar/users.toml`:

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

## 8. Configure relay URL for BT PAN

The relay must listen on the BT PAN interface so the phone can
reach it. Set the relay URL to the BT PAN IP:

```bash
sudo sed -i 's|ws://.*:7777|ws://10.44.0.1:7777|' \
  /etc/keymaster-avatar/avatar.toml
```

Make sure strfry is configured to listen on 10.44.0.1 (or
0.0.0.0). Check `/etc/strfry.conf`:

```
relay {
    bind = "0.0.0.0"
    port = 7777
}
```

## 9. Enable system services

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

You should see JSON with `"relay": "ws://10.44.0.1:7777"`.

## 10. Enable user services

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

## 11. Connect the phone

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

## 12. Set environment variables

```bash
export SSH_AUTH_SOCK=$XDG_RUNTIME_DIR/keymaster-ssh-agent.sock
export GNUPGHOME=$XDG_RUNTIME_DIR/gnupg-keymaster
export NOSTR_SA_SOCK=$XDG_RUNTIME_DIR/keymaster-nostr-sa.sock
```

After logging out and back in, these are set automatically. You
only need the manual `export` for your current terminal session.

## 13. Verify SSH

```bash
ssh-add -l
```

You should see:

```
256 SHA256:xxxx alice@atlanta.com (ED25519)
```

## 14. Verify GPG

```bash
gpg --list-keys alice@atlanta.com
echo "test" | gpg --clearsign
```

You should see a PGP signed message.

## 15. Verify Nostr

```bash
ls -la $NOSTR_SA_SOCK
```

The socket file should exist.

## 16. Verify WiFi independence

Connect the laptop's WiFi to a different network (e.g. a cafe
hotspot). The BT PAN link stays up independently.

```bash
# Internet still works over WiFi
curl -s https://ifconfig.me

# Signing still works over BT PAN
ssh-add -l
echo "cafe test" | gpg --clearsign
```

## Quick health check

```bash
ssh-add -l && \
  gpg --list-keys >/dev/null 2>&1 && \
  ls "$NOSTR_SA_SOCK" >/dev/null 2>&1 && \
  echo "All services OK" || echo "FAILED -- check service status"
```

## Reset the Avatar

### Light reset (keep keys, re-attach phone)

```bash
sudo systemctl restart km-avatar
systemctl --user restart km-ssh-sa km-gpg-sa km-nostr-sa
qrencode -t UTF8 < /run/keymaster-avatar/descriptor.json
```

Then re-attach from the phone.

### Hard reset (new identity)

```bash
sudo systemctl stop km-avatar
systemctl --user stop km-ssh-sa km-gpg-sa km-nostr-sa
sudo rm -f /var/lib/keymaster-avatar/seed
sudo systemctl start km-avatar
systemctl --user start km-ssh-sa km-gpg-sa km-nostr-sa
qrencode -t UTF8 < /run/keymaster-avatar/descriptor.json
```

## Troubleshooting

| Problem | Fix |
|---------|-----|
| `ssh-add -l` says "Could not open a connection" | `export SSH_AUTH_SOCK=$XDG_RUNTIME_DIR/keymaster-ssh-agent.sock` |
| `ssh-add -l` says "no identities" | Phone not attached. Re-scan QR and attach. |
| `gpg: No secret key` | `export GNUPGHOME=$XDG_RUNTIME_DIR/gnupg-keymaster` and restart km-gpg-sa |
| `descriptor.json` not found | `sudo systemctl restart km-avatar` |
| Phone says "Reconnecting..." | Check BT PAN is connected. Toggle "Internet access" off and on. |
| `bt-nap-br` not appearing | `sudo systemctl restart bt-nap.service` |
| Phone gets no IP | Restart dnsmasq: `sudo systemctl restart dnsmasq`, then toggle "Internet access" off and on |
| Ping laptop works but ping phone fails | One-directional BNEP session. Toggle "Internet access" off and on. |
| `bluetoothctl connect` fails with `br-connection-create-socket` | Expected — do not connect from the laptop. The phone must initiate via "Internet access". |
| DHCP lease assigned but ping fails | One-directional BNEP (first session after pairing). Toggle "Internet access" off and on. |
| Permission denied on API socket | npub in `users.toml` does not match the phone's identity |
| BT PAN connects but no `bt-pan` interface on phone | Known Samsung S24 Ultra issue. Use a MediaTek-based phone. |

## After sleep / wake

When the laptop sleeps, the BT PAN link drops and the bridge state
can become stale. After wake:

1. Toggle "Internet access" **OFF** on the phone
2. Restart the NAP and DHCP services on the laptop:
   ```bash
   sudo systemctl restart bt-nap.service
   sudo systemctl restart dnsmasq
   ```
3. Toggle "Internet access" **ON** on the phone
4. Verify with ping:
   ```bash
   ping -c 3 10.44.0.x    # check dnsmasq.leases for phone IP
   ```
5. Re-attach from the phone (the avatar session is lost on sleep)
6. Restart the GPG service avatar:
   ```bash
   systemctl --user restart km-gpg-sa
   ```

Simply toggling "Internet access" without restarting the services
can produce one-directional BNEP sessions that never recover.
Restarting bt-nap.service recreates the bridge, clearing stale
state from before suspend.

km-gpg-sa does not recover cleanly after the phone reconnects —
GPG signing fails with "Unknown packet" until the service is
restarted. km-ssh-sa is not affected.

Auto-reconnect without manual intervention is planned for a future
release.
