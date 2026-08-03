# Bluetooth PAN for KeyMaster Avatar

Provides a dedicated Bluetooth network between phone and laptop so
the phone can reach the avatar relay without using WiFi. WiFi stays
free for internet.

## Components

| File | Installs to | Purpose |
|------|-------------|---------|
| `bt-nap.py` | `/usr/local/bin/bt-nap.py` | Creates bridge, registers BlueZ NAP via D-Bus |
| `bt-nap.service` | `/etc/systemd/system/bt-nap.service` | Starts NAP at boot |
| `dnsmasq-pan.conf` | `/etc/dnsmasq.d/pan0.conf` | DHCP for phones on bt-nap-br |

## Install

```bash
# Dependencies
sudo apt install dnsmasq python3-dbus python3-gi

# NAP script
sudo install -m 755 bt-nap.py /usr/local/bin/bt-nap.py

# Systemd unit
sudo install -m 644 bt-nap.service /etc/systemd/system/bt-nap.service
sudo systemctl daemon-reload
sudo systemctl enable --now bt-nap.service

# dnsmasq config
sudo install -m 644 dnsmasq-pan.conf /etc/dnsmasq.d/pan0.conf
sudo systemctl restart dnsmasq
sudo systemctl enable dnsmasq
```

## Pair a phone

```bash
bluetoothctl discoverable-timeout 0
bluetoothctl discoverable on
# Pair from phone, then:
bluetoothctl trust <PHONE_MAC>
bluetoothctl discoverable off
```

Note: `bluetoothctl agent on` does not work non-interactively.
For automated/SSH pairing, use a Python D-Bus agent (see the
getting-started-bluetooth guide for code).

## Connect

On phone: Bluetooth settings -> paired laptop -> enable
"Internet access" (Internetåtkomst).

The phone **must** initiate the connection. Do not use
`bluetoothctl connect` from the laptop — it tries to connect the
phone's NAP profile (wrong direction) and fails with
`br-connection-create-socket`.

Verify:
```bash
ip addr show bt-nap-br            # should show inet 10.44.0.1/24
cat /var/lib/misc/dnsmasq.leases  # should show phone's MAC + IP
ping 10.44.0.x                    # phone (check leases for actual IP)
```

**Important:** Always verify with `ping`, not just the DHCP lease.
The first BNEP session after pairing can be one-directional (DHCP
succeeds but ping fails). If ping fails, toggle "Internet access"
off and on — the second session works.

## How it works

BlueZ 5.85 requires a valid bridge name when registering a NAP --
passing an empty string causes `bnep_add_to_bridge()` to fail with
ENODEV. The script creates a bridge (`bt-nap-br`) with STP disabled
and zero forward delay, assigns 10.44.0.1/24, and registers it as
the BlueZ NAP. When a phone connects, BlueZ adds the `bnep0`
interface as a bridge port. dnsmasq serves DHCP on the bridge
interface.

## Gotchas

### Android requires a DHCP gateway

Without `dhcp-option=3,10.44.0.1`, Android accepts the DHCP lease
but does not configure the IP on its bt-pan interface.

### dnsmasq at boot

The bridge is created by bt-nap.py at startup, so 10.44.0.1 exists
as long as bt-nap.service is running. dnsmasq should start reliably
if bt-nap.service starts first. If dnsmasq fails to bind, restart
it after bt-nap.service is up:
```bash
sudo systemctl restart dnsmasq
```

### One-directional BNEP session

The first BNEP session after pairing (or after a long disconnect)
can be one-directional: the laptop sends traffic to the phone but
the phone's return traffic never reaches `bnep0`. DHCP succeeds
(it is broadcast-based) but ping fails. Toggle "Internet access"
off and on to get a clean bidirectional session. This appears to
be a MediaTek BT chipset quirk.

### After sleep/wake

After a laptop sleep/wake cycle, simply toggling "Internet access"
can produce one-directional BNEP sessions that never recover.
Restart the services before reconnecting:

```bash
sudo systemctl restart bt-nap.service
sudo systemctl restart dnsmasq
```

Then toggle "Internet access" ON on the phone and verify with
`ping`.

### `bluetoothctl connect` fails

`bluetoothctl connect <PHONE_MAC>` fails with
`br-connection-create-socket` because it auto-connects all
profiles, including the phone's NAP (wrong direction — the laptop
is the NAP). The phone must initiate via "Internet access".
If you need to establish the BT link from the laptop side first
(e.g. to wake the phone's BT stack), connect a non-PAN profile:

```bash
dbus-send --system --dest=org.bluez --print-reply \
  /org/bluez/hci0/dev_XX_XX_XX_XX_XX_XX \
  org.bluez.Device1.ConnectProfile \
  string:"0000110e-0000-1000-8000-00805f9b34fb"   # AVRCP
```

Then toggle "Internet access" on the phone.

### Samsung S24 Ultra

BT PAN is broken on the Samsung S24 Ultra (Android 15, One UI 7).
The phone completes DHCP but never creates a usable bt-pan network
interface. Other Android phones (tested: MediaTek k6789v1_64) work.
