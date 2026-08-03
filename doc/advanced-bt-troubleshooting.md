# Bluetooth PAN Troubleshooting — Lessons Learned

Captured 2026-08-03 during Mission 26.1.1.2 (avatar relay reconnect).

## Architecture

```
Laptop (Tintin)                       Phone (k6789v1_64)
  bt-nap.py → NAP server               PANU client
  bt-nap-br bridge (10.44.0.1/24)      gets 10.44.0.3 via DHCP
  dnsmasq serves DHCP on bridge         connects to laptop's NAP
  strfry relay on :7777                 KeyMaster app → ws://10.44.0.1:7777
```

The **phone initiates** the PAN connection. The laptop is the NAP
server; the phone connects as a PANU client. `bluetoothctl connect`
from the laptop tries the wrong direction (laptop as PANU → phone's
NAP) and always fails.

## Lesson 1: BNEP interface naming

systemd's predictable network naming renames `bnep0` to
`enx<mac_address>` (e.g. `enxf46d3f28644f`). Searching for `bnep`
in `ip link` output misses it.

**Fix:** Check the bt-nap-br bridge ports instead:

```bash
bridge link show            # shows all bridge ports
ip link | grep bt-nap-br    # shows the bridge and its state
```

Or check for any interface attached to the bridge:

```bash
ip link show master bt-nap-br
```

## Lesson 2: bluetoothctl connect is wrong for PAN

`bluetoothctl connect <phone>` tries to connect ALL profiles,
including Network1. It attempts to connect the laptop as a PANU
client to the phone's NAP — which is the reverse of our setup.
This fails with `br-connection-unknown` and tears down the entire
ACL connection.

**Fix:** Don't use `bluetoothctl connect` to establish PAN. Instead:

1. Let the phone initiate (tap CONNECT in BT device details)
2. Or use `hcitool cc` for ACL-only (but the phone must still
   initiate PAN separately)

## Lesson 3: Phone must initiate PAN

The phone's "Internet access" toggle in BT device details triggers
`BluetoothPan.connect()`. This is the only way to establish PAN
from the phone to the laptop's NAP.

There is no way to trigger this programmatically from ADB without
root. Available workarounds:

- **UI automation:** `uiautomator dump` to find element coordinates,
  then `input tap x y` to press buttons. Works reliably.
- **BT cycle + CONNECT tap:** After `cmd bluetooth_manager
  disable/enable`, tap CONNECT from BT device details. If
  "Internet access" was already ON, PAN establishes automatically
  after ACL connects.

## Lesson 4: Stale PAN state after failed recovery

Aggressive recovery attempts (force-stopping com.android.bluetooth,
removing BT pairing, toggling `svc bluetooth`) can leave the phone's
`PanService.mPanDevices` with stale entries. The phone thinks PAN is
partially connected and refuses new connections.

**Fix:** Clean BT cycle on the phone:

```bash
adb shell cmd bluetooth_manager disable
sleep 3
adb shell cmd bluetooth_manager enable
```

Then wait for BT to fully initialize before connecting. Verify with:

```bash
adb shell dumpsys bluetooth_manager | grep -A 8 "Profile: PanService"
# mPanDevices should be empty after clean cycle
```

## Lesson 5: PAN connection policy values

Android's `BluetoothProfile` connection policy values:

| Value | Constant | Meaning |
|-------|----------|---------|
| -1 | UNKNOWN | Profile not applicable |
| 0 | FORBIDDEN | Won't connect |
| 100 | ALLOWED | Connect when requested (manual) |
| 200 | AUTO_CONNECT | Connect automatically |

PAN is typically at 100 (ALLOWED), meaning it only connects when
the user explicitly requests it. `settings put global
bluetooth_pan_priority_<MAC>=200` does NOT propagate to the BT
stack — the stack stores policies internally.

## Lesson 6: Sleep/wake kills everything on same host

When the relay (strfry) runs on the laptop, sleep kills:
- Avatar's WebSocket to relay (avatar side — fixed by D-Bus listener)
- Phone's WebSocket to relay (phone side — needs Android app fix)
- BT ACL connection (phone disconnects)
- BT PAN / BNEP interface (disappears)

After wake, the avatar reconnects instantly via D-Bus
`PrepareForSleep(false)`. But the phone must:
1. Re-establish BT ACL
2. Re-establish BT PAN
3. Reconnect WebSocket to relay

None of these happen automatically today.

## Quick recovery procedure

When BT PAN is down after sleep/wake:

```bash
# 1. Check if BT PAN is actually up (don't grep for "bnep"!)
ip link show master bt-nap-br

# 2. If no interface shown, phone needs to reconnect BT:
#    On phone: BT settings → Tintin → tap CONNECT

# 3. Verify PAN came up
ping -c 1 10.44.0.3

# 4. If ping fails but BT is connected, toggle Internet access
#    on the phone (BT device details → Internet access off/on)

# 5. If PAN state is stale (repeated failures), clean cycle:
adb shell cmd bluetooth_manager disable
sleep 3
adb shell cmd bluetooth_manager enable
# Then tap CONNECT from phone BT settings
```
