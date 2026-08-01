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
