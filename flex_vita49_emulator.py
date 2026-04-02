#!/usr/bin/env python3
"""
FlexRadio VITA-49 Discovery Emulator
=================================================
Mimics the UDP discovery broadcast sent by FlexRadio FLEX-6000, 8000 and Aurora series radios.

This utility will mimic the discovery broadcast for FlexRadios. 

The typical use case for this is accessing your radio via VPN, where it is not on the same LAN.


Defaults:

Port     : 4992
Interval : ~1 second (configurable)

Packet layout (VITA-49 / VRT Extension Context packet):
  - 4-byte VITA-49 header word
  - 4-byte stream ID
  - 8-byte Class ID  (FlexRadio OUI: 00:1C:2D)
  - 4-byte integer timestamp (UTC seconds)
  - 8-byte fractional timestamp (0 for discovery)
  - Variable-length payload: ASCII key=value pairs separated by spaces

Usage
-----
  python3 flex_vita49_emulator.py [options]

  -i / --interval   Heartbeat interval in seconds  (default: 1.0)
  -s / --serial     Radio serial number            (default: 1234-5678)
  -m / --model      Radio model string             (default: FLEX-6600)
  -n / --nickname   Radio nickname                 (default: MyFlexRadio)
  -a / --address    Source IP to advertise         (default: auto-detect)
  -b / --broadcast  Override broadcast address     (default: auto-derive)
  -p / --port       Advertised TCP port            (default: 4992)
  -v / --verbose    Print each packet to stdout
"""

import argparse
import ipaddress
import signal
import socket
import struct
import subprocess
import sys
import threading
import time
from datetime import datetime

# ── FlexRadio / VITA-49 constants ─────────────────────────────────────────────
# Do not modify these unless you know what you're doing!

FLEX_BCAST_PORT   = 4992
FLEX_OUI          = 0x001C2D   # FlexRadio OUI (3 bytes)
FLEX_INFO_CLASS   = 0x534C     # Information class code
FLEX_PACKET_CLASS = 0x534C     # Packet class code

# VITA-49 packet type: Extension Context (0101b)
VRT_PKT_TYPE_EXT_CONTEXT = 0x5

# Header field bits
VRT_CLASS_ID_PRESENT = (1 << 27)
VRT_TSI_UTC          = (1 << 22)   # Integer timestamp: UTC seconds


# ── Network helpers ────────────────────────────────────────────────────────────

def get_local_ip() -> str:
    """Best-effort detection of the primary outbound LAN IP."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def get_broadcast_address(local_ip: str) -> str:
    """
    Derive the directed broadcast address for the interface that owns
    local_ip.

    Strategy (in order):
      1. netifaces library — most accurate, works on all platforms (optional).
      2. `ip addr` output — Linux / macOS with iproute2.
      3. /24 assumption — last resort fallback.
    """
    # ── attempt 1: netifaces ──────────────────────────────────────────────
    try:
        import netifaces  # pip install netifaces
        for iface in netifaces.interfaces():
            addrs = netifaces.ifaddresses(iface).get(netifaces.AF_INET, [])
            for addr in addrs:
                if addr.get("addr") == local_ip:
                    netmask = addr.get("netmask", "255.255.255.0")
                    network = ipaddress.IPv4Network(
                        f"{local_ip}/{netmask}", strict=False
                    )
                    return str(network.broadcast_address)
    except ImportError:
        pass

    # ── attempt 2: `ip addr` (Linux / macOS) ─────────────────────────────
    try:
        import re
        result = subprocess.run(
            ["ip", "addr"], capture_output=True, text=True, timeout=2
        )
        pattern = re.compile(r"inet\s+(" + re.escape(local_ip) + r"/\d+)")
        m = pattern.search(result.stdout)
        if m:
            network = ipaddress.IPv4Network(m.group(1), strict=False)
            return str(network.broadcast_address)
    except Exception:
        pass

    # ── attempt 3: assume /24 ─────────────────────────────────────────────
    parts = local_ip.split(".")
    parts[-1] = "255"
    bcast = ".".join(parts)
    print(
        f"[WARN] Could not determine exact subnet mask for {local_ip}; "
        f"assuming /24 -> broadcast {bcast}. "
        f"Install 'netifaces' (pip install netifaces) for accurate detection, "
        f"or pass -b <broadcast_ip> to override."
    )
    return bcast


# ── Packet builders ────────────────────────────────────────────────────────────

def build_discovery_payload(
    serial: str,
    model: str,
    nickname: str,
    radio_ip: str,
    radio_port: int,
    status: str = "Available",
    inuse_ip: str = "0.0.0.0",
    inuse_host: str = "",
    version: str = "3.3.35.0",
    gui_clients: int = 0,
    wanconnected: bool = False,
) -> bytes:
    """
    Build the ASCII key=value discovery payload that FlexRadio embeds
    inside the VITA-49 context packet.
    """
    fields = {
        "discovery_protocol_version": "3.0.0.1",
        "model":                       model,
        "serial":                      serial,
        "name":                        nickname,
        "callsign":                    "",
        "ip":                          radio_ip,
        "port":                        str(radio_port),
        "inuse_ip":                    inuse_ip,
        "inuse_host":                  inuse_host,
        "version":                     version,
        "status":                      status,
        "max_licensed_version":        "v3",
        "radio_license_id":            serial.replace("-", ""),
        "requires_additional_license": "0",
        "fpc_mac":                     "00:1c:2d:ab:cd:ef",
        "wan_connected":               "1" if wanconnected else "0",
        "licensed_clients":            "2",
        "available_clients":           str(2 - gui_clients),
        "max_panadapters":             "8",
        "available_panadapters":       "8",
        "max_slices":                  "8",
        "available_slices":            "8",
        "gui_client_ips":              "",
        "gui_client_hosts":            "",
        "gui_client_programs":         "",
        "gui_client_stations":         "",
        "gui_client_handles":          "",
    }
    payload_str = " ".join(f"{k}={v}" for k, v in fields.items())
    return payload_str.encode("ascii")


def build_vita49_packet(payload: bytes, stream_id: int = 0x00000000) -> bytes:
    """
    Wrap payload in a VITA-49 Extension Context packet, matching the
    structure FlexRadio uses for its discovery broadcast.

    Word 0   - Header (32 bits)
    Word 1   - Stream ID (32 bits)
    Words 2-3- Class ID (64 bits): OUI + Info-class + Packet-class
    Word 4   - Integer timestamp (UTC seconds)
    Words 5-6- Fractional timestamp (64-bit, 0 for discovery)
    Words 7+ - Payload (padded to 32-bit boundary)
    """
    # Pad payload to 4-byte boundary
    pad_len = (4 - len(payload) % 4) % 4
    padded_payload = payload + b"\x00" * pad_len

    header_words  = 7   # header + stream_id + class_id(2) + ts_int + ts_frac(2)
    payload_words = len(padded_payload) // 4
    total_words   = header_words + payload_words

    # Word 0: VITA-49 header
    #   [31:28] Packet type  = 0x5 (Extension Context)
    #   [27]    Class ID     = 1   (present)
    #   [25:24] TSI          = 01  (UTC)
    #   [23:22] TSF          = 00  (none)
    #   [15:0]  Packet size  = total_words
    header  = (VRT_PKT_TYPE_EXT_CONTEXT << 28)
    header |= VRT_CLASS_ID_PRESENT
    header |= VRT_TSI_UTC
    header |= (total_words & 0xFFFF)

    # Words 2-3: Class ID
    #   [63:40] OUI (24 bits) | [39:32] pad byte
    #   [31:16] Info Class Code | [15:0] Packet Class Code
    class_id_high = (FLEX_OUI & 0xFFFFFF) << 8
    class_id_low  = (FLEX_INFO_CLASS << 16) | (FLEX_PACKET_CLASS & 0xFFFF)

    ts_seconds = int(time.time())

    # Pack 7 header words (struct Q covers words 5-6 as one 64-bit field)
    header_bytes = struct.pack(
        ">IIIIIQ",
        header,
        stream_id,
        class_id_high,
        class_id_low,
        ts_seconds,
        0,           # fractional timestamp = 0
    )

    return header_bytes + padded_payload


# ── Emulator class ─────────────────────────────────────────────────────────────

class FlexRadioEmulator:
    def __init__(
        self,
        serial: str,
        model: str,
        nickname: str,
        radio_ip: str,
        radio_port: int,
        bcast_addr: str,
        interval: float,
        verbose: bool,
    ):
        self.serial      = serial
        self.model       = model
        self.nickname    = nickname
        self.radio_ip    = radio_ip
        self.radio_port  = radio_port
        self.bcast_addr  = bcast_addr
        self.interval    = interval
        self.verbose     = verbose

        self._running    = False
        self._thread     = None
        self._sock       = None
        self._pkt_count  = 0

    def _create_socket(self) -> socket.socket:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # SO_BROADCAST is required to send to a directed broadcast address
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        try:
            # Bind to the radio's IP so the UDP source address is correct
            sock.bind((self.radio_ip, 0))
        except OSError:
            pass  # non-fatal; OS will pick the right source interface
        return sock

    def _send_packet(self):
        payload = build_discovery_payload(
            serial     = self.serial,
            model      = self.model,
            nickname   = self.nickname,
            radio_ip   = self.radio_ip,
            radio_port = self.radio_port,
        )
        packet = build_vita49_packet(payload)
        self._sock.sendto(packet, (self.bcast_addr, FLEX_BCAST_PORT))
        self._pkt_count += 1

        if self.verbose:
            ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
            print(
                f"[{ts}] TX #{self._pkt_count:04d}  "
                f"{len(packet):4d} bytes -> {self.bcast_addr}:{FLEX_BCAST_PORT}  "
                f"| {payload.decode()[:80]}..."
            )

    def _loop(self):
        while self._running:
            try:
                self._send_packet()
            except OSError as e:
                print(f"[ERROR] Send failed: {e}", file=sys.stderr)
            time.sleep(self.interval)

    def start(self):
        self._sock    = self._create_socket()
        self._running = True
        self._thread  = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        print(
            f"\n[OK] FlexRadio emulator started\n"
            f"   Model     : {self.model}\n"
            f"   Serial    : {self.serial}\n"
            f"   Nickname  : {self.nickname}\n"
            f"   Radio IP  : {self.radio_ip}:{self.radio_port}\n"
            f"   Broadcast : {self.bcast_addr}:{FLEX_BCAST_PORT}\n"
            f"   Interval  : {self.interval}s\n"
            f"\nPress Ctrl+C to stop.\n"
        )

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=2)
        if self._sock:
            self._sock.close()
        print(f"\n[STOP] Emulator stopped after {self._pkt_count} packets.")


# ── CLI entry point ────────────────────────────────────────────────────────────

def parse_args():
    p = argparse.ArgumentParser(
        description="FlexRadio VITA-49 Discovery/Heartbeat Emulator (LAN broadcast)",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("-i", "--interval",  type=float, default=1.0,          help="Heartbeat interval (seconds)")
    p.add_argument("-s", "--serial",    type=str,   default="1234-5678",   help="Radio serial number")
    p.add_argument("-m", "--model",     type=str,   default="FLEX-6600",   help="Radio model string")
    p.add_argument("-n", "--nickname",  type=str,   default="MyFlexRadio", help="Radio nickname")
    p.add_argument("-a", "--address",   type=str,   default=None,          help="Source IP to advertise (auto-detect if omitted)")
    p.add_argument("-b", "--broadcast", type=str,   default=None,          help="Broadcast address override (e.g. 192.168.1.255)")
    p.add_argument("-p", "--port",      type=int,   default=4992,          help="Advertised TCP port")
    p.add_argument("-v", "--verbose",   action="store_true",               help="Print each packet to stdout")
    return p.parse_args()


def main():
    args = parse_args()

    radio_ip = args.address or get_local_ip()

    try:
        ipaddress.ip_address(radio_ip)
    except ValueError:
        print(f"[ERROR] Invalid IP address: {radio_ip}", file=sys.stderr)
        sys.exit(1)

    bcast_addr = args.broadcast or get_broadcast_address(radio_ip)

    try:
        addr_obj = ipaddress.ip_address(bcast_addr)
        if addr_obj.packed[-1] != 255:
            print(f"[WARN] {bcast_addr} does not end in .255 — are you sure this is a broadcast address?")
    except ValueError:
        print(f"[ERROR] Invalid broadcast address: {bcast_addr}", file=sys.stderr)
        sys.exit(1)

    emulator = FlexRadioEmulator(
        serial     = args.serial,
        model      = args.model,
        nickname   = args.nickname,
        radio_ip   = radio_ip,
        radio_port = args.port,
        bcast_addr = bcast_addr,
        interval   = args.interval,
        verbose    = args.verbose,
    )

    emulator.start()

    def _shutdown(sig, frame):
        emulator.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT,  _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    while True:
        time.sleep(1)


if __name__ == "__main__":
    main()
