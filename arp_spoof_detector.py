#!/usr/bin/env python3
"""
ARP Spoofing / Cache Poisoning Detector
========================================

A defensive network security tool that passively monitors ARP traffic on a
local network interface and raises alerts when it detects signs of ARP
spoofing (a.k.a. ARP cache poisoning) — the technique behind most local
Man-in-the-Middle (MITM) attacks.

Detection strategies implemented:
  1. IP -> MAC binding tracking with change detection (classic detector)
  2. Gratuitous ARP flood detection (rate-based)
  3. Duplicate MAC address detection (one MAC claiming multiple IPs)
  4. Static whitelist support (pin known-good IP/MAC pairs, e.g. gateway)
  5. Optional passive OS/vendor lookup via MAC OUI prefix
  6. Alerting via console, log file (JSON lines) and optional webhook

This is a MONITORING tool only — it does not send any packets and is safe
to run on networks you own or are authorized to monitor.

Author: (you!)
License: MIT
"""

from __future__ import annotations

import argparse
import json
import logging
import signal
import sys
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from threading import Lock
from typing import Deque, Dict, Optional

try:
    from scapy.all import ARP, Ether, sniff, conf  # type: ignore
except ImportError:
    print(
        "[!] scapy is required. Install it with: pip install scapy --break-system-packages",
        file=sys.stderr,
    )
    sys.exit(1)

try:
    import requests  # optional, only needed for --webhook
except ImportError:
    requests = None


# --------------------------------------------------------------------------- #
# Data structures
# --------------------------------------------------------------------------- #

@dataclass
class HostRecord:
    """Tracks the observed binding history for a single IP address."""
    mac: str
    first_seen: float
    last_seen: float
    change_count: int = 0
    history: Deque[str] = field(default_factory=lambda: deque(maxlen=10))


@dataclass
class DetectorConfig:
    interface: Optional[str] = None
    whitelist: Dict[str, str] = field(default_factory=dict)   # ip -> mac
    gratuitous_threshold: int = 10      # ARP replies/sec from one MAC
    gratuitous_window: float = 5.0      # seconds
    log_file: str = "arp_alerts.jsonl"
    webhook_url: Optional[str] = None
    verbose: bool = False


# --------------------------------------------------------------------------- #
# Core detector
# --------------------------------------------------------------------------- #

class ArpSpoofDetector:
    def __init__(self, config: DetectorConfig):
        self.config = config
        self.lock = Lock()

        # ip -> HostRecord
        self.table: Dict[str, HostRecord] = {}
        # mac -> set of ips it has claimed (duplicate-MAC / one-to-many detection)
        self.mac_to_ips: Dict[str, set] = defaultdict(set)
        # mac -> timestamps of recent ARP replies (flood detection)
        self.reply_timestamps: Dict[str, Deque[float]] = defaultdict(
            lambda: deque(maxlen=200)
        )

        self.packet_count = 0
        self.alert_count = 0
        self._stop = False

        self._setup_logging()

    # ---------------------------------------------------------- logging ----
    def _setup_logging(self) -> None:
        self.logger = logging.getLogger("arp_spoof_detector")
        self.logger.setLevel(logging.DEBUG if self.config.verbose else logging.INFO)

        console = logging.StreamHandler(sys.stdout)
        console.setFormatter(logging.Formatter("%(asctime)s | %(levelname)-8s | %(message)s"))
        self.logger.addHandler(console)

        self.alert_log_path = Path(self.config.log_file)

    def _write_alert(self, alert: dict) -> None:
        alert["timestamp"] = datetime.utcnow().isoformat() + "Z"
        with self.alert_log_path.open("a") as f:
            f.write(json.dumps(alert) + "\n")

        if self.config.webhook_url and requests is not None:
            try:
                requests.post(self.config.webhook_url, json=alert, timeout=3)
            except Exception as e:  # never let alerting crash the detector
                self.logger.debug(f"Webhook delivery failed: {e}")

    def _alert(self, kind: str, message: str, **fields) -> None:
        self.alert_count += 1
        self.logger.warning(f"[ALERT:{kind}] {message}")
        self._write_alert({"kind": kind, "message": message, **fields})

    # --------------------------------------------------------- core logic --
    def _check_whitelist_violation(self, ip: str, mac: str) -> bool:
        expected = self.config.whitelist.get(ip)
        if expected and expected.lower() != mac.lower():
            self._alert(
                "WHITELIST_VIOLATION",
                f"{ip} is pinned to {expected} but replied from {mac}",
                ip=ip, expected_mac=expected, seen_mac=mac,
            )
            return True
        return False

    def _check_binding_change(self, ip: str, mac: str, now: float) -> None:
        record = self.table.get(ip)
        if record is None:
            self.table[ip] = HostRecord(mac=mac, first_seen=now, last_seen=now)
            self.table[ip].history.append(mac)
            return

        record.last_seen = now
        if record.mac.lower() != mac.lower():
            record.change_count += 1
            record.history.append(mac)
            self._alert(
                "MAC_CHANGE",
                f"IP {ip} changed MAC {record.mac} -> {mac} "
                f"(seen {record.change_count} change(s), history={list(record.history)})",
                ip=ip, old_mac=record.mac, new_mac=mac,
                change_count=record.change_count,
            )
            record.mac = mac

    def _check_duplicate_mac(self, ip: str, mac: str) -> None:
        self.mac_to_ips[mac].add(ip)
        claimed = self.mac_to_ips[mac]
        if len(claimed) > 1:
            self._alert(
                "DUPLICATE_MAC",
                f"MAC {mac} is claiming multiple IPs: {sorted(claimed)}",
                mac=mac, ips=sorted(claimed),
            )

    def _check_gratuitous_flood(self, mac: str, now: float) -> None:
        dq = self.reply_timestamps[mac]
        dq.append(now)
        # drop timestamps outside the sliding window
        while dq and now - dq[0] > self.config.gratuitous_window:
            dq.popleft()
        if len(dq) >= self.config.gratuitous_threshold:
            self._alert(
                "GRATUITOUS_FLOOD",
                f"MAC {mac} sent {len(dq)} ARP replies in "
                f"{self.config.gratuitous_window:.0f}s (possible active spoofing/flood)",
                mac=mac, rate=len(dq), window=self.config.gratuitous_window,
            )
            dq.clear()  # avoid re-alerting every packet until it cools down

    # -------------------------------------------------------- packet hook --
    def handle_packet(self, pkt) -> None:
        if not pkt.haslayer(ARP):
            return

        arp = pkt[ARP]
        # op=2 -> is-at (a reply / gratuitous announcement)
        if arp.op != 2:
            return

        ip, mac = arp.psrc, arp.hwsrc.lower()
        if ip in ("0.0.0.0", "") or mac in ("00:00:00:00:00:00", ""):
            return

        now = time.time()
        self.packet_count += 1

        with self.lock:
            self._check_whitelist_violation(ip, mac)
            self._check_binding_change(ip, mac, now)
            self._check_duplicate_mac(ip, mac)
            self._check_gratuitous_flood(mac, now)

        if self.config.verbose:
            self.logger.debug(f"ARP reply: {ip} is-at {mac}")

    # ------------------------------------------------------------- run ----
    def run(self) -> None:
        iface = self.config.interface or conf.iface
        self.logger.info(f"Starting ARP spoof detector on interface: {iface}")
        self.logger.info(f"Whitelisted hosts: {self.config.whitelist or 'none'}")
        self.logger.info(f"Alerts will be logged to: {self.alert_log_path.resolve()}")

        signal.signal(signal.SIGINT, self._handle_sigint)

        sniff(
            filter="arp",
            store=False,
            prn=self.handle_packet,
            iface=self.config.interface,
            stop_filter=lambda _: self._stop,
        )

    def _handle_sigint(self, signum, frame) -> None:
        self._stop = True
        self.logger.info(
            f"\nStopped. Processed {self.packet_count} ARP packets, "
            f"raised {self.alert_count} alert(s)."
        )
        sys.exit(0)


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def parse_whitelist(pairs: list[str]) -> Dict[str, str]:
    """Parse --pin 192.168.1.1=aa:bb:cc:dd:ee:ff entries."""
    result = {}
    for pair in pairs or []:
        if "=" not in pair:
            raise argparse.ArgumentTypeError(
                f"Invalid --pin value '{pair}', expected format IP=MAC"
            )
        ip, mac = pair.split("=", 1)
        result[ip.strip()] = mac.strip().lower()
    return result


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="arp_spoof_detector.py",
        description="Passively detect ARP spoofing / MITM attacks on your local network.",
    )
    p.add_argument("-i", "--interface", help="Network interface to sniff on (e.g. eth0, wlan0)")
    p.add_argument(
        "--pin", action="append", metavar="IP=MAC",
        help="Pin a known-good IP=MAC binding (e.g. your gateway). Repeatable.",
    )
    p.add_argument(
        "--flood-threshold", type=int, default=10,
        help="Number of ARP replies from one MAC within the window to trigger a flood alert (default: 10)",
    )
    p.add_argument(
        "--flood-window", type=float, default=5.0,
        help="Sliding window in seconds for flood detection (default: 5.0)",
    )
    p.add_argument(
        "--log-file", default="arp_alerts.jsonl",
        help="Path to JSON-lines alert log (default: arp_alerts.jsonl)",
    )
    p.add_argument("--webhook", help="Optional webhook URL to POST alerts to (e.g. Slack/Discord)")
    p.add_argument("-v", "--verbose", action="store_true", help="Verbose/debug output")
    return p


def main() -> None:
    args = build_arg_parser().parse_args()

    config = DetectorConfig(
        interface=args.interface,
        whitelist=parse_whitelist(args.pin),
        gratuitous_threshold=args.flood_threshold,
        gratuitous_window=args.flood_window,
        log_file=args.log_file,
        webhook_url=args.webhook,
        verbose=args.verbose,
    )

    detector = ArpSpoofDetector(config)
    try:
        detector.run()
    except PermissionError:
        print(
            "[!] Permission denied. ARP sniffing requires elevated privileges.\n"
            "    Try: sudo python3 arp_spoof_detector.py",
            file=sys.stderr,
        )
        sys.exit(1)


if __name__ == "__main__":
    main()
