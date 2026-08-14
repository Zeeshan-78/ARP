# ARP Spoof Detector

A lightweight, dependency-minimal **defensive** security tool written in
Python that passively monitors ARP traffic on your local network and alerts
you to signs of **ARP spoofing / ARP cache poisoning** — the technique
behind most local Man-in-the-Middle (MITM) attacks (e.g. tools like
`arpspoof`, `ettercap`, `bettercap`).

> ⚠️ This tool only **listens** to traffic. It never sends packets or performs
> any attack. It is safe to run on any network you own or are authorized to
> monitor.

---

## How it works

The tool sniffs ARP replies (`op=2`, i.e. "is-at" packets) on a chosen
interface and runs four independent detection checks on every packet:

| Detection | What it catches |
|---|---|
| **IP → MAC binding change** | The classic sign of spoofing: an IP that suddenly starts resolving to a different MAC address than before. |
| **Whitelist / pinned hosts** | Lets you pin known-good bindings (e.g. your router) with `--pin`; any deviation is an immediate high-confidence alert. |
| **Duplicate MAC claims** | One MAC address claiming to be multiple IPs — a common pattern when an attacker's NIC answers on behalf of several hosts. |
| **Gratuitous ARP flood** | A sliding-window rate check that flags a host sending an abnormal number of ARP replies per second — typical of active poisoning tools. |

Alerts are:
- Printed to the console in real time
- Appended to a structured **JSON-lines log** (`arp_alerts.jsonl` by default) for later analysis / SIEM ingestion
- Optionally POSTed to a **webhook** (Slack, Discord, custom endpoint) for real-time notification

---

## Installation

```bash
git clone https://github.com/<your-username>/arp-spoof-detector.git
cd arp-spoof-detector
pip install -r requirements.txt --break-system-packages   # or use a venv
```

Requires **Python 3.9+** and [Scapy](https://scapy.net/), which needs raw
socket access (root/admin privileges) to sniff packets.

---

## Usage

Basic run (auto-selects default interface):

```bash
sudo python3 arp_spoof_detector.py
```

Specify an interface:

```bash
sudo python3 arp_spoof_detector.py -i eth0
```

Pin your gateway (or any critical host) so any impersonation is caught immediately:

```bash
sudo python3 arp_spoof_detector.py -i eth0 --pin 192.168.1.1=aa:bb:cc:dd:ee:ff
```

Tune flood-detection sensitivity:

```bash
sudo python3 arp_spoof_detector.py --flood-threshold 15 --flood-window 3
```

Send alerts to a Slack/Discord webhook:

```bash
sudo python3 arp_spoof_detector.py --webhook https://hooks.slack.com/services/XXX/YYY/ZZZ
```

Full CLI reference:

```bash
python3 arp_spoof_detector.py --help
```

```
options:
  -i, --interface        Network interface to sniff on (e.g. eth0, wlan0)
  --pin IP=MAC            Pin a known-good IP=MAC binding. Repeatable.
  --flood-threshold INT   ARP replies/window to trigger a flood alert (default: 10)
  --flood-window FLOAT    Sliding window in seconds for flood detection (default: 5.0)
  --log-file PATH         Path to JSON-lines alert log (default: arp_alerts.jsonl)
  --webhook URL           Optional webhook URL to POST alerts to
  -v, --verbose           Verbose/debug output
```

---

## Example alert output

```
2026-08-14 21:03:11 | WARNING  | [ALERT:MAC_CHANGE] IP 192.168.1.1 changed MAC aa:bb:cc:dd:ee:ff -> 11:22:33:44:55:66 (seen 1 change(s), history=['aa:bb:cc:dd:ee:ff', '11:22:33:44:55:66'])
2026-08-14 21:03:12 | WARNING  | [ALERT:GRATUITOUS_FLOOD] MAC 11:22:33:44:55:66 sent 14 ARP replies in 5s (possible active spoofing/flood)
```

Corresponding JSON-lines entry (`arp_alerts.jsonl`):

```json
{"kind": "MAC_CHANGE", "message": "IP 192.168.1.1 changed MAC ...", "ip": "192.168.1.1", "old_mac": "aa:bb:cc:dd:ee:ff", "new_mac": "11:22:33:44:55:66", "change_count": 1, "timestamp": "2026-08-14T21:03:11.482331Z"}
```

---

## Testing it safely

To generate test alerts in a lab environment (e.g. two VMs on an isolated
virtual network), you can use a tool like `arpspoof` (from `dsniff`) or
`bettercap` **against machines you own**, or simply bring a device up/down
on a test switch and change its MAC address to simulate a binding change.

Never run offensive ARP tools against networks you do not own or have
explicit written authorization to test.

---

## Roadmap ideas

- [ ] Passive OS/vendor fingerprinting via MAC OUI lookup
- [ ] Auto-response mode (e.g. trigger a static ARP entry / firewall rule)
- [ ] Web dashboard (Flask) for live alert visualization
- [ ] Multi-interface / VLAN-aware monitoring
- [ ] Export to Syslog / CEF for SIEM integration

Contributions and PRs welcome!

---

## License

MIT — see [LICENSE](LICENSE).

## Disclaimer

This project is provided for **educational and defensive security purposes
only**. The author is not responsible for misuse. Always ensure you have
authorization before monitoring or testing any network.
