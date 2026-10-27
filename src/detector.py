import argparse
import csv
import json
import os
import re
import subprocess
import tempfile
import threading
from datetime import datetime, timezone
from pathlib import Path

from dashboard import DashboardServer
from scapy.all import Dot11, Dot11Beacon, Dot11ProbeResp, RadioTap, sniff

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CONFIG = PROJECT_ROOT / "config" / "trusted_networks.json"
DEFAULT_LOG = PROJECT_ROOT / "logs" / "detector.csv"
CHANNELS = tuple(range(1, 14))
SECURITY_MODES = {"Open", "WEP", "WPA", "WPA2/3"}
BSSID_PATTERN = re.compile(r"^(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$")
IW_BSS_PATTERN = re.compile(r"^\s*BSS\s+([0-9a-fA-F:]{17})\b")


class DetectorState:
    def __init__(self, scan_interval=30.0, scan_mode="managed"):
        self.lock = threading.RLock()
        self.access_points = {}
        self.events = []
        self.alerts = set()
        self.trusted_networks = {}
        self.scanner_running = False
        self.last_scan = None
        self.last_error = ""
        self.scan_interval = scan_interval
        self.scan_mode = scan_mode

    def record_scan(self, access_points, error=""):
        now = datetime.now(timezone.utc).isoformat()
        with self.lock:
            self.last_scan = now
            self.last_error = error
            previous_access_points = self.access_points
            if not error:
                self.access_points = {}
            for ap in access_points:
                key = (ap["ssid"], ap["bssid"])
                current = self.access_points.setdefault(key, {})
                previous = previous_access_points.get(key, {})
                current.update(ap)
                current["first_seen"] = previous.get("first_seen", now)
                current["last_seen"] = now

    def observe_access_point(self, ap):
        now = datetime.now(timezone.utc).isoformat()
        with self.lock:
            self.last_scan = now
            key = (ap["ssid"], ap["bssid"])
            current = self.access_points.setdefault(key, {})
            first_seen = current.get("first_seen", now)
            current.update(ap)
            current["first_seen"] = first_seen
            current["last_seen"] = now

    def record_event(self, event):
        with self.lock:
            self.events.append(dict(event))
            del self.events[:-1000]

    def history(self):
        with self.lock:
            return [dict(event) for event in self.events]

    def snapshot(self):
        with self.lock:
            access_points = [dict(ap) for ap in self.access_points.values()]
            for ap in access_points:
                ap["findings"] = rule_engine(
                    ap.get("ssid", ""), ap["bssid"], ap.get("rssi"), ap.get("channel"),
                    ap.get("security", "Unknown"), self.trusted_networks,
                )
                ap["trusted"] = ap.get("ssid", "") in self.trusted_networks and ap.get("bssid", "").lower() == self.trusted_networks[ap["ssid"]]["bssid"].lower()
            comparisons = []
            for ssid, expected in self.trusted_networks.items():
                expected_bssid = expected["bssid"].lower()
                observations = []
                for ap in access_points:
                    if ap.get("ssid") != ssid:
                        continue
                    observed = {
                        "bssid": ap["bssid"],
                        "rssi": ap.get("rssi"),
                        "channel": ap.get("channel"),
                        "security": ap.get("security", "Unknown"),
                        "first_seen": ap.get("first_seen"),
                        "last_seen": ap.get("last_seen"),
                        "is_trusted_bssid": ap["bssid"].lower() == expected_bssid,
                        "bssid_match": ap["bssid"].lower() == expected_bssid,
                        "channel_match": None if expected.get("channel") is None or ap.get("channel") is None else ap.get("channel") == expected.get("channel"),
                        "security_match": None if expected.get("security") is None else ap.get("security", "Unknown") == expected.get("security"),
                        "signal_threshold": expected.get("rssi_threshold"),
                        "signal_alert_limit": None if expected.get("rssi_threshold") is None else expected["rssi_threshold"] + 10,
                    }
                    observations.append(observed)
                comparisons.append({
                    "ssid": ssid,
                    "expected": {
                        "bssid": expected_bssid,
                        "channel": expected.get("channel"),
                        "security": expected.get("security"),
                        "rssi_threshold": expected.get("rssi_threshold"),
                        "signal_alert_limit": None if expected.get("rssi_threshold") is None else expected["rssi_threshold"] + 10,
                    },
                    "observations": observations,
                })
            return {
                "scanner_running": self.scanner_running,
                "scan_mode": self.scan_mode,
                "scan_interval": self.scan_interval,
                "last_scan": self.last_scan,
                "last_error": self.last_error,
                "access_points": access_points,
                "twin_comparisons": comparisons,
                "alert_count": sum(1 for event in self.events if event.get("event") == "ALERT"),
                "trusted_networks": dict(self.trusted_networks),
            }


def run_command(*args):
    return subprocess.run(args, check=True, text=True, capture_output=True)


def get_interface_state(interface):
    details = run_command("iw", "dev", interface, "info").stdout
    interface_type = next(
        (line.split()[1] for line in details.splitlines() if line.strip().startswith("type ")),
        None,
    )
    if interface_type is None:
        raise RuntimeError(f"Could not determine the type of {interface}")

    link = run_command("ip", "-o", "link", "show", "dev", interface).stdout
    flags = link.split("<", 1)[1].split(">", 1)[0] if "<" in link and ">" in link else ""
    was_up = "UP" in flags.split(",")
    return interface_type, was_up


def set_link_state(interface, up):
    run_command("ip", "link", "set", "dev", interface, "up" if up else "down")


def set_interface_type(interface, interface_type):
    run_command("iw", "dev", interface, "set", "type", interface_type)


def configure_monitor_mode(interface):
    original_type, was_up = get_interface_state(interface)
    if original_type == "monitor":
        return original_type, was_up

    try:
        set_link_state(interface, False)
        set_interface_type(interface, "monitor")
        set_link_state(interface, True)
    except (OSError, subprocess.CalledProcessError):
        try:
            set_link_state(interface, False)
            set_interface_type(interface, original_type)
            set_link_state(interface, was_up)
        except (OSError, subprocess.CalledProcessError):
            pass
        raise
    return original_type, was_up


def restore_interface(interface, original_state):
    original_type, was_up = original_state
    if original_type == "monitor":
        return
    try:
        set_link_state(interface, False)
        set_interface_type(interface, original_type)
        set_link_state(interface, was_up)
    except (OSError, subprocess.CalledProcessError) as error:
        print(f"Warning: could not restore {interface}: {error}")


def information_elements(frame):
    raw_elements = bytes(frame.payload)
    offset = 0
    while offset + 2 <= len(raw_elements):
        element_id = raw_elements[offset]
        length = raw_elements[offset + 1]
        offset += 2
        if offset + length > len(raw_elements):
            return
        yield element_id, raw_elements[offset:offset + length]
        offset += length


def get_ssid(frame):
    for element_id, info in information_elements(frame):
        if element_id == 0:
            return info.decode("utf-8", errors="replace")
    return ""


def get_channel(packet):
    frame = packet.getlayer(Dot11Beacon) or packet.getlayer(Dot11ProbeResp)
    if frame is None:
        return None
    for element_id, info in information_elements(frame):
        if element_id == 3 and info:
            return info[0]
    return None


def channel_from_frequency(frequency):
    if frequency == 2484:
        return 14
    if 2412 <= frequency <= 2472 and (frequency - 2407) % 5 == 0:
        return (frequency - 2407) // 5
    if 5000 <= frequency < 5900 and frequency % 5 == 0:
        return (frequency - 5000) // 5
    if 5955 <= frequency <= 7115 and (frequency - 5950) % 5 == 0:
        return (frequency - 5950) // 5
    return None


def parse_iw_scan(output):
    access_points = []
    access_point = None
    for line in output.splitlines():
        match = IW_BSS_PATTERN.match(line)
        if match:
            if access_point is not None:
                access_points.append(access_point)
            access_point = {
                "bssid": match.group(1),
                "ssid": "",
                "rssi": None,
                "channel": None,
                "security": "Open",
                "has_rsn": False,
                "has_wpa": False,
                "privacy": False,
            }
            continue
        if access_point is None:
            continue
        key, separator, value = line.strip().partition(":")
        if not separator:
            continue
        value = value.strip()
        if key == "SSID":
            access_point["ssid"] = value
        elif key == "freq":
            try:
                access_point["channel"] = channel_from_frequency(round(float(value)))
            except ValueError:
                pass
        elif key == "signal":
            signal = re.match(r"(-?\d+(?:\.\d+)?)\s*dBm", value)
            if signal:
                access_point["rssi"] = round(float(signal.group(1)))
        elif key == "capability":
            access_point["privacy"] = "privacy" in value.lower()
        elif key == "RSN":
            access_point["has_rsn"] = True
        elif key == "WPA":
            access_point["has_wpa"] = True

    if access_point is not None:
        access_points.append(access_point)

    for access_point in access_points:
        if access_point["has_rsn"]:
            access_point["security"] = "WPA2/3"
        elif access_point["has_wpa"]:
            access_point["security"] = "WPA"
        elif access_point["privacy"]:
            access_point["security"] = "WEP"
        del access_point["has_rsn"], access_point["has_wpa"], access_point["privacy"]
    return access_points


def load_trusted_networks(config_path):
    try:
        with Path(config_path).open(encoding="utf-8") as config_file:
            config = json.load(config_file)
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"Could not load config {config_path}: {error}") from error

    networks = config.get("trusted_networks") if isinstance(config, dict) else None
    if not isinstance(networks, dict):
        raise ValueError("Config must contain a 'trusted_networks' object")

    for ssid, network in networks.items():
        if not isinstance(ssid, str) or not ssid or not isinstance(network, dict):
            raise ValueError("Each trusted network must have a non-empty SSID and an object of settings")
        bssid = network.get("bssid")
        if not isinstance(bssid, str) or not BSSID_PATTERN.fullmatch(bssid):
            raise ValueError(f"Trusted network {ssid!r} needs a valid colon-separated BSSID")
        channel = network.get("channel")
        if channel is not None and (type(channel) is not int or channel not in CHANNELS):
            raise ValueError(f"Trusted network {ssid!r} channel must be an integer from 1 to 13")
        threshold = network.get("rssi_threshold")
        if threshold is not None and (type(threshold) not in (int, float) or not -100 <= threshold <= 0):
            raise ValueError(f"Trusted network {ssid!r} RSSI threshold must be between -100 and 0 dBm")
        security = network.get("security")
        if security is not None and (not isinstance(security, str) or security not in SECURITY_MODES):
            raise ValueError(f"Trusted network {ssid!r} security must be one of {sorted(SECURITY_MODES)}")
    return networks


def get_security_mode(frame, packet=None):
    has_rsn = False
    has_wpa = False
    for element_id, info in information_elements(frame):
        if element_id == 48:
            has_rsn = True
        elif element_id == 221 and info.startswith(b"\x00\x50\xf2\x01"):
            has_wpa = True

    if has_rsn:
        return "WPA2/3"
    if has_wpa:
        return "WPA"
    capabilities = getattr(frame, "cap", 0)
    if isinstance(capabilities, str):
        is_protected = "privacy" in capabilities.lower()
    else:
        is_protected = bool(int(capabilities) & 0x10)
    return "WEP" if is_protected else "Open"


def rule_engine(ssid, bssid, rssi, channel, security, trusted_networks):
    network = trusted_networks.get(ssid)
    if network is None:
        return []

    alerts = []
    expected_bssid = network["bssid"]
    if bssid.lower() != expected_bssid.lower():
        alerts.append(f"[HIGH] R-01: BSSID mismatch (observed {bssid}; expected {expected_bssid})")

    threshold = network.get("rssi_threshold")
    if rssi is not None and threshold is not None and rssi > threshold + 10:
        alerts.append(
            f"[HIGH] R-02: Signal is unusually strong ({rssi} dBm observed; "
            f"configured threshold {threshold} dBm, alert limit {threshold + 10} dBm)"
        )

    expected_channel = network.get("channel")
    if channel is not None and expected_channel is not None and channel != expected_channel:
        alerts.append(f"[MEDIUM] R-05: Unexpected channel ({channel}; expected {expected_channel})")

    expected_security = network.get("security")
    if expected_security is not None and security != expected_security:
        alerts.append(
            f"[HIGH] R-04: Security-mode mismatch ({security}; expected {expected_security})"
        )
    return alerts


class EventLogger:
    FIELDS = ("timestamp", "event", "ssid", "bssid", "rssi_dbm", "channel", "security", "message")

    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        is_new = not self.path.exists() or self.path.stat().st_size == 0
        self.file = self.path.open("a", newline="", encoding="utf-8")
        self.writer = csv.DictWriter(self.file, fieldnames=self.FIELDS)
        self.on_write = None
        if is_new:
            self.writer.writeheader()
            self.file.flush()

    def write(self, event, ssid="", bssid="", rssi=None, channel=None, security="", message=""):
        self.writer.writerow({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": event,
            "ssid": ssid,
            "bssid": bssid,
            "rssi_dbm": "" if rssi is None else rssi,
            "channel": "" if channel is None else channel,
            "security": security,
            "message": message,
        })
        self.file.flush()
        if self.on_write is not None:
            self.on_write({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "event": event,
                "ssid": ssid,
                "bssid": bssid,
                "rssi": rssi,
                "channel": channel,
                "security": security,
                "message": message,
            })

    def close(self):
        self.file.close()


def process_access_point(ssid, bssid, rssi, channel, security, trusted_networks, event_logger, state, dashboard_state=None):
    if dashboard_state is not None:
        dashboard_state.observe_access_point({
            "ssid": ssid,
            "bssid": bssid,
            "rssi": rssi,
            "channel": channel,
            "security": security,
        })
    network_key = (ssid, bssid)
    if network_key not in state["access_points"]:
        state["access_points"].add(network_key)
        signal = f"{rssi} dBm" if rssi is not None else "RSSI unavailable"
        frequency = f"channel {channel}" if channel is not None else "channel unavailable"
        print(f"AP: {ssid or '<hidden SSID>'} | {bssid} | {signal} | {frequency} | {security}", flush=True)
        event_logger.write("AP", ssid, bssid, rssi, channel, security, "Access point discovered")

        if ssid:
            other_bssids = state["ssids"].setdefault(ssid, set())
            if other_bssids and bssid not in other_bssids:
                alert = "[MEDIUM] R-06: Multiple BSSIDs advertise this SSID; verify (may be a mesh)"
                alert_key = (ssid, bssid, alert)
                if alert_key not in state["alerts"]:
                    state["alerts"].add(alert_key)
                    print(f"ALERT: {ssid} | {bssid} | {alert}", flush=True)
                    event_logger.write("ALERT", ssid, bssid, rssi, channel, security, alert)
            other_bssids.add(bssid)

    for alert in rule_engine(ssid, bssid, rssi, channel, security, trusted_networks):
        alert_key = (ssid, bssid, alert.split(":", 1)[0])
        if alert_key in state["alerts"]:
            continue
        state["alerts"].add(alert_key)
        print(f"ALERT: {ssid or '<hidden SSID>'} | {bssid} | {alert}", flush=True)
        event_logger.write("ALERT", ssid, bssid, rssi, channel, security, alert)


def packet_callback(packet, trusted_networks, event_logger, state, dashboard_state=None):
    if not (packet.haslayer(Dot11Beacon) or packet.haslayer(Dot11ProbeResp)):
        return

    dot11 = packet.getlayer(Dot11)
    if dot11 is None or not dot11.addr2:
        return

    frame = packet.getlayer(Dot11Beacon) or packet.getlayer(Dot11ProbeResp)
    radio = packet.getlayer(RadioTap)
    process_access_point(
        get_ssid(frame),
        dot11.addr2,
        getattr(radio, "dBm_AntSignal", None) if radio else None,
        get_channel(packet),
        get_security_mode(frame, packet),
        trusted_networks,
        event_logger,
        state,
        dashboard_state,
    )


def scan_managed_interface(interface):
    result = subprocess.run(
        ["iw", "dev", interface, "scan"],
        check=True,
        text=True,
        capture_output=True,
        timeout=30,
    )
    return parse_iw_scan(result.stdout)


def managed_scan_loop(interface, interval, trusted_networks, event_logger, state, stop_event, dashboard_state=None):
    print(
        f"Scanning {interface} in managed mode every {interval:g} seconds. "
        "The Wi-Fi connection may briefly pause during each scan; press Ctrl+C to stop.",
        flush=True,
    )
    while not stop_event.is_set():
        if dashboard_state is not None:
            while not stop_event.is_set():
                with dashboard_state.lock:
                    running = dashboard_state.scanner_running
                if running:
                    break
                stop_event.wait(1)
            if stop_event.is_set():
                break
        try:
            access_points = scan_managed_interface(interface)
        except (OSError, subprocess.SubprocessError) as error:
            detail = getattr(error, "stderr", None) or str(error)
            print(f"Warning: managed-mode scan failed: {detail.strip()}", flush=True)
            if dashboard_state is not None:
                dashboard_state.record_scan([], detail.strip())
        else:
            print(f"Scan complete: {len(access_points)} AP(s) found.", flush=True)
            if dashboard_state is not None:
                dashboard_state.record_scan(access_points)
            for access_point in access_points:
                process_access_point(
                    access_point["ssid"],
                    access_point["bssid"],
                    access_point["rssi"],
                    access_point["channel"],
                    access_point["security"],
                    trusted_networks,
                    event_logger,
                    state,
                    dashboard_state,
                )
        interval = dashboard_state.scan_interval if dashboard_state is not None else interval
        elapsed = 0.0
        while elapsed < interval and not stop_event.is_set():
            delay = min(1.0, interval - elapsed)
            if stop_event.wait(delay):
                break
            elapsed += delay
            if dashboard_state is not None:
                with dashboard_state.lock:
                    running = dashboard_state.scanner_running
                if not running:
                    print("Managed scans paused by an administrator.", flush=True)
                    break


def channel_hopper(interface, stop_event, dwell_seconds):
    while not stop_event.is_set():
        for channel in CHANNELS:
            if stop_event.is_set():
                break
            try:
                result = subprocess.run(
                    ["iw", "dev", interface, "set", "channel", str(channel)],
                    text=True,
                    capture_output=True,
                )
            except OSError as error:
                print(f"Channel hopping stopped: could not run iw: {error}", flush=True)
                return
            if result.returncode:
                message = result.stderr.strip() or result.stdout.strip()
                print(f"Warning: could not select channel {channel}: {message}", flush=True)
            if stop_event.wait(dwell_seconds):
                break


def validate_dashboard_config(networks, scan_interval):
    if not isinstance(networks, dict):
        raise ValueError("trusted_networks must be a JSON object keyed by SSID")
    if type(scan_interval) not in (int, float) or not 5 <= scan_interval <= 3600:
        raise ValueError("scan_interval must be between 5 and 3600 seconds")
    for ssid, network in networks.items():
        if not isinstance(ssid, str) or not ssid or not isinstance(network, dict):
            raise ValueError("Each trusted network needs a non-empty SSID and an object of settings")
        bssid = network.get("bssid")
        if not isinstance(bssid, str) or not BSSID_PATTERN.fullmatch(bssid):
            raise ValueError(f"Trusted network {ssid!r} needs a valid colon-separated BSSID")
        channel = network.get("channel")
        if channel is not None and (type(channel) is not int or channel not in CHANNELS):
            raise ValueError(f"Trusted network {ssid!r} channel must be an integer from 1 to 13")
        threshold = network.get("rssi_threshold")
        if threshold is not None and (type(threshold) not in (int, float) or not -100 <= threshold <= 0):
            raise ValueError(f"Trusted network {ssid!r} RSSI threshold must be between -100 and 0 dBm")
        security = network.get("security")
        if security is not None and (not isinstance(security, str) or security not in SECURITY_MODES):
            raise ValueError(f"Trusted network {ssid!r} security must be one of {sorted(SECURITY_MODES)}")


def set_scanner_running(dashboard_state, value):
    if dashboard_state.scan_mode != "managed":
        raise RuntimeError("Scanner controls are available only in managed mode.")
    with dashboard_state.lock:
        dashboard_state.scanner_running = value


def start_dashboard(args, dashboard_state, trusted_networks, stop_event):
    password = os.environ.get("EVILTWIN_DASHBOARD_PASSWORD", "").strip()
    if args.dashboard_password_file:
        try:
            password = args.dashboard_password_file.read_text(encoding="utf-8").strip()
        except OSError as error:
            raise SystemExit(f"Could not read dashboard password file: {error}") from error
    if args.dashboard_host in ("0.0.0.0", "::") and password and not args.dashboard_cert:
        raise SystemExit("LAN dashboard controls require TLS; provide a certificate/key or run read-only.")
    if password and len(password) < 14:
        raise SystemExit("Dashboard password must be at least 14 characters")
    if bool(args.dashboard_cert) != bool(args.dashboard_key):
        raise SystemExit("Provide both --dashboard-cert and --dashboard-key for HTTPS")
    if password and not args.dashboard_cert:
        raise SystemExit("A dashboard password requires HTTPS; provide --dashboard-cert and --dashboard-key")

    def update_config(networks, scan_interval):
        validate_dashboard_config(networks, scan_interval)
        config_path = args.config
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_data = {"trusted_networks": networks}
        temp_path = None
        try:
            with tempfile.NamedTemporaryFile(
                "w", encoding="utf-8", dir=config_path.parent, prefix=f".{config_path.name}.",
                suffix=".tmp", delete=False,
            ) as temp_file:
                temp_path = Path(temp_file.name)
                json.dump(config_data, temp_file, indent=2)
                temp_file.write("\n")
                temp_file.flush()
                os.fsync(temp_file.fileno())
            load_trusted_networks(temp_path)
            os.replace(temp_path, config_path)
        finally:
            if temp_path is not None and temp_path.exists():
                temp_path.unlink()
        with dashboard_state.lock:
            trusted_networks.clear()
            trusted_networks.update(networks)
            dashboard_state.trusted_networks = trusted_networks
            dashboard_state.scan_interval = float(scan_interval)
        return {"trusted_networks": dict(trusted_networks), "scan_interval": float(scan_interval)}

    server = DashboardServer(
        args.dashboard_host,
        args.dashboard_port,
        password,
        dashboard_state.snapshot,
        dashboard_state.history,
        lambda: set_scanner_running(dashboard_state, True),
        lambda: set_scanner_running(dashboard_state, False),
        update_config,
        certfile=args.dashboard_cert,
        keyfile=args.dashboard_key,
    )
    try:
        server.start()
    except OSError as error:
        server.server.server_close()
        raise SystemExit(f"Could not start dashboard on {args.dashboard_host}:{args.dashboard_port}: {error}") from error
    scheme = "https" if args.dashboard_cert else "http"
    display_host = args.dashboard_host if args.dashboard_host not in ("0.0.0.0", "::") else "<Pi-address>"
    print(f"Dashboard: {scheme}://{display_host}:{server.address[1]}/", flush=True)
    if not password:
        print("Dashboard is read-only; set EVILTWIN_DASHBOARD_PASSWORD and configure TLS to enable controls.", flush=True)
    return server


def main():
    parser = argparse.ArgumentParser(description="Wi-Fi evil-twin detector")
    parser.add_argument("--interface", default="wlan0", help="wireless interface to scan (default: wlan0)")
    parser.add_argument(
        "--mode",
        choices=("monitor", "managed"),
        default="monitor",
        help="monitor-mode packet capture or periodic scans while connected (default: monitor)",
    )
    parser.add_argument("--dwell", type=float, default=1.0, help="seconds to spend on each channel in monitor mode")
    parser.add_argument(
        "--scan-interval",
        type=float,
        default=30.0,
        help="seconds between managed-mode scans (default: 30)",
    )
    parser.add_argument("--dashboard-host", default="127.0.0.1", help="dashboard bind address; use 0.0.0.0 to share on LAN")
    parser.add_argument("--dashboard-port", type=int, default=8080, help="dashboard TCP port (default: 8080)")
    parser.add_argument("--dashboard-password-file", type=Path, help="file containing a dashboard password (HTTPS required)")
    parser.add_argument("--dashboard-cert", type=Path, help="TLS certificate (required when dashboard password is set)")
    parser.add_argument("--dashboard-key", type=Path, help="TLS private key (required when dashboard password is set)")
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG, help="trusted network JSON configuration")
    parser.add_argument("--log", type=Path, default=DEFAULT_LOG, help="CSV event log path")
    args = parser.parse_args()
    if args.dwell <= 0:
        parser.error("--dwell must be greater than zero")
    if args.scan_interval <= 0:
        parser.error("--scan-interval must be greater than zero")

    try:
        trusted_networks = load_trusted_networks(args.config)
    except ValueError as error:
        raise SystemExit(str(error)) from error

    try:
        event_logger = EventLogger(args.log)
    except OSError as error:
        raise SystemExit(f"Could not open event log {args.log}: {error}") from error

    state = {"access_points": set(), "ssids": {}, "alerts": set()}
    stop_event = threading.Event()
    dashboard_state = DetectorState(args.scan_interval, args.mode)
    dashboard_state.trusted_networks = trusted_networks
    if args.log.exists():
        try:
            with args.log.open(newline="", encoding="utf-8") as existing_log:
                for row in csv.DictReader(existing_log):
                    dashboard_state.record_event({
                        "timestamp": row.get("timestamp", ""),
                        "event": row.get("event", ""),
                        "ssid": row.get("ssid", ""),
                        "bssid": row.get("bssid", ""),
                        "rssi": row.get("rssi_dbm", ""),
                        "channel": row.get("channel", ""),
                        "security": row.get("security", ""),
                        "message": row.get("message", ""),
                    })
        except OSError as error:
            event_logger.close()
            raise SystemExit(f"Could not read event history {args.log}: {error}") from error
    event_logger.on_write = dashboard_state.record_event
    dashboard_server = None
    print(
        f"Starting {args.mode}-mode detector on {args.interface} with {len(trusted_networks)} trusted network(s). "
        f"CSV log: {args.log}",
        flush=True,
    )

    if args.dashboard_port < 1 or args.dashboard_port > 65535:
        event_logger.close()
        parser.error("--dashboard-port must be between 1 and 65535")
    if args.dashboard_password_file and not args.dashboard_password_file.is_file():
        event_logger.close()
        parser.error("--dashboard-password-file must point to an existing file")

    if args.mode == "managed":
        dashboard_state.scanner_running = True
        dashboard_server = start_dashboard(args, dashboard_state, trusted_networks, stop_event)
        try:
            managed_scan_loop(
                args.interface,
                args.scan_interval,
                trusted_networks,
                event_logger,
                state,
                stop_event,
                dashboard_state,
            )
        except KeyboardInterrupt:
            pass
        finally:
            if dashboard_server is not None:
                dashboard_server.close()
            dashboard_state.scanner_running = False
            event_logger.close()
            print(
                f"Summary: {len(state['access_points'])} unique AP(s) observed; "
                f"{len(state['alerts'])} unique alert(s). CSV log: {args.log}",
                flush=True,
            )
            print("Stopped; managed Wi-Fi interface left in its original connection mode.", flush=True)
        return

    try:
        original_state = configure_monitor_mode(args.interface)
    except (OSError, RuntimeError, subprocess.CalledProcessError) as error:
        detail = getattr(error, "stderr", None) or str(error)
        event_logger.close()
        raise SystemExit(f"Could not enable monitor mode on {args.interface}: {detail}") from error

    dashboard_state.scanner_running = True
    try:
        dashboard_server = start_dashboard(args, dashboard_state, trusted_networks, stop_event)
    except BaseException:
        dashboard_state.scanner_running = False
        restore_interface(args.interface, original_state)
        event_logger.close()
        raise
    hopper = threading.Thread(
        target=channel_hopper,
        args=(args.interface, stop_event, args.dwell),
        daemon=True,
    )
    hopper.start()
    print("Scanning channels 1-13. Press Ctrl+C to stop.", flush=True)
    try:
        sniff(
            iface=args.interface,
            prn=lambda packet: packet_callback(packet, trusted_networks, event_logger, state, dashboard_state),
            store=False,
        )
    except KeyboardInterrupt:
        pass
    finally:
        stop_event.set()
        dashboard_state.scanner_running = False
        hopper.join(timeout=2)
        restore_interface(args.interface, original_state)
        if dashboard_server is not None:
            dashboard_server.close()
        event_logger.close()
        print(
            f"Summary: {len(state['access_points'])} unique AP(s) observed; "
            f"{len(state['alerts'])} unique alert(s). CSV log: {args.log}",
            flush=True,
        )
        print("Stopped; wireless interface restored where possible.", flush=True)


if __name__ == "__main__":
    main()
