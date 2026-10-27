import argparse
import csv
import json
import re
import subprocess
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from scapy.all import Dot11, Dot11Beacon, Dot11Elt, Dot11ProbeResp, RadioTap, sniff

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CONFIG = PROJECT_ROOT / "config" / "trusted_networks.json"
DEFAULT_LOG = PROJECT_ROOT / "logs" / "detector.csv"
CHANNELS = tuple(range(1, 14))
SECURITY_MODES = {"Open", "WEP", "WPA", "WPA2/3"}
BSSID_PATTERN = re.compile(r"^(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$")


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


def get_channel(packet):
    frame = packet.getlayer(Dot11Beacon) or packet.getlayer(Dot11ProbeResp)
    if frame is None:
        return None
    for element_id, info in information_elements(frame):
        if element_id == 3 and info:
            return info[0]
    return None


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
    if bssid.lower() != network["bssid"].lower():
        alerts.append("[HIGH] R-01: BSSID mismatch for trusted SSID")

    threshold = network.get("rssi_threshold")
    if rssi is not None and threshold is not None and rssi > threshold + 10:
        alerts.append(f"[HIGH] R-02: Suspiciously high signal strength ({rssi} dBm)")

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

    def close(self):
        self.file.close()


def packet_callback(packet, trusted_networks, event_logger, state):
    if not (packet.haslayer(Dot11Beacon) or packet.haslayer(Dot11ProbeResp)):
        return

    dot11 = packet.getlayer(Dot11)
    if dot11 is None or not dot11.addr2:
        return

    frame = packet.getlayer(Dot11Beacon) or packet.getlayer(Dot11ProbeResp)
    ssid = frame.info.decode("utf-8", errors="replace")
    bssid = dot11.addr2
    radio = packet.getlayer(RadioTap)
    rssi = getattr(radio, "dBm_AntSignal", None) if radio else None
    channel = get_channel(packet)
    security = get_security_mode(frame, packet)
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
        alert_key = (ssid, bssid, alert)
        if alert_key in state["alerts"]:
            continue
        state["alerts"].add(alert_key)
        print(f"ALERT: {ssid or '<hidden SSID>'} | {bssid} | {alert}", flush=True)
        event_logger.write("ALERT", ssid, bssid, rssi, channel, security, alert)


def channel_hopper(interface, stop_event, dwell_seconds):
    while not stop_event.is_set():
        for channel in CHANNELS:
            if stop_event.is_set():
                break
            result = subprocess.run(
                ["iw", "dev", interface, "set", "channel", str(channel)],
                text=True,
                capture_output=True,
            )
            if result.returncode:
                message = result.stderr.strip() or result.stdout.strip()
                print(f"Warning: could not select channel {channel}: {message}", flush=True)
            if stop_event.wait(dwell_seconds):
                break


def main():
    parser = argparse.ArgumentParser(description="Passive Wi-Fi evil-twin detector")
    parser.add_argument("--interface", default="wlan0", help="wireless interface to scan (default: wlan0)")
    parser.add_argument("--dwell", type=float, default=1.0, help="seconds to spend on each channel (default: 1)")
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG, help="trusted network JSON configuration")
    parser.add_argument("--log", type=Path, default=DEFAULT_LOG, help="CSV event log path")
    args = parser.parse_args()
    if args.dwell <= 0:
        parser.error("--dwell must be greater than zero")

    try:
        trusted_networks = load_trusted_networks(args.config)
    except ValueError as error:
        raise SystemExit(str(error)) from error

    try:
        event_logger = EventLogger(args.log)
    except OSError as error:
        raise SystemExit(f"Could not open event log {args.log}: {error}") from error

    print(
        f"Starting passive detector on {args.interface} with {len(trusted_networks)} trusted network(s). "
        f"CSV log: {args.log}",
        flush=True,
    )
    try:
        original_state = configure_monitor_mode(args.interface)
    except (OSError, RuntimeError, subprocess.CalledProcessError) as error:
        detail = getattr(error, "stderr", None) or str(error)
        event_logger.close()
        raise SystemExit(f"Could not enable monitor mode on {args.interface}: {detail}") from error

    state = {"access_points": set(), "ssids": {}, "alerts": set()}
    stop_event = threading.Event()
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
            prn=lambda packet: packet_callback(packet, trusted_networks, event_logger, state),
            store=False,
        )
    except KeyboardInterrupt:
        pass
    finally:
        stop_event.set()
        hopper.join(timeout=2)
        restore_interface(args.interface, original_state)
        event_logger.close()
        print(
            f"Summary: {len(state['access_points'])} unique AP(s) observed; "
            f"{len(state['alerts'])} unique alert(s). CSV log: {args.log}",
            flush=True,
        )
        print("Stopped; wireless interface restored where possible.", flush=True)


if __name__ == "__main__":
    main()
