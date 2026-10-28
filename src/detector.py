import argparse
import csv
import json
import os
import re
import subprocess
import tempfile
import threading
import time
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
        self.fingerprint_store = None

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
        key = (ap["ssid"], ap["bssid"])
        with self.lock:
            self.last_scan = now
            current = self.access_points.setdefault(key, {})
            first_seen = current.get("first_seen", now)
            current.update(ap)
            current["first_seen"] = first_seen
            current["last_seen"] = now
        try:
            fingerprint_update = self.fingerprint_store.observe(ap) if self.fingerprint_store else None
        except OSError as error:
            with self.lock:
                self.last_error = f"Fingerprint persistence failed: {error}"
            return None
        if fingerprint_update:
            with self.lock:
                if self.last_error.startswith("Fingerprint persistence failed:"):
                    self.last_error = ""

        if fingerprint_update:
            with self.lock:
                current = self.access_points.get(key)
                if current is not None:
                    current["fingerprint"] = fingerprint_update["fingerprint"]
        return fingerprint_update

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
                ap["rule_ids"] = list(dict.fromkeys(
                    match.group(1)
                    for finding in ap["findings"]
                    if (match := re.search(r"\b(R-\d+):", finding))
                ))
                expected = self.trusted_networks.get(ap.get("ssid", ""))
                ap["rule_count"] = len(ap["rule_ids"])
                ap["rule_capacity"] = (
                    1 + sum(expected.get(field) is not None for field in ("channel", "security", "rssi_threshold"))
                    if expected else 0
                )
                ap["heuristic_rule_score"] = (
                    min(100, round(ap["rule_count"] * 100 / ap["rule_capacity"]))
                    if expected else None
                )
                ap["trusted"] = bool(expected and ap.get("bssid", "").lower() == expected["bssid"].lower())
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
                        "frequency_mhz": ap.get("frequency_mhz"),
                        "band": ap.get("band", band_from_frequency(ap.get("frequency_mhz"))),
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
                "fingerprints": self.fingerprint_store.snapshot(
                    limit=100,
                    observed_after=time.time() - max(90, self.scan_interval * 3),
                ) if self.fingerprint_store else [],
                "fingerprint_count": self.fingerprint_store.count if self.fingerprint_store else 0,
            }



FINGERPRINT_VERSION = 1
FINGERPRINT_LEARNING_SIGHTINGS = 3
FINGERPRINT_MIN_INTERVAL_SECONDS = 20
FINGERPRINT_SIGNAL_DELTA_DB = 20
FINGERPRINT_MAX_RECORDS = 5000
FINGERPRINT_DRIFT_FIELDS = ("band", "channel", "security", "strong_signal")


class FingerprintStore:
    """Persist observed AP fingerprints as evidence, never as trusted identities."""

    def __init__(self, path, minimum_interval=FINGERPRINT_MIN_INTERVAL_SECONDS):
        self.path = Path(path)
        self.minimum_interval = minimum_interval
        self.lock = threading.RLock()
        self.records = {}
        self.dirty = False
        self.last_save = time.monotonic()
        if self.path.exists():
            try:
                with self.path.open(encoding="utf-8") as fingerprint_file:
                    data = json.load(fingerprint_file)
            except (OSError, json.JSONDecodeError) as error:
                raise ValueError(f"Could not load fingerprint store {self.path}: {error}") from error
            if not isinstance(data, dict) or data.get("version") != FINGERPRINT_VERSION or not isinstance(data.get("networks"), dict):
                raise ValueError(f"Fingerprint store {self.path} has an unsupported or invalid format")
            records = data["networks"]
            if len(records) > FINGERPRINT_MAX_RECORDS:
                raise ValueError(f"Fingerprint store {self.path} exceeds the {FINGERPRINT_MAX_RECORDS}-record limit")
            for key, record in records.items():
                if not isinstance(record, dict) or not isinstance(record.get("ssid"), str) or not isinstance(record.get("bssid"), str):
                    raise ValueError(f"Fingerprint store {self.path} contains an invalid AP record")
                if key != self._key(record["ssid"], record["bssid"]):
                    raise ValueError(f"Fingerprint store {self.path} contains an inconsistent AP key")
                baseline = record.get("baseline")
                if baseline is not None and not isinstance(baseline, dict):
                    raise ValueError(f"Fingerprint store {self.path} contains an invalid baseline")
                if baseline is not None:
                    if baseline.get("band") not in (None, "Unknown", "2.4 GHz", "5 GHz", "6 GHz"):
                        raise ValueError(f"Fingerprint store {self.path} contains an invalid baseline band")
                    if baseline.get("security") is not None and baseline.get("security") not in SECURITY_MODES:
                        raise ValueError(f"Fingerprint store {self.path} contains an invalid baseline security mode")
                active = record.get("active_drift", {})
                streaks = record.get("drift_streaks", {})
                samples = record.get("samples", [])
                if not isinstance(active, dict) or not isinstance(streaks, dict):
                    raise ValueError(f"Fingerprint store {self.path} contains invalid drift state")
                if not isinstance(samples, list) or len(samples) > FINGERPRINT_LEARNING_SIGHTINGS or any(not isinstance(sample, dict) for sample in samples):
                    raise ValueError(f"Fingerprint store {self.path} contains invalid AP samples")
                if type(record.get("sightings", 0)) is not int or record.get("sightings", 0) < 0:
                    raise ValueError(f"Fingerprint store {self.path} contains an invalid sightings count")
                for timestamp_field in ("last_sample_epoch", "last_seen_epoch"):
                    timestamp = record.get(timestamp_field, 0)
                    if type(timestamp) not in (int, float) or not 0 <= timestamp < float("inf"):
                        raise ValueError(f"Fingerprint store {self.path} contains an invalid {timestamp_field}")
                for field, value in streaks.items():
                    if field not in FINGERPRINT_DRIFT_FIELDS or type(value) is not int or value < 0:
                        raise ValueError(f"Fingerprint store {self.path} contains invalid drift counters")
                for field, change in active.items():
                    if field not in FINGERPRINT_DRIFT_FIELDS or not isinstance(change, dict):
                        raise ValueError(f"Fingerprint store {self.path} contains invalid drift evidence")
                for sample in samples:
                    if sample.get("band") not in (None, "Unknown", "2.4 GHz", "5 GHz", "6 GHz"):
                        raise ValueError(f"Fingerprint store {self.path} contains an invalid band sample")
                    channel = sample.get("channel")
                    if channel is not None and (type(channel) is not int or not 1 <= channel <= 233):
                        raise ValueError(f"Fingerprint store {self.path} contains an invalid channel sample")
                    security = sample.get("security")
                    if security is not None and security not in SECURITY_MODES:
                        raise ValueError(f"Fingerprint store {self.path} contains an invalid security sample")
            self.records = records

    @staticmethod
    def _key(ssid, bssid):
        return json.dumps([ssid, bssid.lower()], ensure_ascii=False, separators=(",", ":"))

    @staticmethod
    def _sample(ap):
        rssi = ap.get("rssi")
        if isinstance(rssi, bool) or not isinstance(rssi, (int, float)) or not -127 <= rssi <= 0:
            rssi = None
        frequency_mhz = ap.get("frequency_mhz")
        if isinstance(frequency_mhz, bool) or not isinstance(frequency_mhz, (int, float)) or not 2400 <= frequency_mhz <= 7125:
            frequency_mhz = None
        band = ap.get("band")
        if band not in ("2.4 GHz", "5 GHz", "6 GHz"):
            band = band_from_frequency(frequency_mhz)
        channel = ap.get("channel")
        if type(channel) is not int or not 1 <= channel <= 233:
            channel = None
        security = ap.get("security")
        if security not in SECURITY_MODES:
            security = "Unknown"
        return {
            "band": band,
            "channel": channel,
            "frequency_mhz": frequency_mhz,
            "security": security,
            "rssi": rssi,
        }

    @staticmethod
    def _median(values):
        values = sorted(values)
        if not values:
            return None
        middle = len(values) // 2
        if len(values) % 2:
            return values[middle]
        return round((values[middle - 1] + values[middle]) / 2, 1)

    def _save(self, force=False):
        if not self.dirty:
            return
        now = time.monotonic()
        if not force and now - self.last_save < 5:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary_path = None
        try:
            with tempfile.NamedTemporaryFile(
                "w", encoding="utf-8", dir=self.path.parent,
                prefix=f".{self.path.name}.", suffix=".tmp", delete=False,
            ) as temporary_file:
                temporary_path = Path(temporary_file.name)
                json.dump({"version": FINGERPRINT_VERSION, "networks": self.records}, temporary_file, ensure_ascii=False, indent=2)
                temporary_file.write("\n")
                temporary_file.flush()
                os.fsync(temporary_file.fileno())
            os.chmod(temporary_path, 0o600)
            os.replace(temporary_path, self.path)
        finally:
            if temporary_path is not None and temporary_path.exists():
                temporary_path.unlink()
        self.dirty = False
        self.last_save = now

    def flush(self):
        with self.lock:
            self._save(force=True)

    def observe(self, ap):
        if not isinstance(ap, dict) or not isinstance(ap.get("ssid"), str) or not isinstance(ap.get("bssid"), str):
            raise ValueError("Fingerprint observations require string SSID and BSSID values")
        now_epoch = time.time()
        now_iso = datetime.now(timezone.utc).isoformat()
        key = self._key(ap["ssid"], ap["bssid"])
        sample = self._sample(ap)
        with self.lock:
            record = self.records.get(key)
            if record is None:
                if len(self.records) >= FINGERPRINT_MAX_RECORDS:
                    oldest_key = min(self.records, key=lambda existing: self.records[existing].get("last_seen_epoch", 0))
                    del self.records[oldest_key]
                record = {
                    "ssid": ap["ssid"], "bssid": ap["bssid"], "first_seen": now_iso,
                    "last_seen": now_iso, "last_seen_epoch": now_epoch,
                    "last_sample_epoch": now_epoch - self.minimum_interval, "sightings": 0,
                    "samples": [], "baseline": None,
                    "drift_streaks": {field: 0 for field in FINGERPRINT_DRIFT_FIELDS},
                    "active_drift": {},
                }
                self.records[key] = record
            record["last_seen"] = now_iso
            record["last_seen_epoch"] = now_epoch
            self.dirty = True
            if now_epoch - float(record.get("last_sample_epoch", 0)) < self.minimum_interval:
                self._save()
                return {"fingerprint": self._public_record(record), "newly_confirmed": []}

            record["last_sample_epoch"] = now_epoch
            record["sightings"] = int(record.get("sightings", 0)) + 1
            record["samples"] = (record.get("samples", []) + [sample])[-FINGERPRINT_LEARNING_SIGHTINGS:]
            newly_confirmed = []
            if record.get("baseline") is None:
                if record["sightings"] >= FINGERPRINT_LEARNING_SIGHTINGS:
                    samples = record["samples"]
                    baseline = {}
                    for field in ("band", "channel", "frequency_mhz", "security"):
                        values = [item.get(field) for item in samples if item.get(field) is not None and (field == "security" or item.get(field) != "Unknown")]
                        if field == "security":
                            baseline[field] = max(set(values), key=values.count) if values else "Unknown"
                        else:
                            baseline[field] = self._median(values)
                    baseline["rssi_dbm"] = self._median([item["rssi"] for item in samples if item.get("rssi") is not None])
                    baseline["learned_at"] = now_iso
                    record["baseline"] = baseline
                    record["samples"] = []
                    record["drift_streaks"] = {field: 0 for field in FINGERPRINT_DRIFT_FIELDS}
                    record["active_drift"] = {}
            else:
                recent_samples = record.setdefault("samples", [])
                recent_samples.append(sample)
                record["samples"] = recent_samples[-FINGERPRINT_LEARNING_SIGHTINGS:]
                baseline = record["baseline"]
                changed = {}
                for field in ("band", "channel", "security"):
                    expected = baseline.get(field)
                    observed = sample.get(field)
                    if expected not in (None, "Unknown") and observed not in (None, "Unknown") and expected != observed:
                        changed[field] = {"baseline": expected, "observed": observed}
                baseline_rssi = baseline.get("rssi_dbm")
                observed_rssi = sample.get("rssi")
                if baseline_rssi is not None and observed_rssi is not None and observed_rssi >= baseline_rssi + FINGERPRINT_SIGNAL_DELTA_DB:
                    changed["strong_signal"] = {
                        "baseline": baseline_rssi, "observed": observed_rssi,
                        "threshold_db": FINGERPRINT_SIGNAL_DELTA_DB,
                    }
                drift_streaks = record.setdefault("drift_streaks", {field: 0 for field in FINGERPRINT_DRIFT_FIELDS})
                previous_active = record.get("active_drift", {})
                active = {}
                for field in FINGERPRINT_DRIFT_FIELDS:
                    if field in changed:
                        drift_streaks[field] = int(drift_streaks.get(field, 0)) + 1
                    else:
                        drift_streaks[field] = 0
                    if drift_streaks[field] >= FINGERPRINT_LEARNING_SIGHTINGS:
                        active[field] = {**changed[field], "consecutive_sightings": drift_streaks[field]}
                        if field not in previous_active:
                            newly_confirmed.append(active[field] | {"field": field})
                record["active_drift"] = active

            should_save_baseline = record.get("baseline") is not None and record["sightings"] == FINGERPRINT_LEARNING_SIGHTINGS
            self._save(force=bool(newly_confirmed) or should_save_baseline)
            return {"fingerprint": self._public_record(record), "newly_confirmed": newly_confirmed}

    def snapshot(self, limit=None, observed_after=None):
        with self.lock:
            records = sorted(self.records.values(), key=lambda record: record.get("last_seen_epoch", 0), reverse=True)
            if limit is not None:
                records = records[:limit]
            result = []
            for record in records:
                public = self._public_record(record)
                public["currently_observed"] = (
                    observed_after is not None
                    and float(record.get("last_seen_epoch", 0)) >= observed_after
                )
                result.append(public)
            return result

    @property
    def count(self):
        with self.lock:
            return len(self.records)

    @staticmethod
    def _public_record(record):
        return {
            "ssid": record.get("ssid", ""),
            "bssid": record.get("bssid", ""),
            "status": "learning" if record.get("baseline") is None else "drift" if record.get("active_drift") else "baseline",
            "sightings": int(record.get("sightings", 0)),
            "required_sightings": FINGERPRINT_LEARNING_SIGHTINGS,
            "minimum_interval_seconds": FINGERPRINT_MIN_INTERVAL_SECONDS,
            "baseline": dict(record["baseline"]) if record.get("baseline") else None,
            "latest": dict(record["samples"][-1]) if record.get("samples") else {},
            "changed_fields": {field: dict(change) for field, change in record.get("active_drift", {}).items()},
            "first_seen": record.get("first_seen"),
            "last_seen": record.get("last_seen"),
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
    frequency_mhz = get_radio_frequency(packet)
    frame = packet.getlayer(Dot11Beacon) or packet.getlayer(Dot11ProbeResp)
    channel = channel_from_frequency(frequency_mhz) if frequency_mhz is not None else None
    for element_id, info in information_elements(frame) if frame is not None else ():
        if element_id == 3 and info:
            channel = info[0]
    return channel


def get_radio_frequency(packet):
    radio = packet.getlayer(RadioTap)
    frequency = getattr(radio, "ChannelFrequency", None) if radio else None
    return int(frequency) if isinstance(frequency, (int, float)) and frequency > 0 else None


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


def band_from_frequency(frequency_mhz):
    if frequency_mhz is None:
        return "Unknown"
    if 2400 <= frequency_mhz < 2500:
        return "2.4 GHz"
    if 4900 <= frequency_mhz < 5925:
        return "5 GHz"
    if 5925 <= frequency_mhz <= 7125:
        return "6 GHz"
    return "Unknown"


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
                "frequency_mhz": None,
                "band": "Unknown",
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
                frequency_mhz = round(float(value))
                access_point["frequency_mhz"] = frequency_mhz
                access_point["channel"] = channel_from_frequency(frequency_mhz)
                access_point["band"] = band_from_frequency(frequency_mhz)
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


def process_access_point(ssid, bssid, rssi, channel, security, trusted_networks, event_logger, state, dashboard_state=None, frequency_mhz=None):
    band = band_from_frequency(frequency_mhz)
    fingerprint_update = None
    if dashboard_state is not None:
        fingerprint_update = dashboard_state.observe_access_point({
            "ssid": ssid,
            "bssid": bssid,
            "rssi": rssi,
            "channel": channel,
            "frequency_mhz": frequency_mhz,
            "band": band,
            "security": security,
        })
    if fingerprint_update:
        for change in fingerprint_update["newly_confirmed"]:
            message = (
                f"[MEDIUM] R-07: Persistent RF fingerprint drift confirmed after "
                f"{FINGERPRINT_LEARNING_SIGHTINGS} spaced observations: {change['field']} "
                f"changed (baseline {change['baseline']}; observed {change['observed']})"
            )
            print(f"ALERT: {ssid or '<hidden SSID>'} | {bssid} | {message}", flush=True)
            event_logger.write("ALERT", ssid, bssid, rssi, channel, security, message)
    network_key = (ssid, bssid)
    if network_key not in state["access_points"]:
        state["access_points"].add(network_key)
        signal = f"{rssi} dBm" if rssi is not None else "RSSI unavailable"
        radio = f"{band} · {frequency_mhz} MHz · channel {channel}" if frequency_mhz is not None else f"band unavailable · channel {channel if channel is not None else 'unavailable'}"
        print(f"AP: {ssid or '<hidden SSID>'} | {bssid} | {signal} | {radio} | {security}", flush=True)
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
        get_radio_frequency(packet),
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
                    access_point.get("frequency_mhz"),
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
    parser.add_argument(
        "--fingerprints", type=Path, default=PROJECT_ROOT / "logs" / "fingerprints.json",
        help="persistent observational AP fingerprint store (never an authorization list)",
    )
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
    try:
        dashboard_state.fingerprint_store = FingerprintStore(args.fingerprints)
    except (OSError, ValueError) as error:
        event_logger.close()
        raise SystemExit(str(error)) from error
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
            dashboard_state.fingerprint_store.flush()
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
        dashboard_state.fingerprint_store.flush()
        print("Stopped; wireless interface restored where possible.", flush=True)


if __name__ == "__main__":
    main()
