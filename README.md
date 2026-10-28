# Evil Twin Wi-Fi Detection

A deterministic Wi-Fi monitoring system that detects suspicious access points by comparing live 802.11 observations against trusted network definitions.

This project is built for Raspberry Pi and similar Linux hosts, and supports both:
- **Monitor mode capture** (packet sniffing + channel hopping)
- **Managed mode scans** (periodic `iw` scans while staying connected)

It also includes a local dashboard with read-only monitoring by default, and optional authenticated admin controls over HTTPS.

---

## 1) What problem this solves

An **evil twin** attack copies the SSID of a legitimate network to trick users into connecting to a rogue AP.

This detector does **not** rely on opaque ML models. It uses explicit protocol and radio checks, so each alert explains exactly what was observed and why it was flagged.

---

## 2) Core capabilities

### 2.1 Real-time AP observation
- Captures beacon/probe-response information.
- Tracks AP identity by `(SSID, BSSID)`.
- Records radio and security metadata:
  - RSSI (`dBm_AntSignal` when available)
  - Channel
  - Frequency (MHz)
  - Derived band (`2.4 GHz`, `5 GHz`, `6 GHz`, or `Unknown`)
  - Security mode (`Open`, `WEP`, `WPA`, `WPA2/3`)

### 2.2 Deterministic rule engine (R-01, R-02, R-04, R-05, R-06, R-07)
The detector evaluates each observed AP against trusted configuration and learned fingerprint state.

- **R-01 [HIGH]**: BSSID mismatch for a trusted SSID.
- **R-02 [HIGH]**: Signal significantly stronger than configured threshold (`threshold + 10 dB`).
- **R-04 [HIGH]**: Security mode mismatch from trusted profile.
- **R-05 [MEDIUM]**: Channel mismatch from trusted profile.
- **R-06 [MEDIUM]**: Multiple BSSIDs advertising the same SSID.
- **R-07 [MEDIUM]**: Persistent fingerprint drift (band/channel/security/strong-signal drift confirmed across spaced observations).

### 2.3 Persistent RF fingerprinting (observational, not authorization)
- Stored in `logs/fingerprints.json`.
- Learns baseline after **3 spaced sightings** (`>=20s` apart).
- Confirms drift only after **3 consecutive spaced drift observations**.
- Baselines are not silently overwritten.
- Record store is capped (`5000` AP records, oldest evicted first when full).

### 2.4 Operational telemetry
- CSV event log (`logs/detector.csv`) with AP and ALERT events.
- In-memory dashboard history (bounded).
- Startup/shutdown summaries.

### 2.5 Dashboard
- Live AP list, findings, and event timeline.
- Twin comparison view (trusted vs observed).
- Fingerprint baseline/drift view.
- RF spectrum/band channel distribution view.
- Admin controls (optional, HTTPS + password required):
  - Start/stop scans in managed mode
  - Validate/save trusted network config + scan interval

---

## 3) Repository layout

```text
.
├── config/
│   └── trusted_networks.json
├── docs/
│   ├── ARCHITECTURE.md
│   ├── EXPLANATION.md
│   ├── HEADLESS_GUIDE.md
│   ├── UBUNTU_SETUP.md
│   ├── FEATURE_REFERENCE.md
│   └── CONFIG_AND_DATA_REFERENCE.md
└── src/
    ├── detector.py
    ├── dashboard.py
    └── dashboard.html
```

---

## 4) Requirements

- Linux host with wireless adapter access (`iw`, `ip` utilities)
- Python 3
- Scapy (`python3-scapy` on Debian/Ubuntu)
- Elevated privileges for scan operations (`sudo`)

Install essentials on Ubuntu/Debian:

```bash
sudo apt update
sudo apt install -y python3-scapy iw iproute2
```

---

## 5) Trusted network configuration

Edit `config/trusted_networks.json`.

```json
{
  "trusted_networks": {
    "MyNetwork": {
      "bssid": "00:11:22:33:44:55",
      "channel": 6,
      "rssi_threshold": -60,
      "security": "WPA2/3"
    }
  }
}
```

Validation constraints:
- `trusted_networks`: object keyed by SSID
- `bssid`: required, MAC format `aa:bb:cc:dd:ee:ff`
- `channel`: optional, integer `1..13`
- `rssi_threshold`: optional, `-100..0`
- `security`: optional, one of `Open | WEP | WPA | WPA2/3`

Detailed property semantics: see `docs/CONFIG_AND_DATA_REFERENCE.md`.

---

## 6) Running the detector

### 6.1 Monitor mode (default)

```bash
sudo python3 src/detector.py --interface wlan0
```

Behavior:
- Interface switched to monitor mode.
- Channel hopper cycles channels `1..13` using `--dwell` delay.
- Sniffs Dot11 beacon/probe-response frames.
- On exit, attempts to restore original interface type/link state.

### 6.2 Managed mode

```bash
sudo python3 src/detector.py --interface wlan0 --mode managed --scan-interval 30
```

Behavior:
- Keeps interface in managed operation.
- Runs periodic `iw dev <iface> scan`.
- May briefly interrupt connectivity during scan cycles.
- Dashboard scan controls can pause/resume managed scans.

---

## 7) CLI reference

```bash
python3 src/detector.py [options]
```

- `--interface` (default `wlan0`): scan interface
- `--mode` (`monitor` or `managed`, default `monitor`)
- `--dwell` (default `1.0`): channel dwell seconds in monitor mode
- `--scan-interval` (default `30.0`): managed-mode interval seconds
- `--dashboard-host` (default `127.0.0.1`)
- `--dashboard-port` (default `8080`, valid `1..65535`)
- `--dashboard-password-file`: password file for admin controls
- `--dashboard-cert`: TLS certificate path
- `--dashboard-key`: TLS private key path
- `--config` (default `config/trusted_networks.json`)
- `--log` (default `logs/detector.csv`)
- `--fingerprints` (default `logs/fingerprints.json`)

---

## 8) Dashboard security model

### Read-only mode (default)
- No password configured.
- Anyone with network reach can view telemetry.
- No write/admin actions available.

### Admin mode (hardened)
Requires all of the following:
1. Password configured
2. HTTPS enabled (`--dashboard-cert` + `--dashboard-key`)
3. Secure session + CSRF token checks

Security controls implemented:
- TLS required for sign-in and admin endpoints
- Password minimum length checks
- Rate limiting for login attempts (per client)
- Session cookie hardening (`HttpOnly`, `Secure`, `SameSite=Strict`)
- CSP, HSTS (when TLS), frame protection, no-sniff headers
- Origin checks for POST requests

---

## 9) How findings should be interpreted

This project is a **detection aid**, not an autonomous verdict engine.

Important interpretation points:
- Multiple BSSIDs can be legitimate (mesh/repeaters/enterprise AP groups).
- Channel/security changes may be caused by router reconfiguration.
- Signal anomalies can reflect proximity or RF conditions.
- Fingerprint drift indicates a sustained change pattern, not immediate proof of compromise.

Use findings for investigation and verification against operational context.

---

## 10) Logs and persisted data

### 10.1 CSV event log (`logs/detector.csv`)
Columns:
- `timestamp`, `event`, `ssid`, `bssid`, `rssi_dbm`, `channel`, `security`, `message`

### 10.2 Fingerprint store (`logs/fingerprints.json`)
Contains:
- Version marker
- AP records keyed by normalized SSID/BSSID tuple
- Baseline attributes + drift counters/evidence
- First/last seen metadata and sample windows

Full schema-level explanation: `docs/CONFIG_AND_DATA_REFERENCE.md`.

---

## 11) Operations guidance

- Prefer Ethernet management when using monitor mode on onboard Wi-Fi.
- If headless over Wi-Fi, use a second adapter for monitor capture.
- Keep trusted network values accurate and current.
- Protect `logs/` artifacts as sensitive local telemetry.

See:
- `docs/HEADLESS_GUIDE.md`
- `docs/UBUNTU_SETUP.md`
- `docs/ARCHITECTURE.md`

---

## 12) Limitations

- Rule logic focuses on management-frame observations, not full traffic analysis.
- Internal adapter capabilities vary by hardware/driver/regulatory domain.
- Default channel hopper scope is channels 1–13.
- Reliability depends on scan visibility and RF conditions.

---

## 13) Extended documentation map

- `docs/FEATURE_REFERENCE.md` — deep explanation of each system feature
- `docs/CONFIG_AND_DATA_REFERENCE.md` — property-by-property config/data reference
- `docs/ARCHITECTURE.md` — architecture and pipeline framing
- `docs/EXPLANATION.md` — high-level conceptual explanation
- `docs/HEADLESS_GUIDE.md` — remote/headless operation patterns
- `docs/UBUNTU_SETUP.md` — installation and runtime setup on Ubuntu Server

