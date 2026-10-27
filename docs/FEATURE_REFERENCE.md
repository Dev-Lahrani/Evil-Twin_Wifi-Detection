# Feature Reference (Deep Dive)

This document explains each major feature in implementation terms and operational terms.

## 1) Dual scanning architecture

The detector supports two scanning paths from one CLI:

1. **Monitor mode path**
   - Puts interface into monitor mode.
   - Sniffs Dot11 management frames continuously.
   - Uses channel hopping to sample channels 1–13.

2. **Managed mode path**
   - Keeps interface in managed operation.
   - Executes periodic `iw dev <iface> scan`.
   - Parses scan output into AP observations.

Why this matters:
- Monitor mode gives continuous passive capture behavior.
- Managed mode can work when staying associated is important.

---

## 2) Packet and frame parsing

### Monitor mode source
Only beacon and probe-response frames are processed:
- `Dot11Beacon`
- `Dot11ProbeResp`

### Extracted fields
Per AP observation:
- SSID from information element 0
- BSSID from `Dot11.addr2`
- Signal from radiotap `dBm_AntSignal` (when available)
- Frequency from radiotap `ChannelFrequency` (when available)
- Channel from DS parameter IE when available, otherwise from frequency mapping
- Security inferred from RSN/WPA information elements and privacy capability bit

Design detail:
- Frequency-to-channel conversion handles 2.4/5/6 GHz ranges.
- Band derivation is calculated from frequency into `2.4 GHz`, `5 GHz`, `6 GHz`, or `Unknown`.

---

## 3) Deterministic rule engine

The rules run whenever an AP is observed and a trusted SSID match exists.

### R-01: BSSID mismatch (`HIGH`)
If observed BSSID differs from trusted BSSID for same SSID, detector flags impersonation risk.

### R-02: Strong signal anomaly (`HIGH`)
If observed RSSI is greater than configured threshold + 10 dB, detector raises an anomaly.

### R-04: Security mismatch (`HIGH`)
If observed security mode differs from expected mode, detector flags downgrade/clone risk.

### R-05: Channel mismatch (`MEDIUM`)
If observed channel differs from configured channel, detector flags off-channel behavior.

### R-06: Multiple BSSIDs for one SSID (`MEDIUM`)
If detector sees multiple BSSIDs for same SSID, it emits a review alert (mesh can be benign).

### R-07: Persistent RF fingerprint drift (`MEDIUM`)
After baseline learning, drift is tracked for:
- band
- channel
- security
- strong signal jump

Drift only becomes a confirmed alert after repeated spaced observations.

---

## 4) Alert deduplication behavior

The runtime state keeps alert keys so repeated sightings do not flood logs with identical finding categories for the same AP.

Benefit:
- Better signal-to-noise in terminal output, CSV history, and dashboard timelines.

---

## 5) AP lifecycle and state model

Runtime tracks:
- unique AP tuples `(SSID, BSSID)`
- SSID to observed BSSID set
- alert signatures already emitted

Each AP state includes:
- first seen timestamp
- last seen timestamp
- latest radio/security fields

This supports both immediate detection and meaningful dashboard history.

---

## 6) Event logging subsystem

All AP discoveries and alerts are persisted to CSV with UTC timestamps.

Event types:
- `AP` — first discovery event for a unique `(SSID, BSSID)` pair
- `ALERT` — rule-triggered finding or confirmed fingerprint drift

The event stream is also fed into dashboard history for near-real-time review.

---

## 7) Fingerprint learning and drift detection

Fingerprinting is intentionally conservative:

- Learning requires 3 sightings separated by a minimum interval (default 20s).
- Baseline fields are learned from recent samples:
  - `band`
  - `channel`
  - `frequency_mhz`
  - `security`
  - median `rssi_dbm`
- Drift counters track consecutive spaced deviations.
- Drift is confirmed only after 3 consecutive spaced mismatches.

Persistence behavior:
- Atomic writes using temp file + replace.
- Restrictive permissions on persisted file.
- Store cap (5000 records).

Operational interpretation:
- Drift is a sustained-change indicator, not guaranteed malicious proof.

---

## 8) Dashboard views and feature behavior

### 8.1 Station summary metrics
- Networks seen
- Open networks
- Warning count
- Last scan status

### 8.2 Twin comparison panel
For each configured trusted SSID, dashboard shows expected profile and observed APs with match/diff flags for:
- BSSID
- channel
- security
- signal threshold context

### 8.3 Fingerprint panel
Shows learned baseline status:
- `learning`
- `baseline`
- `drift`

Displays changed fields and observation recency.

### 8.4 RF spectrum intelligence panel
Aggregates observed APs by radio band and channel occupancy counts for local situational awareness.

### 8.5 Observed networks table
Filterable table with AP and finding details.

### 8.6 Scan record timeline
Recent events (AP + ALERT) in reverse chronology.

---

## 9) Administrator controls

Admin controls are optional and available only when secured:
- Sign in/out
- Start/pause scans (managed mode only)
- Validate and save trusted network JSON + scan interval

Validation and persistence:
- Incoming config is validated before write.
- Config save uses atomic write workflow.
- Runtime trusted-network map and interval update immediately after successful save.

---

## 10) Safety and resilience features

- Interface state restoration on monitor-mode exit.
- Command failure handling around `iw`/`ip` operations.
- Bounded in-memory history to avoid unbounded growth.
- JSON body size limits and strict object parsing for dashboard APIs.
- CSRF and origin checks for state-changing requests.

---

## 11) Feature boundaries

What this tool does well:
- Explainable AP anomaly detection from management-plane observations.
- Local operational awareness with durable telemetry.

What this tool does not attempt:
- Traffic payload inspection or credential interception.
- Autonomous network blocking.
- Global threat attribution.

