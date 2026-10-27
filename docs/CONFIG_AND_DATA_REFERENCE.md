# Configuration and Data Reference

This document provides property-level reference for runtime inputs, persistence files, and dashboard API payloads.

## 1) Trusted network config (`config/trusted_networks.json`)

Top-level object:

- `trusted_networks` (object, required)
  - Keys are SSID strings.
  - Values are per-network configuration objects.

Per-network properties:

- `bssid` (string, required)
  - Format: lowercase or uppercase colon-separated MAC (`xx:xx:xx:xx:xx:xx`).
  - Used by rule R-01 for identity matching.

- `channel` (integer, optional)
  - Allowed range: `1..13`.
  - Used by rule R-05.

- `rssi_threshold` (number, optional)
  - Allowed range: `-100..0` dBm.
  - Used by rule R-02 with alert limit = `threshold + 10`.

- `security` (string, optional)
  - Allowed values: `Open`, `WEP`, `WPA`, `WPA2/3`.
  - Used by rule R-04.

Validation notes:
- SSID key must be a non-empty string.
- Unknown properties are preserved in JSON but not used by detector logic.

---

## 2) Event CSV (`logs/detector.csv`)

Columns written by `EventLogger`:

- `timestamp` (ISO 8601 UTC)
- `event` (`AP` or `ALERT`)
- `ssid` (string; may be empty for hidden SSIDs)
- `bssid` (string)
- `rssi_dbm` (number or empty)
- `channel` (number or empty)
- `security` (`Open`, `WEP`, `WPA`, `WPA2/3`, or `Unknown`)
- `message` (human-readable description)

Semantics:
- `AP` event: first observed unique `(SSID, BSSID)` during runtime.
- `ALERT` event: rule finding or confirmed drift message.

---

## 3) Fingerprint store (`logs/fingerprints.json`)

Top-level:
- `version` (integer)
- `networks` (object)

`networks` keys:
- Internal normalized key derived from `[ssid, bssid.lower()]` serialized as JSON string.

Per-record fields:
- `ssid` (string)
- `bssid` (string)
- `first_seen` (ISO timestamp)
- `last_seen` (ISO timestamp)
- `last_seen_epoch` (unix seconds)
- `last_sample_epoch` (unix seconds)
- `sightings` (int)
- `samples` (array; bounded rolling samples)
- `baseline` (object or null)
- `drift_streaks` (object with integer counters)
- `active_drift` (object of currently confirmed drift evidence)

`baseline` fields (when learned):
- `band`
- `channel`
- `frequency_mhz`
- `security`
- `rssi_dbm` (median)
- `learned_at`

`active_drift` fields may include:
- `band`
- `channel`
- `security`
- `strong_signal`

Constraints:
- Maximum records: 5000.
- Invalid versions/formats fail startup.
- Writes are atomic.

---

## 4) Detector CLI parameters

- `--interface` (string): network interface name
- `--mode` (`monitor` or `managed`)
- `--dwell` (float > 0): channel hop dwell in monitor mode
- `--scan-interval` (float > 0): managed scan period in seconds
- `--dashboard-host` (string): bind host
- `--dashboard-port` (int `1..65535`)
- `--dashboard-password-file` (path): password source file
- `--dashboard-cert` (path): TLS cert
- `--dashboard-key` (path): TLS private key
- `--config` (path): trusted networks JSON
- `--log` (path): event CSV path
- `--fingerprints` (path): persistent fingerprint file

Security/consistency rules:
- Password + no TLS is rejected.
- Cert without key (or key without cert) is rejected.
- Password file must exist if provided.

---

## 5) Dashboard status payload (`GET /api/status`)

Common fields:
- `scanner_running` (bool)
- `scan_mode` (`monitor` or `managed`)
- `scan_interval` (number)
- `last_scan` (timestamp or null)
- `last_error` (string)
- `access_points` (array)
- `twin_comparisons` (array)
- `alert_count` (int)
- `trusted_networks` (object; hidden when unauthenticated in admin mode)
- `fingerprints` (array)
- `fingerprint_count` (int)
- `dashboard_secure` (bool)
- `admin_enabled` (bool)
- `authenticated` (bool)
- `csrf_token` (string when authenticated)

`access_points[]` representative fields:
- `ssid`, `bssid`, `rssi`, `channel`, `frequency_mhz`, `band`, `security`
- `first_seen`, `last_seen`
- `findings` (array of rule messages)
- `trusted` (bool)
- optional `fingerprint` object

---

## 6) Dashboard history payload (`GET /api/history`)

Returns:
- `events` (array)

Event object fields:
- `timestamp`, `event`, `ssid`, `bssid`, `rssi`, `channel`, `security`, `message`

History retention:
- In-memory history is capped to recent entries (bounded list).

---

## 7) Dashboard admin endpoints

All admin endpoints require:
- HTTPS session
- Authenticated admin session cookie
- Valid CSRF token header
- same-origin checks for POST

### `POST /api/login`
Body:
```json
{ "password": "..." }
```
Response includes:
- `csrf_token`
- secure session cookie

### `POST /api/logout`
Body:
```json
{}
```
Invalidates session and clears cookie.

### `POST /api/admin/scan`
Body:
```json
{ "action": "start" }
```
or
```json
{ "action": "stop" }
```
Applies only in managed mode.

### `POST /api/admin/config`
Body shape:
```json
{
  "trusted_networks": { ... },
  "scan_interval": 30
}
```
Validation identical to runtime checks plus interval range `5..3600`.

---

## 8) Error and edge-case behaviors

- Invalid config file blocks startup with explicit validation error.
- Fingerprint store format/version mismatch blocks startup.
- Managed scan command failures update `last_error` and continue loop.
- Monitor-mode setup failures attempt rollback before exiting.
- Channel hop command failures warn and continue.

