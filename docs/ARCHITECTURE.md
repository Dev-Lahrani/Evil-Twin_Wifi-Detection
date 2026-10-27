# Technical Framework: Evil Twin Detection System

## 1. System Overview
This project implements a deterministic, non-ML based Rogue Access Point (RAP) and Evil Twin detector designed for embedded deployment on a **Raspberry Pi 3B+**. The system analyzes 802.11 management frames in real-time to identify impersonation attempts.

## 2. Hardware Integration (Raspberry Pi 3B+)
The Raspberry Pi 3B+ is the ideal host for this project due to its integrated Wi-Fi chip and Linux-based OS, allowing low-level access to the wireless stack.

### Deployment Model:
- **NIC Mode:** The internal `wlan0` interface is placed into **Monitor Mode** using `iw` or `airmon-ng`. This allows the Pi to capture all nearby packets without associating with any network.
- **Channel Hopping:** A background process (or a wrapper around `airodump-ng`) continuously cycles the NIC through channels 1-13 (2.4GHz) to ensure full-spectrum coverage.
- **Resource Usage:** By using a deterministic rules engine instead of a Neural Network, the system maintains a low CPU footprint, preventing thermal throttling on the Pi.

## 3. The Deterministic Rules Engine
The detector uses these configured heuristics to flag anomalies:

| Rule ID | Logic | Threat Identified | Severity |
|---|---|---|---|
| **R-01** | BSSID $\neq$ Trusted BSSID for a known SSID | MAC Spoofing | High |
| **R-02** | Signal exceeds configured threshold by more than 10 dB | Unusually strong signal (verify) | High |
| **R-04** | Security mode differs from the configured trusted mode | Possible security downgrade or clone | High |
| **R-05** | Channel differs from the configured channel | Off-channel clone (verify) | Medium |
| **R-06** | Multiple BSSIDs advertise the same SSID | Possible clone; mesh systems can be legitimate | Medium |

## 4. Pipeline Workflow
1. **Capture:** `scapy` sniffs raw 802.11 frames.
2. **Parsing:** Dissects **Beacon** and **Probe Response** frames.
3. **Evaluation:** Checks SSID, BSSID, RSSI, channel, and advertised security against the JSON trusted-network config.
4. **Alerting and logging:** Prints each discovered AP and unique alert and appends events to a CSV log.
5. **Summary:** Reports unique AP and alert counts when scanning stops.

## 5. Evaluation Methodology (for Viva/Paper)
To prove the system works, we will use the following lab setup:
- **Attacker:** A second Raspberry Pi or laptop running `hostapd-mana` or a Wi-Fi Pineapple to create an Evil Twin.
- **Target:** The Detector Pi scanning the environment.
- **Metrics:** 
    - **True Positive Rate:** Percentage of rogue APs correctly flagged.
    - **False Positive Rate:** Benign APs mistakenly flagged as rogue.
    - **Latency:** Time from frame capture to alert generation.
