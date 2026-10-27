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
The detector uses five primary heuristics to flag anomalies:

| Rule ID | Logic | Threat Identified | Severity |
|---|---|---|---|
| **R-01** | BSSID $\neq$ Trusted BSSID for a known SSID | MAC Spoofing | High |
| **R-02** | $\Delta RSSI > \text{Threshold}$ | Power Overpowering (Evil Twin) | High |
| **R-03** | Sequence Counter Regression/Jump | Concurrent Transmitter Injection | Critical |
| **R-04** | Security $\neq$ Expected (e.g. Open vs WPA3) | Captive Portal Downgrade | Critical |
| **R-05** | Channel $\neq$ Expected Channel | Off-Channel Cloning | Medium |

## 4. Pipeline Workflow
1. **Capture:** `scapy` sniffs raw 802.11 frames.
2. **Parsing:** Dissects **Beacon** and **Probe Response** frames.
3. **Evaluation:** Passes parsed fields (SSID, BSSID, RSSI, Sequence Number) into the Rule Engine.
4. **Alerting:** If a rule is triggered, an alert is logged with the associated severity.

## 5. Evaluation Methodology (for Viva/Paper)
To prove the system works, we will use the following lab setup:
- **Attacker:** A second Raspberry Pi or laptop running `hostapd-mana` or a Wi-Fi Pineapple to create an Evil Twin.
- **Target:** The Detector Pi scanning the environment.
- **Metrics:** 
    - **True Positive Rate:** Percentage of rogue APs correctly flagged.
    - **False Positive Rate:** Benign APs mistakenly flagged as rogue.
    - **Latency:** Time from frame capture to alert generation.
