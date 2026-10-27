# Ubuntu Server Setup Guide for Evil Twin Detector

Use this guide on the Raspberry Pi itself or through SSH over Ethernet. The detector changes only the selected Wi-Fi interface (`wlan0`) to monitor mode; keep the Pi's Ethernet interface up for SSH access.

## 1. Install dependencies

On Ubuntu Server for Raspberry Pi, run:

```bash
sudo apt update
sudo apt install -y python3-scapy iw iproute2
```

Copy/clone this project onto the Pi, then from its project directory verify that Scapy imports:

```bash
python3 -c 'import scapy; print("Scapy OK")'
```

## 2. Verify Ethernet SSH is active

Before scanning, confirm the SSH connection is using Ethernet, not Wi-Fi:

```bash
ip -brief address
ip route get "$(echo "$SSH_CLIENT" | awk '{print $1}')"
```

The route to your SSH client should show the wired interface (often `eth0` or `end0`). Do not start monitor mode over a Wi-Fi-only SSH connection.

## 3. Configure trusted networks

Edit `config/trusted_networks.json` with your router's actual values. The starter config is empty, so the detector can list and log nearby APs but cannot compare them to a trusted network until you add one. Supported security values are `Open`, `WEP`, `WPA`, and `WPA2/3`.

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

The detector warns about trusted SSID BSSID, signal, channel, and security mismatches. Multiple BSSIDs for one SSID are also reported for review; mesh systems may legitimately use several.

## 4. Run the detector

From the project root on the Pi:

```bash
sudo python3 src/detector.py --interface wlan0
```

The detector enables monitor mode, scans channels 1-13, writes discovered APs and alerts to `logs/detector.csv`, and restores the interface mode when stopped with Ctrl+C. It prints a summary at shutdown. If the Pi's Wi-Fi device uses another interface name, pass it with `--interface`. Check availability with `iw dev`. Optional flags: `--config config/trusted_networks.json`, `--log logs/detector.csv`, and `--dwell 1.0`.

To run it in a persistent SSH session, install and use `tmux`:

```bash
sudo apt install -y tmux
tmux new -s detector
sudo python3 src/detector.py --interface wlan0
```

Detach with Ctrl+B then D; reconnect with `tmux attach -t detector`.

## Troubleshooting

- `Operation not permitted`: run the command with `sudo`.
- `No such device`: use the interface name listed by `iw dev`.
- `Device or resource busy` or monitor-mode errors: check `iw dev`, then stop the Wi-Fi connection manager from controlling `wlan0` before retrying; do not stop Ethernet networking.
- The Pi 3 B+ internal Wi-Fi supports 2.4 GHz; this scanner hops channels 1-13 only. Use a compatible external adapter for other bands.
- A second BSSID advertising your SSID can be legitimate (for example, a mesh node); verify it rather than treating the alert as proof of an attack.
