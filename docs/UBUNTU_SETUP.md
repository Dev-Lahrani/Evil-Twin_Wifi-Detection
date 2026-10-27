# Ubuntu Server Setup Guide for Evil Twin Detector

Use this guide on the Raspberry Pi itself or through SSH over Ethernet. For the built-in Wi-Fi adapter, managed mode can scan without changing its connection; keep Ethernet available for reliable administration while scans briefly use the radio.

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

By default the detector enables monitor mode on the selected interface, scans channels 1-13, writes discovered APs and alerts to `logs/detector.csv`, and restores that interface mode when stopped with Ctrl+C. It prints a summary at shutdown. If using a USB monitor-capable adapter, check its interface name with `iw dev` and select it with `--interface` (often `wlan1`), leaving the Pi's built-in `wlan0` connected to the hotspot for SSH and dashboard access. Keep Ethernet connected until you have verified both Wi-Fi access and scanning. If the Pi's built-in Wi-Fi is the only adapter or does not support monitor mode, use periodic scans in managed mode instead:

```bash
sudo python3 src/detector.py --interface wlan0 --mode managed --scan-interval 30
```

Managed mode leaves the Wi-Fi interface connected, scans nearby networks every 30 seconds, and may briefly pause that connection during each scan. Prefer connecting over Ethernet before starting it. For hotspot-only dashboard access, bind to the Pi's `wlan0` address; `0.0.0.0` listens on every Pi network interface, including Ethernet. The dashboard listens on port 8080 by default. Browse to `http://<Pi-address>:8080/` for read-only HTTP, or `https://<Pi-address>:8080/` when TLS is configured. Nearby SSIDs, BSSIDs, signal measurements, and warning history will be visible to anyone who can reach that port, so use this only on a network you trust. The dashboard has no write controls unless a password and TLS certificate/key are configured; those options require HTTPS because an HTTP password would be sent unencrypted. To create local credentials for the hotspot IP (replace the example address with `wlan0`'s actual address), run:

```bash
sudo install -d -m 700 /etc/eviltwin
sudo sh -c 'openssl rand -hex 24 > /etc/eviltwin/dashboard-password && chmod 600 /etc/eviltwin/dashboard-password'
PI_WLAN0_IP=$(ip -4 -o addr show dev wlan0 | awk '{split($4,a,"/"); print a[1]}')
sudo openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
  -keyout /etc/eviltwin/dashboard.key -out /etc/eviltwin/dashboard.crt \
  -subj "/CN=$PI_WLAN0_IP" -addext "subjectAltName=IP:$PI_WLAN0_IP"
sudo chmod 600 /etc/eviltwin/dashboard.key
```

Then pass `--dashboard-password-file /etc/eviltwin/dashboard-password --dashboard-cert /etc/eviltwin/dashboard.crt --dashboard-key /etc/eviltwin/dashboard.key`; protect the password file and private key, and expect the browser to warn that the locally generated certificate is not issued by a public certificate authority.

When controls are enabled, the dashboard lets an authenticated administrator pause/resume managed scans and validate/save the trusted-network JSON plus scan interval. No start/stop controls are offered for monitor-mode capture. If the Pi's Wi-Fi device uses another interface name, pass it with `--interface`. Check availability with `iw dev`. Optional flags: `--config config/trusted_networks.json`, `--log logs/detector.csv`, `--dwell 1.0` (monitor mode), and `--scan-interval 30` (managed mode).

The same run command can publish the dashboard on the hotspot address while scanning on the USB adapter:

```bash
PI_WLAN0_IP=$(ip -4 -o addr show dev wlan0 | awk '{split($4,a,"/"); print a[1]}')
sudo python3 src/detector.py --interface wlan1 --dashboard-host "$PI_WLAN0_IP"
```

This uses monitor mode on `wlan1`; `wlan0` can remain connected to the hotspot. Confirm the interface names with `iw dev` before running the command. On a home hotspot, open `https://<PI_WLAN0_IP>:8080/` (replace the placeholder with the printed address) from another connected device; accept the locally generated certificate warning if prompted. The dashboard administrator password is stored in `/etc/eviltwin/dashboard-password` on the Pi and can be read there with `sudo cat /etc/eviltwin/dashboard-password`. To start it detached, `nohup` can keep it running, but use a proper service manager for automatic startup and recovery.

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
