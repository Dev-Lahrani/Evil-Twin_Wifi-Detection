# Headless Operation Guide (SSH)

## The Challenge
When you put a Wi-Fi interface into **Monitor Mode**, it disconnects from any Access Point. If you are using SSH over Wi-Fi on the same interface (`wlan0`), you will be immediately kicked out and lose access to the Raspberry Pi.

## The Solution
To run this project headlessly without losing access, you must use one of these three methods:

### Method A: Ethernet Connection (Recommended)
Connect the Raspberry Pi to your router via an **Ethernet cable**.
- SSH into the Pi using its Ethernet IP.
- Put `wlan0` into monitor mode.
- Since the SSH session is on `eth0` and the sniffing is on `wlan0`, you stay connected.

### Method B: USB Wi-Fi Adapter
Add a monitor-capable USB Wi-Fi dongle to the Pi.
- Keep `wlan0` (internal) connected to Wi-Fi for SSH and dashboard access.
- Check the adapter's interface name with `iw dev` (often `wlan1`).
- Bind the read-only dashboard to the internal Wi-Fi address and select the USB adapter at runtime: `sudo python3 src/detector.py --interface wlan1 --dashboard-host <wlan0-address>`. Avoid `0.0.0.0` if dashboard visibility should be limited to hotspot Wi-Fi.
- Keep Ethernet connected until you have confirmed scanning and hotspot access work together; hotspot client isolation may block other devices from reaching the dashboard.

### Method C: Scheduled Cron / Systemd (Blind Run)
Run the script as a background service that logs to a file.
1. Set up the script as a systemd service.
2. Redirect output to a log file: `python3 detector.py > /home/pi/detection.log 2>&1`.
3. SSH in, check the log, then kill the process to regain Wi-Fi.

## Scanning modes
The detector supports monitor-mode capture with a channel hopper, or managed-mode periodic scans using `--mode managed`. Monitor mode must use a separate adapter if the Pi needs to remain connected over Wi-Fi; the selected adapter is restored when scanning stops.
