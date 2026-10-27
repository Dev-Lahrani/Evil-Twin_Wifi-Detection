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

### Method B: USB Wi-Fi Adapter (Professional Setup)
Add a secondary USB Wi-Fi dongle to the Pi.
- Keep `wlan0` (internal) connected to the Wi-Fi for SSH access.
- Put `wlan1` (external) into monitor mode for the detector.
- Update the script: `sniff(iface="wlan1", ...)`

### Method C: Scheduled Cron / Systemd (Blind Run)
Run the script as a background service that logs to a file.
1. Set up the script as a systemd service.
2. Redirect output to a log file: `python3 detector.py > /home/pi/detection.log 2>&1`.
3. SSH in, check the log, then kill the process to regain Wi-Fi.

## Implementation in this version:
The updated `detector.py` now includes a **Channel Hopper** thread. Because you are headless, you cannot manually change channels; the script now automatically cycles through channels 1-13 in the background so you don't miss rogue APs on other frequencies.
