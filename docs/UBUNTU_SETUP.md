# Ubuntu Server Setup Guide for Evil Twin Detector

Since you are using **Ubuntu Server** (headless), you don't have a desktop environment. You will manage everything via SSH.

## 1. Required Dependencies
Run these commands on your Raspberry Pi to install the necessary tools for packet sniffing and monitor mode:

```bash
sudo apt update
sudo apt install -y python3-pip python3-scapy wireless-tools iw aircrack-ng
```

## 2. Fixing the "Headless Lockout" (Crucial)
As mentioned in the `HEADLESS_GUIDE.md`, putting `wlan0` into monitor mode will kill your SSH connection if you are using Wi-Fi.

**The Ubuntu Server Solution:**
If you don't have Ethernet, use a **screen** or **tmux** session. This ensures the script keeps running even if your SSH connection drops.

```bash
# Install screen
sudo apt install screen

# Start a session
screen -S detector

# Run the script
sudo python3 detector.py
```
*If you get disconnected, you can reconnect and resume the session with:* `screen -r detector`

## 3. Ubuntu-Specific Interface Commands
Ubuntu Server uses `ip` and `iw` instead of the older `ifconfig`. The `detector.py` script is already designed to use these, but if you need to do it manually:

```bash
# Put into monitor mode
sudo ip link set wlan0 down
sudo iw dev wlan0 set type monitor
sudo ip link set wlan0 up

# Verify monitor mode
iwconfig wlan0
```

## 4. Permissions
Since `scapy` needs to access the network hardware directly, you must always run the script with `sudo`:
```bash
sudo python3 detector.py
```
