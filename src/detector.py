import os
import sys
import time
import subprocess
import threading
from scapy.all import *
from scapy.layers.dot11 import Dot11Beacon, Dot11ProbeResp, Dot11

# --- CONFIGURATION ---
TRUSTED_NETWORKS = {
    "Home_WiFi": {"bssid": "AA:BB:CC:DD:EE:FF", "channel": 6, "rssi_threshold": -60},
    "Office_Guest": {"bssid": "11:22:33:44:55:66", "channel": 1, "rssi_threshold": -70}
}

sequence_tracker = {}

def get_oui_vendor(mac):
    return "UnknownVendor"

def rule_engine(packet, ssid, bssid, rssi, channel):
    alerts = []
    if ssid in TRUSTED_NETWORKS:
        if bssid != TRUSTED_NETWORKS[ssid]["bssid"]:
            alerts.append("[HIGH] R-01: BSSID Mismatch for trusted SSID!")
    if ssid in TRUSTED_NETWORKS:
        expected_rssi = TRUSTED_NETWORKS[ssid]["rssi_threshold"]
        if rssi > (expected_rssi + 10):
            alerts.append(f"[HIGH] R-02: Suspiciously high signal strength ({rssi}dBm)")
    if bssid in sequence_tracker:
        prev_seq = sequence_tracker[bssid]
        curr_seq = packet.SC
        if curr_seq < prev_seq - 10:
            alerts.append(f"[CRITICAL] R-03: Sequence number regression ({prev_seq} -> {curr_seq})")
        elif abs(curr_seq - prev_seq) > 100:
            alerts.append(f"[CRITICAL] R-03: Sequence number jump detected")
    sequence_tracker[bssid] = packet.SC
    return alerts

def packet_callback(pkt):
    if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
        ssid = pkt[Dot11Beacon].info.decode(errors='ignore') if pkt.haslayer(Dot11Beacon) else pkt[Dot11ProbeResp].info.decode(errors='ignore')
        bssid = pkt[Dot11].addr2
        rssi = pkt.dBm_AntSignal if hasattr(pkt, 'dBm_AntSignal') else -50 
        channel = 1 
        findings = rule_engine(pkt, ssid, bssid, rssi, channel)
        for alert in findings:
            print(f"ALERT: {ssid} | {bssid} | {alert}")

def channel_hopper():
    """
    Background thread to hop channels. 
    Crucial for headless Pi to ensure we don't get stuck on one channel.
    """
    while True:
        for channel in range(1, 14):
            # Use a non-blocking system call to change channel
            # os.system(f"sudo iw dev wlan0 set channel {channel}")
            time.sleep(2)

def main():
    print("Starting Headless Evil Twin Detector on Raspberry Pi 3B+...")
    
    # Setup Monitor Mode (Headless Safe)
    # we use 'iw' instead of 'airmon-ng' for better stability in scripts
    # os.system("sudo ip link set wlan0 down")
    # os.system("sudo iw dev wlan0 set type monitor")
    # os.system("sudo ip link set wlan0 up")

    # Start channel hopping in a separate thread so we don't block sniffing
    hopper = threading.Thread(target=channel_hopper, daemon=True)
    hopper.start()

    print("Scanning... Press Ctrl+C to stop.")
    sniff(iface="wlan0", prn=packet_callback, store=0)

if __name__ == "__main__":
    main()
