# Project Explanation: Rogue AP & Evil Twin Detector

## What is this project?
This is a cybersecurity tool designed to protect users from "Evil Twin" attacks. An Evil Twin is a fake Wi-Fi network that looks exactly like a real one (same name/SSID) to trick people into connecting so the attacker can steal passwords and data.

## Why use a Raspberry Pi 3B+?
The Raspberry Pi 3B+ is used because it is a small, portable computer with a Wi-Fi chip that can be put into "Monitor Mode." In this mode, the Pi doesn't connect to any network; instead, it acts like a "radio scanner," listening to every Wi-Fi packet in the air.

## How does it work? (The Logic)
The tool doesn't use AI (which is slow and can be wrong). Instead, it uses **Deterministic Rules**. Imagine a security guard with a checklist. If the "guard" (the code) sees a Wi-Fi network, he checks these things:

1. **Is the MAC address wrong?** (If the network says "Airport_Free" but the hardware ID isn't the official airport ID $\rightarrow$ **ALERT**).
2. **Is the signal too strong?** (If the signal is suddenly much stronger than usual, the attacker might be standing right next to you $\rightarrow$ **ALERT**).
3. **Are the packet numbers jumping?** (Legitimate routers count packets 1, 2, 3... If the numbers jump 1 $\rightarrow$ 500 $\rightarrow$ 2, there are two different routers fighting for the same name $\rightarrow$ **ALERT**).
4. **Is the security downgraded?** (If the real network requires a password, but the fake one is "Open" to lure you in $\rightarrow$ **ALERT**).

## How to present this in a Viva/Exam:
1. **Hardware Demo:** Show the Raspberry Pi scanning the room.
2. **Attack Demo:** Turn on an "Evil Twin" (using another device).
3. **Detection Demo:** Show the Python terminal instantly printing "CRITICAL ALERT" when the fake network appears.
4. **Defense:** Explain that this is better than ML because it is **transparent**. You can point to exactly which protocol rule was broken.
