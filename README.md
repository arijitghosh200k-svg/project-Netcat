# project-Netcat
A Python‑based Network &amp; Port Scanner that discovers active devices in a subnet using ARP requests and performs multi‑threaded port scanning on target IPs. Built with scapy and socket, it provides fast, concurrent scanning and clear terminal output for network analysis and security learning.
# Network & Port Scanner

## Overview
This project is a **Python network scanning tool** designed for educational and research purposes. It combines **ARP scanning** to discover live hosts in a subnet and **multi-threaded port scanning** to identify open ports on a target IP. The tool demonstrates practical networking concepts such as packet crafting, concurrency, and socket programming.

---

## Features
- 🔍 **ARP Scan**: Detects active devices in a subnet (requires `scapy` and Npcap/WinPcap on Windows).
- ⚡ **Multi-threaded Port Scan**: Quickly scans ports using Python threads.
- 🖥️ **Interactive CLI**: User-friendly menu for subnet scanning, port scanning, or both.
- 🛡️ **Error Handling**: Validates IP/subnet inputs and handles exceptions gracefully.

---

## Requirements
- Python 3.7+
- Libraries:
  - `scapy` (for ARP scanning)
  - `socket` (built-in)
  - `ipaddress` (built-in)
  - `threading` (built-in)
- On Windows: Install **Npcap/WinPcap** for ARP packet capture.

Install scapy via pip:
```bash
pip install scapy
```bash
pip install scapy
