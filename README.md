Here is the `README.md` file for your project, based on the provided report:  


# Packet Sniffer and Traffic Analyzer

## Overview

This project is a lightweight yet effective **Packet Sniffer and Traffic Analyzer** developed as part of the CIS 554 course. It is designed to capture real-time network traffic, analyze data packets, and identify security threats like ARP poisoning attacks. The tool supports both **Command-Line Interface (CLI)** and **Graphical User Interface (GUI)** versions.

## Features

- **Real-Time Packet Capture:** Monitors all incoming and outgoing packets in real-time.
- **Packet Filtering:** Filters specific traffic types such as TCP, UDP, or ICMP using Berkeley Packet Filters (BPF).
- **Packet Parsing and Analysis:** Extracts attributes like source/destination IPs, ports, protocols, and payload data.
- **ARP Poisoning Detection:** Identifies anomalies in ARP traffic to detect ARP spoofing attacks.
- **Reporting and Visualization:** Outputs captured traffic data in plain text or pcap format.
- **Compatibility with Standard Tools:** Saved packets can be analyzed with tools like Wireshark.

## Libraries Used

- `scapy`: For packet sniffing and analysis.
- `aiofiles`: Asynchronous file operations.
- `mac-vendor-lookup`: Identifies manufacturers based on MAC addresses.
- `attrs`: For class attribute validation.
- **Others:** `aiohappyeyeballs`, `aiosignal`, `frozenlist`, `multidict`, `propcache`, `idna`.

## Testing

### 1. **Wireshark for Packet Verification**
The tool was tested alongside Wireshark to ensure consistency in capturing packets.

### 2. **ARP Poisoning Simulation**
Simulated ARP poisoning attacks using Ettercap validated the detection mechanism.

### Results:
- Accurate real-time packet capture.
- Successful detection of ARP poisoning events.

## Usage

### Requirements
- Python 3.x
- Kali Linux environment
- Install dependencies from `requirements.txt`:

```bash
pip install -r requirements.txt
```

### Execution Steps

1. **Extract the Project Archive**:
   ```bash
   unzip packet_sniffer.zip
   cd packet_sniffer
   ```

2. **Run the GUI Version**:
   ```bash
   sudo python -m build.gui
   ```

3. **Run the CLI Version**:
   ```bash
   sudo python -m build.cli
   ```


## Conclusion

The Packet Sniffer and Traffic Analyzer provides researchers and network administrators with an efficient and user-friendly tool to monitor traffic, detect threats, and diagnose network issues.

## References

- [Scapy Documentation](https://scapy.readthedocs.io/en/stable/)
- [Wireshark](https://www.wireshark.org/docs/)
- [ARP Poisoning Detection](https://www.comparitech.com/blog/information-security/arp-poisoning-spoofing-detect-prevent/)

---

**Author**: Alim Khan Abdul  

```

This `README.md` file covers key project aspects, including its purpose, features, dependencies, testing, and usage instructions. Let me know if you'd like further customization or additional sections!
