# Basic-Packet-Sniffer

A basic packet sniffer implemented in Python.

## Project Description

A packet sniffer, also known as a network analyzer, is a tool used to capture and analyze network traffic. It intercepts data packets transmitted over a network and allows users to examine their contents. This can be useful for network troubleshooting, security analysis, and understanding network protocols.

This specific project aims to provide a simple, educational packet sniffer that demonstrates the fundamental principles of packet capture and analysis using Python. The goal is to create a tool that can:

- Capture packets from a specified network interface.
- Display basic information about captured packets, such as source and destination addresses, protocols, and data payloads.
- Provide a foundation for further development and customization in network analysis.

## Setup Instructions

Before running the packet sniffer, you need to install the required dependencies. This project relies on the `scapy` library for packet capture and analysis.

1.  **Install Python:** Ensure you have Python 3.6 or higher installed on your system.

2.  **Install Scapy:** Use pip to install the `scapy` library:

        On some systems, you may need to run this command with administrative privileges (e.g., using `sudo pip install scapy` on Linux/macOS).

3. **Install other dependencies (if needed)**: Install any additional libraries.
    > `pip install <library-name>`

## Usage Instructions

bash
    sudo python your_sniffer_script.py
    2.  **Select Interface (if prompted):** The script might prompt you to select a network interface to listen on. Choose the appropriate interface for your network.

3.  **View Captured Packets:** The sniffer will start capturing packets and display information about them in the console.  The output will typically include details such as:

    -   Source IP address
    -   Destination IP address
    -   Protocol (e.g., TCP, UDP, ICMP)
    -   Packet summary

4.  **Stop the Sniffer:** Press `Ctrl+C` to stop the sniffer.

## Project Structure

The project typically consists of the following files:

-   `your_sniffer_script.py`: The main Python script containing the packet sniffing logic.

    > **Example Structure (adjust based on your actual code):**
    > python
from scapy.all import sniff, IP

def packet_callback(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        print(f"IP Packet: {src_ip} -> {dst_ip}")

sniff(prn=packet_callback, store=False, count=10) # Capture 10 packets
This code snippet captures 10 packets and prints the source and destination IP addresses for each IP packet. The `sniff` function captures packets, and the `packet_callback` function is executed for each captured packet.