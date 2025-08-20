# Basic-Packet-Sniffer

A basic packet sniffer implemented in Python using the `scapy` library.

## Project Description

A packet sniffer, also known as a network analyzer, is a tool used to capture and analyze network traffic. It intercepts data packets transmitted over a network and allows users to examine their contents. This can be useful for network troubleshooting, security analysis, and understanding network protocols.

This specific project aims to provide a simple, educational packet sniffer that demonstrates the fundamental principles of packet capture and analysis using Python. The goal is to create a tool that can:

-   Capture packets from a specified network interface.
-   Display basic information about captured packets, such as source and destination addresses, protocols, and data payloads.
-   Provide a foundation for further development and customization in network analysis.

## Setup Instructions

Before running the packet sniffer, you need to install the required dependencies. This project relies on the `scapy` library for packet capture and analysis.

1.  **Install Python:** Ensure you have Python 3.6 or higher installed on your system.

2.  **Install Scapy:** Use pip to install the `scapy` library:

2.  **Select Interface (if prompted):** The script might prompt you to select a network interface to listen on. Choose the appropriate interface for your network. You can usually identify the correct interface by its name (e.g., `eth0`, `wlan0`, `en0`).

3.  **View Captured Packets:** The sniffer will start capturing packets and display information about them in the console. The output will typically include details such as:

    -   Source IP address
    -   Destination IP address
    -   Protocol (e.g., TCP, UDP, ICMP)
    -   Packet summary

4.  **Stop the Sniffer:** Press `Ctrl+C` to stop the sniffer.

## Project Structure

The project consists of a single Python file:

-   `PacketSniffer.py`: The main Python script containing the packet sniffing logic.

