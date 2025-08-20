#!/usr/bin/env python3
import argparse
import time
from collections import Counter
from scapy.all import (
    sniff, get_if_list, get_if_addr,
    IP, TCP, UDP, ICMP, ARP, IPv6, DNS, DHCP,
    wrpcap
)

# Colors for terminal output
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
MAGENTA = "\033[95m"
BLUE = "\033[94m"
WHITE = "\033[97m"     
RESET = "\033[0m"

stats_proto = Counter()
captured_packets = []   # store packets for saving
args = None             # global holder for CLI args

def list_interfaces():
    """List interfaces with IPs for user-friendly display"""
    interfaces = []
    for iface in get_if_list():
        try:
            ip = get_if_addr(iface)
            if ip and not ip.startswith("127."):  # skip loopback
                interfaces.append((iface, ip))
        except Exception:
            pass
    return interfaces

def choose_interface():
    """Ask user to choose interface if multiple are active."""
    interfaces = list_interfaces()
    if not interfaces:
        print("[-] No active interfaces found. Connect to Wi-Fi/Ethernet first.")
        return None

    if len(interfaces) == 1:
        iface, ip = interfaces[0]
        print(f"[+] Auto-selected interface: {iface} ({ip})")
        return iface

    print("\nAvailable interfaces:")
    for i, (iface, ip) in enumerate(interfaces, start=1):
        print(f"{i}. {iface} ({ip})")

    choice = int(input("Select interface number: "))
    return interfaces[choice - 1][0]

def pkt_summary(pkt, filter_active=False):
    """Return a short, colored summary of the packet."""
    ts = time.strftime("%H:%M:%S")

    if IP in pkt:
        src, dst = pkt[IP].src, pkt[IP].dst
        if TCP in pkt:
            return f"{RED}[{ts}] {src}:{pkt[TCP].sport} -> {dst}:{pkt[TCP].dport} TCP{RESET}"
        elif UDP in pkt:
            if pkt.haslayer(DNS):
                return f"{MAGENTA}[{ts}] {src}:{pkt[UDP].sport} -> {dst}:{pkt[UDP].dport} DNS{RESET}"
            elif pkt.haslayer(DHCP):
                return f"{YELLOW}[{ts}] DHCP message {src} -> {dst}{RESET}"
            else:
                return f"{GREEN}[{ts}] {src}:{pkt[UDP].sport} -> {dst}:{pkt[UDP].dport} UDP{RESET}"
        elif ICMP in pkt:
            return f"{CYAN}[{ts}] {src} -> {dst} ICMP{RESET}"

    elif ARP in pkt:
        return f"{BLUE}[{ts}] ARP {pkt[ARP].psrc} -> {pkt[ARP].pdst}{RESET}"
    elif IPv6 in pkt:
        return f"{WHITE}[{ts}] IPv6 packet{RESET}"

    # Only show generic "Other" if no filter was applied
    if not filter_active:
        return f"{CYAN}[{ts}] Other packet{RESET}"
    return None   # don’t print anything if filtered

def update_stats(pkt):
    """Update protocol counters and talker pairs."""
    if IP in pkt:
        if TCP in pkt: stats_proto["TCP"] += 1
        elif UDP in pkt:
            if pkt.haslayer(DNS): stats_proto["DNS"] += 1
            elif pkt.haslayer(DHCP): stats_proto["DHCP"] += 1
            else: stats_proto["UDP"] += 1
        elif ICMP in pkt: stats_proto["ICMP"] += 1
        else: stats_proto["OTHER"] += 1
    elif ARP in pkt:
        stats_proto["ARP"] += 1
    elif IPv6 in pkt:
        stats_proto["IPv6"] += 1
    else:
        stats_proto["OTHER"] += 1

def handle(pkt):
    """Handle each sniffed packet."""
    summary = pkt_summary(pkt, filter_active=bool(args.filter))
    if summary:
        print(summary)
    update_stats(pkt)
    captured_packets.append(pkt)

def print_stats():
    """Print capture summary."""
    print("\n=== Capture Summary ===")
    if args.filter:
        print(f"(Filter applied: {args.filter})")
        total = len(captured_packets)
        print(f"Total packets: {total}")
    else:
        total = sum(stats_proto.values())
        print(f"Total packets: {total}")
        for proto, count in stats_proto.items():
            print(f"{proto}: {count}")
    print("========================")

def main():
    global args
    parser = argparse.ArgumentParser(
        description="Simple Python Packet Sniffer",
        epilog="""Examples:
  python PacketSniffer.py                 # Capture on default interface, unlimited packets
  python PacketSniffer.py --count 50      # Capture only 50 packets
  python PacketSniffer.py --filter "tcp"  # Capture only TCP packets
  python PacketSniffer.py --duration 30   # Run for 30 seconds then stop
  python PacketSniffer.py --nosave        # Capture packets but don't save to PCAP
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument("--nosave", action="store_true",
                        help="Do not save packets to PCAP file")
    parser.add_argument("--count", type=int, default=0,
                        help="Number of packets to capture (0 = unlimited)")
    parser.add_argument("--filter", type=str, default="",
                        help="BPF filter (e.g. 'tcp port 80')")
    parser.add_argument("--duration", type=int, default=0,
                        help="Duration in seconds to run (0 = unlimited)")

    args = parser.parse_args()

    iface = choose_interface()
    if not iface:
        return

    print("Starting capture… Press Ctrl+C to stop.\n")

    sniff_kwargs = {"iface": iface}
    if args.filter:
        sniff_kwargs["filter"] = args.filter

    try:
        sniff(prn=handle,
              count=args.count if args.count > 0 else 0,
              timeout=args.duration if args.duration > 0 else None,
              **sniff_kwargs)
    except KeyboardInterrupt:
        print("\n[!] Capture stopped by user.")
    finally:
        print_stats()
        if not args.nosave and captured_packets:
            filename = f"capture_{int(time.time())}.pcap"
            wrpcap(filename, captured_packets)
            print(f"[+] Packets saved to {filename}")


if __name__ == "__main__":
    main()
