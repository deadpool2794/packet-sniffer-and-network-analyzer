import argparse
from src.Sniffer import PacketSniffer



def main():
    # Argument parsing
    parser = argparse.ArgumentParser(description="A simple packet sniffer using Scapy.")
    parser.add_argument("-i", "--interface", type=str, help="Network interface to sniff on (e.g., 'eth0').")
    parser.add_argument("-c", "--count", type=int, default=0, help="Number of packets to capture (default is 0 for infinite).")
    parser.add_argument("-f", "--filter", type=str, default=None, help="BPF filter string (e.g., 'tcp', 'udp').")
    parser.add_argument("-o", "--output_file", type=str, default=None, help="Filename to save captured packets (optional).")
    parser.add_argument("-d", "--display_info", action="store_true", help="Display information of packet")
    args = parser.parse_args()

    sniffer = PacketSniffer(interface=args.interface, count=args.count, filter=args.filter, output_file=args.output_file, display_info = args.display_info) 
    sniffer.start_sniffing()


if __name__ == "__main__":
    main()