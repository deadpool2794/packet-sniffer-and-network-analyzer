from .Analyzer import Analyzer
from scapy.all import sniff, wrpcap, ARP
from datetime import datetime
import os


class PacketSniffer:
    def __init__(self, interface=None, count=0, filter=None, output_file=None, display_info=False):
        """
        Initializes the PacketSniffer object.
        :param interface: Network interface to sniff on (e.g., "eth0", "wlan0").
        :param count: Number of packets to capture. Default is 0 (sniff indefinitely).
        :param filter: BPF filter string (e.g., "tcp", "udp", "port 80").
        :param output_file: Filename to save captured packets (optional).
        """
        self.interface = interface
        self.count = count
        self.filter = filter
        self.pcap_file, self.txt_file = self.set_output_filename(output_file)
        self.packets = []
        self.display_info = display_info
        self.packets_captured = 0
        self.analyzer = Analyzer()
        self.display_string = "\rPackets Captured: {}"

    def set_output_filename(self, output_file):
        """
        Sets the output filenames for both PCAP and TXT files.
        Creates folders 'captured_packets/pcap_files' and 'captured_packets/txt_files' if they don't exist.
        :param output_file: Desired output filename (optional).
        :return: Tuple of full paths for the PCAP file and TXT file.
        """
        # Create main directory and subdirectories if they do not exist
        base_dir = "captured_packets"
        pcap_dir = os.path.join(base_dir, "pcap_files")
        txt_dir = os.path.join(base_dir, "txt_files")

        os.makedirs(pcap_dir, exist_ok=True)
        os.makedirs(txt_dir, exist_ok=True)

        # Generate filenames based on the provided output_file or use a timestamp-based default
        if output_file:
            filename = os.path.splitext(os.path.basename(output_file))[0]
        else:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S%f")
            filename = f"packets_{timestamp}"

        # Construct full paths for PCAP and TXT files
        pcap_file = os.path.join(pcap_dir, f"{filename}.pcap")
        txt_file = os.path.join(txt_dir, f"{filename}.txt")

        return pcap_file, txt_file
    

    def process_packet(self, packet):
        """
        Callback function to process each captured packet.
        Writes the packet summary to a TXT file and the raw packet data to a PCAP file.
        :param packet: The captured packet.
        """
        self.packets_captured += 1
         
        if(self.display_info):
            print(packet.summary())
        else:
            print(self.display_string.format(self.packets_captured), end="")
        packet_details = repr(packet)

        # Write packet details to the TXT file
        with open(self.txt_file, "a") as txt_fp:
            txt_fp.write(packet_details + "\n\n")

        # Write raw packet data to PCAP file
        wrpcap(self.pcap_file, packet, append=True)

        if(packet.haslayer(ARP)):
            result = self.analyzer.analyze_packet(packet)
            if(len(result)!= 0 and len(self.display_string) < 100):
                self.display_string+= " Duplicate MAC Address detected. "
                self.display_string += "IP {} has 2 MAC Addresses {}, {}".format(result[0], result[1], result[2])


    def stop_sniffing(self, packet):
        if(self.count == 0): 
            return False
        if(self.count == self.packets_captured):
            return True

    def start_sniffing(self):
        """
        Starts packet sniffing.
        """
        print(f"Starting packet sniffing")
        sniff(iface=self.interface, prn=self.process_packet, stop_filter = self.stop_sniffing, filter = self.filter)
