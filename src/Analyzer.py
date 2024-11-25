from scapy.all import sniff, ARP

class Analyzer:

    def __init__(self):
        self.ip_mac = {}

    def analyze_packet(self, packet):

        arp_layer = packet[ARP]
        ip = arp_layer.psrc
        mac = arp_layer.hwsrc
        if(arp_layer.op == 2):
            if  ip in self.ip_mac:
                if(self.ip_mac[ip] != mac):
                    result = []
                    result.append(ip)
                    result.append(self.ip_mac[ip])
                    result.append(mac)
                    self.ip_mac[ip] = mac
                    return result
            else:
                self.ip_mac[ip] = mac
        return []


        

    def start_analyzing(self):
        sniff(prn=self.process_packet, stop_filter = self.stop_sniffing, filter = "arp")