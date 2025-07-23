from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP
from colorama import Fore, Style
import datetime

def process_packet(packet):
    timestamp = datetime.datetime.now().strftime('%H:%M:%S')

    if IP in packet:
        ip_layer = packet[IP]
        proto = "OTHER"
        details = ""

        if TCP in packet:
            proto = "TCP"
            details = f"{packet[TCP].sport} → {packet[TCP].dport}"
        elif UDP in packet:
            proto = "UDP"
            details = f"{packet[UDP].sport} → {packet[UDP].dport}"
        elif ICMP in packet:
            proto = "ICMP"

        print(f"{Fore.GREEN}[{timestamp}]{Style.RESET_ALL} {proto} | {ip_layer.src} → {ip_layer.dst} | {details}")

def main():
    print("Starting packet sniffer...\nPress Ctrl+C to stop.\n")
    sniff(prn=process_packet, store=False)

if __name__ == "__main__":
    main()
