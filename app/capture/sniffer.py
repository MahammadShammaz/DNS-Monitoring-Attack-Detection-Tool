from scapy.all import sniff

from app.capture.parser import parse_dns_packet
from app.database.db import insert_dns_log


def process_packet(packet):

    dns_data = parse_dns_packet(packet)

    if dns_data:

        insert_dns_log(dns_data)

        print("\n[DNS PACKET CAPTURED]")

        print(f"Time        : {dns_data['timestamp']}")
        print(f"Source IP   : {dns_data['source_ip']}")
        print(f"Destination : {dns_data['destination_ip']}")
        print(f"Domain      : {dns_data['domain']}")
        print(f"Query Type  : {dns_data['query_type']}")


def start_sniffer():

    print("[*] DNS Sniffer Started...")

    sniff(
        filter="port 53",
        prn=process_packet,
        store=False
    )