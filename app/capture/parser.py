from scapy.layers.dns import DNSQR
from scapy.layers.inet import IP

from datetime import datetime

from app.detection.analyzer import (
    decode_query_type,
    is_suspicious_domain,
    generate_threat_score
)


def parse_dns_packet(packet):

    try:

        if packet.haslayer(DNSQR):

            timestamp = datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            )

            source_ip = packet[IP].src

            destination_ip = packet[IP].dst

            queried_domain = packet[DNSQR].qname.decode()

            raw_query_type = packet[DNSQR].qtype

            query_type = decode_query_type(
                raw_query_type
            )

            suspicious = is_suspicious_domain(
                queried_domain
            )

            threat_score = generate_threat_score(
                queried_domain
            )

            dns_data = {

                "timestamp": timestamp,

                "source_ip": source_ip,

                "destination_ip": destination_ip,

                "domain": queried_domain,

                "query_type": query_type,

                "suspicious": suspicious,

                "threat_score": threat_score
            }

            return dns_data

    except Exception as error:

        print(f"[ERROR] Parsing packet: {error}")

    return None