import json
import textwrap
import threading
import uuid
from datetime import datetime

from functions import data_logger, get_iface, utils
from scapy.all import sniff

data = []

CONFIG_PATH = r"config/config.json"

with open(CONFIG_PATH, "r", encoding="utf-8") as f:
    config = json.load(f)

IGNORED_DOMAINS = config.get("ignored_domains", [])


def packet_callback(pkt):
    if pkt.haslayer("DNS") and pkt.haslayer("DNSQR"):
        raw_qname = pkt["DNSQR"].qname
        domain_name = raw_qname.decode("utf-8", errors="ignore").rstrip(".")

        if any(ignored in domain_name.lower() for ignored in IGNORED_DOMAINS):
            return

        transaction_id = pkt["DNS"].id
        src_ip = pkt["IP"].src if pkt.haslayer("IP") else "Unknown"
        dst_ip = pkt["IP"].dst if pkt.haslayer("IP") else "Unknown"

        query_type_code = pkt["DNSQR"].qtype
        q_types = {
            1: "A (IPv4)",
            2: "NS (Nameserver)",
            5: "CNAME (Alias)",
            6: "SOA (Start of Authority)",
            12: "PTR (Pointer)",
            15: "MX (Mail Exchange)",
            16: "TXT (Text)",
            28: "AAAA (IPv6)",
            33: "SRV (Service)",
            65: "HTTPS (SVCB)",
            255: "ANY",
        }
        query_type = q_types.get(query_type_code, f"OTHER ({query_type_code})")

        is_response = pkt["DNS"].qr == 1
        packet_direction = "RESPONSE" if is_response else "QUERY"

        raw_ip_response = pkt["DNSRR"].rdata if pkt.haslayer("DNSRR") else "Unknown"

        if isinstance(raw_ip_response, bytes):
            ip_response = raw_ip_response.decode("utf-8", errors="ignore").rstrip(".")
        else:
            ip_response = str(raw_ip_response).rstrip(".")

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        info = {
            "id": str(uuid.uuid4()),
            "transaction_id": transaction_id,
            "domain": domain_name,
            "src": src_ip,
            "dst": dst_ip,
            "qtype": query_type,
            "type": packet_direction,
            "ip_response": ip_response,
            "timestamp": timestamp,
        }

        data.append(info)

        description = textwrap.dedent(f"""
            --- {packet_direction} ---

            Transaction ID: {info['transaction_id']}
            Domain: {info['domain']}
            Source: {info['src']}
            Destination: {info['dst']}
            Type: {info['qtype']}
            IP Response: {info['ip_response']}

            Time: {info['timestamp']}
            [Internal Log ID: {info['id']}]

            """).strip()

        print()
        print(description)


def start_sniffing(iface_guid):
    sniff(iface=iface_guid, filter="udp port 53", prn=packet_callback, store=False)


def main():
    selected_iface_guid = get_iface.iface_selection()

    sniffing_thread = threading.Thread(
        target=start_sniffing, args=(selected_iface_guid,), daemon=True
    )

    sniffing_thread.start()

    print(f"Listening on: {selected_iface_guid}")
    print("\nPress ESC to stop sniffing...")

    while True:
        key = utils.get_key()

        if key == "\x1b":
            if data:
                dns_log = data_logger.DataLogger("DNS", selected_iface_guid, data)
                dns_log.save_log()

            print("\nStopping the sniffer...")
            break
