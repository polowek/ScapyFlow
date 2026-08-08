import json
import textwrap
import uuid
from datetime import datetime

from functions.utils import Colors

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

        ip_layer = pkt.getlayer("IP") or pkt.getlayer("IPv6")
        src_ip = ip_layer.src if ip_layer else "Unknown"
        dst_ip = ip_layer.dst if ip_layer else "Unknown"

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

        header_color = Colors.MAGENTA if is_response else Colors.BLUE

        description = textwrap.dedent(f"""\
            {Colors.GRAY}│ ───{Colors.RESET} {header_color}{Colors.BOLD}{packet_direction}{Colors.RESET} {Colors.GRAY}───{Colors.RESET}
            {Colors.GRAY}│{Colors.RESET} {Colors.GRAY}Transaction ID:{Colors.RESET} {Colors.YELLOW}{info['transaction_id']}{Colors.RESET}
            {Colors.GRAY}│{Colors.RESET} {Colors.GRAY}Domain:{Colors.RESET} {Colors.CYAN}{Colors.BOLD}{info['domain']}{Colors.RESET}
            {Colors.GRAY}│{Colors.RESET} {Colors.GRAY}Source:{Colors.RESET} {Colors.GREEN}{info['src']}{Colors.RESET} ──> {Colors.GREEN}{info['dst']}{Colors.RESET}
            {Colors.GRAY}│{Colors.RESET} {Colors.GRAY}Type:{Colors.RESET} {info['qtype']}
            {Colors.GRAY}│{Colors.RESET} {Colors.GRAY}IP Response:{Colors.RESET} {Colors.YELLOW}{info['ip_response']}{Colors.RESET}
            {Colors.GRAY}│{Colors.RESET} {Colors.GRAY}Time:{Colors.RESET} {info['timestamp']}
            {Colors.GRAY}└─ Log ID: {info['id']}{Colors.RESET}
        """).strip()

        print()
        print(description)
