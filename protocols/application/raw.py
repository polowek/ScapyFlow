import textwrap
import uuid
from datetime import datetime

from functions.utils import Colors

data = []


def packet_callback(pkt):
    if pkt.haslayer("Raw"):
        raw_data = pkt["Raw"].load

        cargo_length = f"{len(raw_data)} B"

        ip_layer = pkt.getlayer("IP") or pkt.getlayer("IPv6")
        ip_src = ip_layer.src if ip_layer else "Unknown"
        ip_dst = ip_layer.dst if ip_layer else "Unknown"

        l4_layer = pkt.getlayer("TCP") or pkt.getlayer("UDP")
        sport = l4_layer.sport if l4_layer else "Unknown"
        dport = l4_layer.dport if l4_layer else "Unknown"

        eth_layer = pkt.getlayer("Ether")
        mac_src = eth_layer.src if eth_layer else "Unknown"
        mac_dst = eth_layer.dst if eth_layer else "Unknown"

        payload_hex = raw_data[:16].hex(" ")

        is_encrypted = (
            sport == 443
            or dport == 443
            or pkt.haslayer("TLS")
            or (len(raw_data) > 0 and raw_data[0] in [0x16, 0x17])
        )
        payload_type = "TLS/Encrypted" if is_encrypted else "Plaintext/Unknown"

        payload_txt = (
            "".join(chr(b) if 32 <= b <= 126 else "." for b in raw_data)
            if not is_encrypted
            else "Unknown"
        )

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        info = {
            "id": str(uuid.uuid4()),
            "packet_length": cargo_length,
            "ip_src": ip_src,
            "ip_dst": ip_dst,
            "sport": sport,
            "dport": dport,
            "mac_src": mac_src,
            "mac_dst": mac_dst,
            "payload_type": payload_type,
            "payload_hex": payload_hex,
            "payload_txt": payload_txt,
            "timestamp": timestamp,
        }

        data.append(info)

        type_color = Colors.RED if is_encrypted else Colors.GREEN

        description = textwrap.dedent(f"""\
            {Colors.GRAY}┌─[{Colors.RESET}{type_color}{payload_type}{Colors.RESET}{Colors.GRAY}]────[{Colors.RESET}{Colors.CYAN}{cargo_length}{Colors.RESET}{Colors.GRAY}]────[{Colors.RESET}{Colors.GRAY}{timestamp}{Colors.RESET}{Colors.GRAY}]{Colors.RESET}
            {Colors.GRAY}│{Colors.RESET} {Colors.GREEN}{ip_src}{Colors.RESET}:{Colors.YELLOW}{sport}{Colors.RESET} ──> {Colors.GREEN}{ip_dst}{Colors.RESET}:{Colors.YELLOW}{dport}{Colors.RESET}
            {Colors.GRAY}│{Colors.RESET} {Colors.GRAY}MAC:{Colors.RESET} {mac_src} -> {mac_dst}
            {Colors.GRAY}├─{Colors.RESET} HEX: {payload_hex}
            {Colors.GRAY}├─{Colors.RESET} TXT: {payload_txt}
            {Colors.GRAY}└─{Colors.RESET} {Colors.GRAY}ID: {info['id']}{Colors.RESET}
        """).strip()

        print()
        print(description)
