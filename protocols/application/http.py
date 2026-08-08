import textwrap
import uuid
from datetime import datetime

from functions.utils import Colors

data = []


def packet_callback(pkt):
    if pkt.haslayer("TCP") and pkt.haslayer("Raw"):
        if pkt["TCP"].sport == 80 or pkt["TCP"].dport == 80:
            src_ip = (
                pkt["IP"].src
                if pkt.haslayer("IP")
                else (pkt["IPv6"].src if pkt.haslayer("IPv6") else "Unknown")
            )

            raw_data = pkt["Raw"].load
            if not (
                raw_data.startswith(b"GET")
                or raw_data.startswith(b"POST")
                or raw_data.startswith(b"HTTP")
                or raw_data.startswith(b"HEAD")
                or raw_data.startswith(b"PUT")
            ):
                return

            text_data = raw_data.decode("utf-8", errors="ignore")
            lines = text_data.splitlines()

            if not lines:
                return

            headers = {}
            for line in lines[1:]:
                if ": " in line:
                    key, value = line.split(": ", 1)
                    headers[key.lower()] = value.strip()

            first_line = lines[0]
            method = "Unknown"
            status = "Unknown"

            parts = first_line.split(" ")
            if first_line.startswith("HTTP/"):
                if len(parts) > 1:
                    status = parts[1]
            elif parts:
                method = parts[0]

            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            is_request = "REQUEST" if method != "Unknown" else "RESPONSE"

            info = {
                "id": str(uuid.uuid4()),
                "type": is_request,
                "method": method,
                "status": status,
                "src": src_ip,
                "host": headers.get("host", "Unknown"),
                "user-agent": headers.get("user-agent", "Unknown"),
                "content-type": headers.get("content-type", "Unknown"),
                "timestamp": timestamp,
            }

            data.append(info)

            if is_request == "REQUEST":
                description = textwrap.dedent(f"""\
                    {Colors.GRAY}│ ───{Colors.RESET} {Colors.GREEN}{Colors.BOLD}HTTP REQUEST{Colors.RESET} {Colors.GRAY}───{Colors.RESET}
                    {Colors.GRAY}│{Colors.RESET} {Colors.GRAY}Method:{Colors.RESET} {Colors.CYAN}{Colors.BOLD}{info['method']}{Colors.RESET}
                    {Colors.GRAY}│{Colors.RESET} {Colors.GRAY}Source:{Colors.RESET} {Colors.GREEN}{info['src']}{Colors.RESET}
                    {Colors.GRAY}│{Colors.RESET} {Colors.GRAY}Host:{Colors.RESET} {Colors.YELLOW}{info['host']}{Colors.RESET}
                    {Colors.GRAY}│{Colors.RESET} {Colors.GRAY}User-Agent:{Colors.RESET} {info['user-agent']}
                    {Colors.GRAY}│{Colors.RESET} {Colors.GRAY}Time:{Colors.RESET} {info['timestamp']}
                    {Colors.GRAY}└─ Log ID: {info['id']}{Colors.RESET}
                """).strip()
            else:
                status_color = (
                    Colors.GREEN if info["status"].startswith("2") else Colors.RED
                )
                description = textwrap.dedent(f"""\
                    {Colors.GRAY}│ ───{Colors.RESET} {Colors.MAGENTA}{Colors.BOLD}HTTP RESPONSE{Colors.RESET} {Colors.GRAY}───{Colors.RESET}
                    {Colors.GRAY}│{Colors.RESET} {Colors.GRAY}Status:{Colors.RESET} {status_color}{Colors.BOLD}{info['status']}{Colors.RESET}
                    {Colors.GRAY}│{Colors.RESET} {Colors.GRAY}Source:{Colors.RESET} {Colors.GREEN}{info['src']}{Colors.RESET}
                    {Colors.GRAY}│{Colors.RESET} {Colors.GRAY}Content-Type:{Colors.RESET} {Colors.YELLOW}{info['content-type']}{Colors.RESET}
                    {Colors.GRAY}│{Colors.RESET} {Colors.GRAY}Time:{Colors.RESET} {info['timestamp']}
                    {Colors.GRAY}└─ Log ID: {info['id']}{Colors.RESET}
                """).strip()

            print()
            print(description)
