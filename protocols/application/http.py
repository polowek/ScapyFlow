import textwrap
import uuid
from datetime import datetime

data = []


def packet_callback(pkt):
    if pkt.haslayer("TCP") and pkt.haslayer("Raw"):
        if pkt["TCP"].sport == 80 or pkt["TCP"].dport == 80:
            src_ip = pkt["IP"].src if pkt.haslayer("IP") else "Unknown"

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
                status = parts[1] if len(parts) > 1 else "Unknown"
            else:
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
                description = textwrap.dedent(f"""
                    --- HTTP REQUEST ---

                    Method: {info['method']}
                    Source: {info['src']}
                    Host: {info['host']}
                    User-Agent: {info['user-agent']}

                    Time: {info['timestamp']}
                    [Internal Log ID: {info['id']}]

                    """).strip()
            else:
                description = textwrap.dedent(f"""
                    --- HTTP RESPONSE ---

                    Status: {info['status']}
                    Source: {info['src']}
                    Content-Type: {info['content-type']}

                    Time: {info['timestamp']}
                    [Internal Log ID: {info['id']}]

                    """).strip()

            print()
            print(description)
