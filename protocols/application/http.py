import textwrap
import threading
import uuid

from scapy.all import sniff

from functions import data_logger, get_iface, utils

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

            info = {
                "id": str(uuid.uuid4()),
                "method": method,
                "status": status,
                "src": src_ip,
                "host": headers.get("host", "Unknown"),
                "user-agent": headers.get("user-agent", "Unknown"),
                "content-type": headers.get("content-type", "Unknown"),
            }

            data.append(info)

            if info["method"] != "Unknown":
                description = textwrap.dedent(f"""
                    --- REQUEST CLIENT ---

                    Method: {info['method']}
                    Src: {info['src']}
                    Host: {info['host']}
                    User-Agent: {info['user-agent']}

                    [Internal Log ID: {info['id']}]

                    """).strip()

                print()
                print(description)
                return

            else:
                description = textwrap.dedent(f"""
                    --- RESPONSE SERVER ---

                    Status: {info['status']}
                    Src: {info['src']}
                    Content-Type: {info['content-type']}

                    [Internal Log ID: {info['id']}]

                    """).strip()

                print()
                print(description)


def start_sniffing(iface_guid):
    sniff(iface=iface_guid, filter="tcp port 80", prn=packet_callback)


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
            http_log = data_logger.DataLogger("HTTP", selected_iface_guid, data)
            http_log.save_log()

            print("\nStopping the sniffer...")
            break
