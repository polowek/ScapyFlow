from scapy.all import conf


def show_network_interface():
    iface_map = tuple(
        f"{i}. {iface.description} ({iface.ip if iface.ip else 'Brak IP'})"
        for i, iface in enumerate(conf.ifaces.values(), 1)
    )

    print("Available network interfaces:")

    print("\n".join(iface_map))
