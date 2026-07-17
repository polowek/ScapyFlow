import sys

import questionary
from scapy.all import conf


def iface_selection():
    iface_map = {
        f"{i}. {iface.description} ({iface.ip if iface.ip else 'Brak IP'})": iface_guid
        for i, (iface_guid, iface) in enumerate(conf.ifaces.items(), 1)
    }

    choice = questionary.select(
        "Select the network interface to listen on:", choices=list(iface_map.keys())
    ).ask()

    if choice is None:
        sys.exit(0)

    return iface_map.get(choice)
