import importlib
import os
import subprocess
import textwrap
import threading
from json import load

from scapy.all import sniff

from functions import data_logger, get_iface, utils
from protocols.physical.main import show_network_interface

CONFIG_PATH = r"config/config.json"


class Layer:
    layers = {
        1: "Physical",
        2: "Data Link",
        3: "Network",
        4: "Transport",
        5: "Session",
        6: "Presentation",
        7: "Application",
    }

    def __init__(self, layer_number):
        self.layer_number = layer_number
        self.layer_name = self.layers.get(layer_number, "Unknown")

    def get_protocol_config(self, protocol):
        with open(CONFIG_PATH, "r", encoding="UTF-8") as f:
            config_data = load(f)

        protocols_config = config_data.get("protocols_config", {})

        protocol_config = {}
        for protocol_name, protocol_settings in protocols_config.items():
            if protocol_name.lower() == protocol.lower():
                protocol_config = protocol_settings
                break

        handler = protocol_config.get("handler", "packet_callback")
        sniff_filter = protocol_config.get("sniff_filter", "")

        return handler, sniff_filter

    def get_information(self, protocol):
        module = None

        current_folder = self.layer_name.lower()
        other_folders = [
            layer.lower()
            for layer in self.layers.values()
            if layer.lower() != current_folder
        ]

        search_paths = [current_folder] + other_folders

        searched_modules = []
        for folder_name in search_paths:
            module_path = f"protocols.{folder_name}.{protocol.lower()}"
            searched_modules.append(module_path)
            try:
                module = importlib.import_module(module_path)
                break
            except ModuleNotFoundError:
                continue

        if not module:
            raise ModuleNotFoundError(
                f"No module found for protocol '{protocol}'. Searched paths: {searched_modules}"
            )

        handler, sniff_filter = self.get_protocol_config(protocol)

        try:
            packet_callback = getattr(module, handler or "packet_callback")
        except AttributeError:
            print(
                f"\n[ERROR] Module '{module.__name__}' does not have a handler function named '{handler}'!"
            )
            print(
                f"Please check your JSON configuration file and the function name in the protocol file."
            )

            utils.get_key()
            return

        selected_iface_guid = get_iface.iface_selection()

        sniffing_thread = threading.Thread(
            target=sniff,
            kwargs={
                "iface": selected_iface_guid,
                "filter": sniff_filter,
                "prn": packet_callback,
                "store": False,
            },
            daemon=True,
        )

        sniffing_thread.start()

        print(f"Listening on: {selected_iface_guid}")
        print("\nPress ESC to stop sniffing...")

        while True:
            key = utils.get_key()

            if key == "\x1b":
                print("\nStopping the sniffer...")

                collected_data = getattr(module, "data", [])
                if collected_data:
                    log = data_logger.DataLogger(
                        protocol, selected_iface_guid, collected_data
                    )
                    log.save_log()
                break

    def get_options(self):
        with open(CONFIG_PATH, "r", encoding="UTF-8") as f:
            config_data = load(f)

        protocols_list = config_data.get("options_layers", {}).get(self.layer_name, [])

        if not protocols_list:
            protocols_list = ["[No available protocols for this layer]"]

        return protocols_list

    def show_options(self):
        if self.layer_number == 1:
            show_network_interface()
            utils.get_key()
            return

        protocols_list = self.get_options()

        while True:
            clear_screen()
            print(textwrap.dedent(f"--- {self.layer_name.upper()} ---").strip())

            for protocol in protocols_list:
                print(f"- {protocol}")

            print()
            footer = textwrap.dedent(f"""
                Press Enter to start typing to select.
                Press ESC to return to the menu. 
            """).strip()
            print(footer)

            key = utils.get_key()

            match key:
                case "\r":
                    choice = input("\nWhich Protocols?: ").upper()

                    if choice in (p.upper() for p in protocols_list):
                        clear_screen()

                        self.get_information(choice)
                        break
                    else:
                        print("There is no such protocol, please try again.")
                        utils.get_key()

                case "\x1b":
                    utils.clear_buffer()
                    clear_screen()
                    get_information()
                    break


def clear_screen():
    command = "cls" if os.name == "nt" else "clear"
    subprocess.run(command, shell=True)


def get_information():
    while True:
        menu = textwrap.dedent("""
            --- GET INFORMATION ---
            7 - Application
            6 - Presentation
            5 - Session
            4 - Transport
            3 - Network
            2 - Data Link
            1 - Physcial

            Press ESC to return to the menu.  

            Choose Layer:                                                        
            """).strip()

        clear_screen()
        print(menu)

        key = utils.get_key()

        match key:
            case "1" | "2" | "3" | "4" | "5" | "6" | "7":
                utils.clear_buffer()
                clear_screen()
                Layer(int(key)).show_options()
                break

            case "\x1b":
                utils.clear_buffer()
                clear_screen()
                main()
                break


def send_packet():
    # TODO: Implement packet sending logic
    # Work in progress - Coming soon!
    pass


def analyse_packets():
    # TODO: Implement packet analysis logic
    # Work in progress - Coming soon!
    pass


def main():
    while True:
        menu = textwrap.dedent("""
            --- NETWORK TOOLS ---
            1. Get Information
            2. Send Packet
            3. Analyse Packets
            4. Exit
                               
            Select options (1-4):
            """).strip()

        print(menu)

        key = utils.get_key()

        match key:
            case "1":
                utils.clear_buffer()
                get_information()
                break

            case "2":
                utils.clear_buffer()
                send_packet()
                break

            case "3":
                utils.clear_buffer()
                analyse_packets()
                break

            case "4":
                utils.clear_buffer()
                print("Exit")
                break

            case _:
                print("Invalid selection, please try again.\n")


if __name__ == "__main__":
    main()
