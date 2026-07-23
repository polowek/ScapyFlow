import importlib
import os
import subprocess
import textwrap
from json import load

from functions import utils
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

    def __init__(self, layer_number, forced_name=None):
        self.layer = layer_number
        self.layer_name = (
            forced_name if forced_name else self.layers.get(layer_number, "Unknown")
        )
        self.layer_key = None

    def get_information(self, protocol, value):
        module_path = f"protocols.{self.layer_key.lower()}.{protocol.lower()}"

        module = importlib.import_module(module_path)

        func = getattr(module, value or "main")

        func()

    def get_options(self):
        with open(CONFIG_PATH, "r", encoding="UTF-8") as f:
            config_data = load(f)

        self.layer_key = (
            "Application"
            if self.layer_name in ("Session", "Presentation")
            else self.layer_name
        )

        for layer_definition in config_data["options_layers"]:
            if self.layer_key in layer_definition:
                return self.layer_name, layer_definition[self.layer_key]

    def show_options(self):
        if self.layer == 1:
            show_network_interface()
            utils.get_key()
            return

        selected_layer, layer_protocols = self.get_options()

        protocol_map = {}
        for protocol_definition in layer_protocols:
            if isinstance(protocol_definition, dict):
                protocol_map.update(protocol_definition)
            else:
                protocol_map[protocol_definition] = "main"

        upper_map = {k.upper(): k for k in protocol_map}

        valid_protocols = list(protocol_map.keys())

        while True:
            clear_screen()
            print(textwrap.dedent(f"--- {selected_layer.upper()} ---").strip())

            for protocol in valid_protocols:
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

                    if choice in upper_map:
                        clear_screen()

                        real_key = upper_map[choice]
                        self.get_information(real_key, protocol_map[real_key])
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
            case "1" | "2" | "3" | "4" | "7":
                utils.clear_buffer()
                clear_screen()
                Layer(int(key)).show_options()
                break

            case "5":
                Layer(7, "Session").show_options()
                break

            case "6":
                Layer(7, "Presentation").show_options()
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
