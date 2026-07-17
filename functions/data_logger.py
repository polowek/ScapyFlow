import os
from json import JSONDecodeError, dump, load

DATA_SRC = r"data/data.json"


class DataLogger:
    def __init__(self, protocol_name, iface, data):
        self.protocol_name = protocol_name
        self.iface = iface
        self.data = data

        for pkt in self.data:
            pkt["protocol"] = self.protocol_name
            pkt["iface"] = self.iface

    def save_log(self):
        all_data = []

        if os.path.exists(DATA_SRC):
            try:
                with open(DATA_SRC, "r", encoding="UTF-8") as f:
                    content = load(f)

                    if isinstance(content, list):
                        all_data = content

            except (JSONDecodeError, ValueError):
                pass

            all_data.extend(self.data)

            with open(DATA_SRC, "w", encoding="UTF-8") as f:
                dump(all_data, f, indent=4, ensure_ascii=False)

            self.data = {}
