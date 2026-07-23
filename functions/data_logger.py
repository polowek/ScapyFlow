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

        if not os.path.exists(DATA_SRC):
            os.makedirs(os.path.dirname(DATA_SRC), exist_ok=True)

            with open(DATA_SRC, "w", encoding="UTF-8") as f:
                dump([], f, indent=4, ensure_ascii=False)

            print(f"[INFO] Created missing file: {DATA_SRC}")

        try:
            with open(DATA_SRC, "r", encoding="UTF-8") as f:
                content = load(f)

                if isinstance(content, list):
                    all_data = content

        except (JSONDecodeError, ValueError) as e:
            print(f"[WARNING] File {DATA_SRC} is corrupted or empty (error: {e}). Starting with a fresh list.")

        all_data.extend(self.data)

        with open(DATA_SRC, "w", encoding="UTF-8") as f:
            dump(all_data, f, indent=4, ensure_ascii=False)

        self.data = []
        print(f"\n[SUCCESS] Successfully saved data to {DATA_SRC}")
