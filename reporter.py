import json
import os

class Reporter:
    def __init__(self, out_path):
        self.out_path = out_path

    def save(self, data):
        dirp = os.path.dirname(self.out_path)
        if dirp:
            os.makedirs(dirp, exist_ok=True)
        with open(self.out_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
