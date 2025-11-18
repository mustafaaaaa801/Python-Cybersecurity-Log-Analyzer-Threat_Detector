def load_file(path):
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return [ln.rstrip("\n") for ln in f]
    except FileNotFoundError:
        return []
