import matplotlib.pyplot as plt
from collections import Counter
import os

class Dashboard:
    def __init__(self, out_path):
        self.out_path = out_path

    def plot_top_ips(self, events, top_n=10):
        ips = [e['ip'] for e in events if e.get('ip')]
        counts = Counter(ips)
        top = counts.most_common(top_n)
        if not top:
            # empty plot
            plt.figure()
            plt.text(0.5, 0.5, "No IPs found", ha="center")
            plt.axis("off")
            os.makedirs(os.path.dirname(self.out_path) or ".", exist_ok=True)
            plt.savefig(self.out_path, bbox_inches='tight')
            plt.close()
            return

        labels, values = zip(*top)
        plt.figure(figsize=(10,6))
        plt.bar(range(len(labels)), values)
        plt.xticks(range(len(labels)), labels, rotation=45, ha="right")
        plt.title("Top IPs by event count")
        plt.tight_layout()
        os.makedirs(os.path.dirname(self.out_path) or ".", exist_ok=True)
        plt.savefig(self.out_path, bbox_inches='tight')
        plt.close()
