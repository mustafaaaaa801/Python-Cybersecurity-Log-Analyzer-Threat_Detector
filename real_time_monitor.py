import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

class LogMonitor(FileSystemEventHandler):
    def __init__(self, filepath, callback):
        self.filepath = filepath
        self.callback = callback

    def on_modified(self, event):
        if event.src_path.endswith(self.filepath):
            print(f"[+] Change detected in {self.filepath}")
            self.callback(self.filepath)

def start_monitoring(files_to_watch):
    observer = Observer()

    for filepath, callback in files_to_watch.items():
        event_handler = LogMonitor(filepath, callback)
        observer.schedule(event_handler, path=".", recursive=False)

    observer.start()
    print("[*] Real-time monitoring started...")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
