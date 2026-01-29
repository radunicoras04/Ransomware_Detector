from watchdog.observers.polling import PollingObserver as Observer
from watchdog.events import FileSystemEventHandler


class Handler(FileSystemEventHandler):
    def __init__(self, callback):
        self.callback = callback

    def _safe(self, event_type, src_path, dest_path=None):
        try:
            self.callback(event_type, src_path, dest_path)
        except Exception as e:
            print(f"[MONITOR ERROR] callback failed: {e}")

    def on_created(self, event):
        if not event.is_directory:
            self._safe("created", event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            self._safe("modified", event.src_path)

    def on_moved(self, event):
        if not event.is_directory:
            self._safe("moved", event.src_path, event.dest_path)

    def on_deleted(self, event):
        if not event.is_directory:
            self._safe("deleted", event.src_path)


class FileMonitor:
    def __init__(self, paths, callback):
        self.observer = Observer()
        self.handler = Handler(callback)
        self.paths = paths

    def start(self):
        for p in self.paths:
            self.observer.schedule(self.handler, p, recursive=True)
        self.observer.start()

    def stop(self):
        self.observer.stop()
        self.observer.join()
