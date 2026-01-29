import time
from typing import Optional, Dict

from utils.logger import setup_logger, log_info, log_warning
from utils.paths import ensure_dir, normalize_path
from utils.hashing import sha256_file

from core.monitor import FileMonitor
from core.analyzer import BehaviorAnalyzer


WATCH_FOLDER = "./test_folder"
LOG_FILE = "./activity.log"


def main():
    watch_path = normalize_path(WATCH_FOLDER)
    ensure_dir(watch_path)

    logger = setup_logger(LOG_FILE)
    log_info(logger, f"[INIT] Watch folder: {watch_path}")

    analyzer = BehaviorAnalyzer(
        time_window_sec=3,
        burst_write_threshold=15,
        burst_rename_threshold=6,
        enable_rename_rule=True
    )

    last_hashes: Dict[str, str] = {}

    def on_event(event_type: str, src_path: str, dest_path: Optional[str] = None):
        if event_type == "moved":
            log_info(logger, f"EVENT: moved | {src_path} -> {dest_path}")
        else:
            log_info(logger, f"EVENT: {event_type} | {src_path}")

        if event_type == "modified":
            try:
                h = sha256_file(src_path)
                prev = last_hashes.get(src_path)
                last_hashes[src_path] = h

                if prev and prev != h:
                    log_info(logger, f"INTEGRITY: changed | {src_path} | sha256={h[:12]}...")
                elif not prev:
                    log_info(logger, f"INTEGRITY: baseline | {src_path} | sha256={h[:12]}...")
            except (FileNotFoundError, PermissionError, IsADirectoryError):
                pass

        analyzer.add_event(event_type)
        v = analyzer.verdict()

        if v["suspicious"]:
            log_warning(
                logger,
                "ALERT: suspicious behavior detected | "
                f"window={v['time_window_sec']}s | "
                f"writes={v['write_count']} renames={v['rename_count']} | "
                f"triggers={v['triggers']}"
            )
            analyzer.reset()

    monitor = FileMonitor([watch_path], on_event)
    monitor.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        monitor.stop()
        log_info(logger, "[STOP] Monitoring stopped.")


if __name__ == "__main__":
    main()
