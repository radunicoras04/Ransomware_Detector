import time
import os
from typing import Optional, Dict
from utils.logger import setup_logger, log_info, log_warning, log_error
from utils.paths import ensure_dir, normalize_path
from utils.hashing import sha256_file
from core.monitor import FileMonitor
from core.analyzer import BehaviorAnalyzer
from core.honeyfiles import HoneyfileManager

WATCH_FOLDER = "./test_folder"
LOG_FILE = "./activity.log"

def main():
    watch_path = normalize_path(WATCH_FOLDER)
    ensure_dir(watch_path)
    logger = setup_logger(LOG_FILE)
    log_info(logger, "=" * 60)
    log_info(logger, "[INIT] Ransomware Detector Starting")
    log_info(logger, f"[INIT] Watch folder: {watch_path}")
    log_info(logger, "=" * 60)

    # Initialize honeyfile manager
    honeyfile_dir = os.path.join(watch_path, ".honeyfiles")
    honey_mgr = HoneyfileManager(
        directory=honeyfile_dir,
        count=5,
        prefix=".honey_",
        extensions=[".docx", ".pdf", ".jpg", ".txt"]
    )

    # Create honeyfiles
    honeyfiles = honey_mgr.create_honeyfiles()
    log_info(logger, f"[HONEYFILES] Created {len(honeyfiles)} decoy files in {honeyfile_dir}")
    for hf in honeyfiles:
        log_info(logger, f"[HONEYFILES] - {os.path.basename(hf)}")

    # Initialize behavioral analyzer
    analyzer = BehaviorAnalyzer(
        time_window_sec=3,
        burst_write_threshold=15,
        burst_rename_threshold=6,
        enable_rename_rule=True
    )
    log_info(logger,
             f"[ANALYZER] Thresholds: "
             f"writes={analyzer.burst_write_threshold}, "
             f"renames={analyzer.burst_rename_threshold}, "
             f"window={analyzer.time_window_sec}s"
             )

    # Track file hashes for integrity monitoring
    last_hashes: Dict[str, str] = {}

    # Event handler callback
    def on_event(event_type: str, src_path: str, dest_path: Optional[str] = None):
        # Log event
        if event_type == "moved":
            log_info(logger, f"EVENT: moved | {src_path} -> {dest_path}")
        else:
            log_info(logger, f"EVENT: {event_type} | {src_path}")

        # File integrity checking
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

        # Check honeyfile violations
        violated_honeyfiles = honey_mgr.check_integrity()
        if violated_honeyfiles:
            log_warning(logger, "")
            log_warning(logger, "=" * 60)
            log_warning(logger, "CRITICAL ALERT: HONEYFILE VIOLATION DETECTED! 🚨")
            log_warning(logger, "=" * 60)
            log_warning(logger, "This is a strong indicator of ransomware activity!")
            log_warning(logger, "Honeyfiles are decoy files that should NEVER be modified.")
            log_warning(logger, "")
            for violation in violated_honeyfiles:
                log_warning(logger, f"VIOLATION: {violation}")
            log_warning(logger, "")
            log_warning(logger, "RECOMMENDATION: Immediately investigate this activity!")
            log_warning(logger, "Consider disconnecting from network and running antivirus.")
            log_warning(logger, "=" * 60)
            log_warning(logger, "")

            # Reset analyzer to prevent spam
            analyzer.reset()

            # Restore violated honeyfiles
            log_info(logger, "[HONEYFILES] Attempting to restore violated honeyfiles...")
            for violation in violated_honeyfiles:
                filepath = violation.split(" ")[0]  # Extract path before violation type
                if honey_mgr.restore_honeyfile(filepath):
                    log_info(logger, f"[HONEYFILES] ✓ Restored: {os.path.basename(filepath)}")
                else:
                    log_error(logger, f"[HONEYFILES] ✗ Failed to restore: {os.path.basename(filepath)}")

            return  # Skip normal analysis after honeyfile violation

        # Add event to behavioral analyzer
        analyzer.add_event(event_type)
        verdict = analyzer.verdict()

        # Check for suspicious behavior
        if verdict["suspicious"]:
            log_warning(logger, "")
            log_warning(logger, "=" * 60)
            log_warning(logger, "ALERT: SUSPICIOUS BEHAVIOR DETECTED!")
            log_warning(logger, "=" * 60)
            log_warning(logger,
                        f"Time window: {verdict['time_window_sec']}s | "
                        f"Writes: {verdict['write_count']} | "
                        f"Renames: {verdict['rename_count']}"
                        )
            log_warning(logger, f"Triggers: {', '.join(verdict['triggers'])}")
            log_warning(logger, "")
            log_warning(logger, "Multiple files are being modified/renamed rapidly.")
            log_warning(logger, "This behavior is consistent with ransomware encryption.")
            log_warning(logger, "=" * 60)
            log_warning(logger, "")

            # Reset analyzer
            analyzer.reset()

    # Start file system monitoring
    monitor = FileMonitor([watch_path], on_event)
    monitor.start()

    log_info(logger, "=" * 60)
    log_info(logger, "[RUNNING] Ransomware detector is now active")
    log_info(logger, "[RUNNING] Monitoring for suspicious activity...")
    log_info(logger, "[RUNNING] Honeyfiles deployed and monitored")
    log_info(logger, "[RUNNING] Press Ctrl+C to stop")
    log_info(logger, "=" * 60)

    # Main loop
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        # Cleanup on exit
        log_info(logger, "")
        log_info(logger, "=" * 60)
        log_info(logger, "[SHUTDOWN] Stopping monitoring...")

        monitor.stop()

        # Get final stats
        log_info(logger, "[STATS] Final Statistics:")
        log_info(logger, f"[STATS] - Honeyfiles monitored: {honey_mgr.get_honeyfile_count()}")
        log_info(logger, f"[STATS] - Files tracked: {len(last_hashes)}")

        log_info(logger, "[SHUTDOWN] Ransomware detector stopped")
        log_info(logger, "=" * 60)


if __name__ == "__main__":
    main()