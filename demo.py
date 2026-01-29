"""
Simple interactive test for honeyfiles
"""

import os
import sys
import shutil

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.honeyfiles import HoneyfileManager


def test():
    test_dir = "./test_honeyfiles"

    # Cleanup
    if os.path.exists(test_dir):
        shutil.rmtree(test_dir)

    print("\n" + "="*60)
    print("HONEYFILE TEST")
    print("="*60)

    # Step 1: Create honeyfiles
    print("\n[1] Creating honeyfiles...")
    honey_mgr = HoneyfileManager(
        directory=test_dir,
        count=5,
        prefix=".honey_",
        extensions=[".docx", ".pdf", ".txt"]
    )
    honeyfiles = honey_mgr.create_honeyfiles()

    for hf in honeyfiles:
        print(f"    Created: {os.path.basename(hf)}")

    input("\nPress Enter to check integrity...")

    # Step 2: Initial integrity check
    print("\n[2] Checking integrity...")
    violations = honey_mgr.check_integrity()

    if not violations:
        print("    All honeyfiles intact ✓")
    else:
        print(f"    Violations detected: {violations}")

    input("\nPress Enter to simulate ransomware attack...")

    # Step 3: Modify file
    print("\n[3] Modifying honeyfile...")
    target = honeyfiles[0]
    os.chmod(target, 0o644)
    with open(target, 'a') as f:
        f.write("\nENCRYPTED BY RANSOMWARE")
    print(f"    Modified: {os.path.basename(target)}")

    input("\nPress Enter to detect violation...")

    # Step 4: Detect modification
    print("\n[4] Checking integrity...")
    violations = honey_mgr.check_integrity()

    if violations:
        print("    VIOLATION DETECTED!")
        for v in violations:
            print(f"    {v}")
    else:
        print("    No violations (detection failed)")

    input("\nPress Enter to delete a honeyfile...")

    # Step 5: Delete file
    print("\n[5] Deleting honeyfile...")
    target2 = honeyfiles[1]
    os.remove(target2)
    print(f"    Deleted: {os.path.basename(target2)}")

    input("\nPress Enter to detect deletion...")

    # Step 6: Detect deletion
    print("\n[6] Checking integrity...")
    violations = honey_mgr.check_integrity()

    deleted = [v for v in violations if "DELETED" in v]
    if deleted:
        print("    DELETION DETECTED!")
        for v in deleted:
            print(f"    {v}")

    input("\nPress Enter to restore honeyfile...")

    # Step 7: Restore
    print("\n[7] Restoring violated honeyfile...")
    if honey_mgr.restore_honeyfile(honeyfiles[0]):
        print(f"    Restored: {os.path.basename(honeyfiles[0])}")

        violations = honey_mgr.check_integrity()
        modified = [v for v in violations if "MODIFIED" in v and honeyfiles[0] in v]

        if not modified:
            print("    Restoration verified ✓")

    input("\nPress Enter to view stats...")

    # Step 8: Stats
    print("\n[8] Statistics")
    print(f"    Total honeyfiles: {honey_mgr.get_honeyfile_count()}")

    violations = honey_mgr.check_integrity()
    print(f"    Current violations: {len(violations)}")

    for v in violations:
        print(f"      - {v}")

    input("\nPress Enter to cleanup...")

    # Cleanup
    print("\n[9] Cleanup")
    shutil.rmtree(test_dir)
    print("    Test files removed")

    print("\n" + "="*60)
    print("TEST COMPLETE")
    print("="*60 + "\n")


if __name__ == "__main__":
    test()