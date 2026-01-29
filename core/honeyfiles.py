import os
import random
from pathlib import Path
from typing import List, Dict
from utils.hashing import sha256_file


class HoneyfileManager:
    def __init__(self, directory: str, count: int, prefix: str, extensions: List[str]):
        self.directory = Path(directory)
        self.count = count
        self.prefix = prefix
        self.extensions = extensions
        self.honeyfiles: Dict[str, str] = {}  # {filepath: original_hash}

    def create_honeyfiles(self) -> List[str]:
        enticing_names = [
            "Passwords", "BankAccount", "CreditCards", "SSN",
            "TaxReturns_2024", "PrivateKeys", "Secrets", "Confidential",
            "Financial_Report", "Salary_Info", "Bitcoin_Wallet",
            "Personal_Documents", "ID_Scans", "Medical_Records",
            "Insurance_Policy", "Investment_Portfolio"
        ]

        self.directory.mkdir(exist_ok=True, parents=True)

        created_files = []

        for i in range(self.count):
            # Pick random name and extension
            name = random.choice(enticing_names)
            ext = random.choice(self.extensions)
            filename = f"{self.prefix}{name}_{i}{ext}"
            filepath = self.directory / filename

            # Create dummy content that looks realistic
            content = self._generate_realistic_content(ext)

            # Write file
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(content)

            # Make file hidden on Unix systems (starts with .)
            # On Windows, we'd need to set file attributes separately
            if os.name != 'nt' and not filename.startswith('.'):
                hidden_filepath = self.directory / f".{filename}"
                filepath.rename(hidden_filepath)
                filepath = hidden_filepath

            # Calculate and store hash
            file_hash = sha256_file(str(filepath))
            self.honeyfiles[str(filepath)] = file_hash
            created_files.append(str(filepath))

            # Set file as read-only to make it more suspicious if modified
            try:
                os.chmod(filepath, 0o444)  # Read-only
            except Exception:
                pass  # Ignore if chmod fails (e.g., on Windows)

        return created_files

    def _generate_realistic_content(self, extension: str) -> str:
        if extension in ['.txt', '.docx', '.doc']:
            return """CONFIDENTIAL - DO NOT DISTRIBUTE

Account Numbers:
- Checking: 1234-5678-9012
- Savings: 9876-5432-1098

Password List:
- Email: MySecurePass123!
- Banking: Finance2024$
- Crypto Wallet: Bitcoin#2024

This is a honeyfile - any modification indicates malicious activity.
DO NOT EDIT OR DELETE THIS FILE.
"""

        elif extension in ['.pdf']:
            return """FINANCIAL STATEMENT 2024

Total Assets: $XXX,XXX
Investment Portfolio
Account Holdings

[This is a decoy file for ransomware detection]
"""

        elif extension in ['.xlsx', '.xls', '.csv']:
            return """Account,Balance,Type
Checking,50000,Primary
Savings,125000,High-Yield
Investment,250000,Portfolio

[Honeyfile - Do Not Modify]
"""

        else:
            # Generic content with some randomness
            random_data = os.urandom(50).hex()
            return f"""IMPORTANT DOCUMENT

Reference: {random_data}

This is a monitoring file.
Any modification will trigger security alerts.
"""
#if any honeyfiles have been modified or deleted, return list of violated honeyfiles with violation type;
#empty list if all honeyfiles are intact
    def check_integrity(self) -> List[str]:
        violations = []

        for filepath, original_hash in self.honeyfiles.items():
            # Check if file still exists
            if not os.path.exists(filepath):
                violations.append(f"{filepath} (DELETED)")
                continue

            # Check if file was modified
            try:
                current_hash = sha256_file(filepath)
                if current_hash != original_hash:
                    violations.append(f"{filepath} (MODIFIED)")
            except PermissionError:
                violations.append(f"{filepath} (ACCESS_DENIED)")
            except Exception as e:
                violations.append(f"{filepath} (ERROR: {str(e)})")

        return violations

# Restore violated honeyfile to original vers
# True if success, false otherwise
    def restore_honeyfile(self, filepath: str) -> bool:
        if filepath not in self.honeyfiles:
            return False

        try:
            # Extract info from filepath
            path_obj = Path(filepath)
            ext = path_obj.suffix

            # Regenerate content
            content = self._generate_realistic_content(ext)

            # Recreate file
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(content)

            # Update hash
            new_hash = sha256_file(filepath)
            self.honeyfiles[filepath] = new_hash

            # Reset permissions
            try:
                os.chmod(filepath, 0o444)
            except Exception:
                pass

            return True

        except Exception:
            return False

    def get_honeyfile_count(self) -> int:
        return len(self.honeyfiles)

    def get_honeyfile_paths(self) -> List[str]:
        return list(self.honeyfiles.keys())

# Remove all honeyfiles when system shut down
    def cleanup(self):
        for filepath in self.honeyfiles.keys():
            try:
                if os.path.exists(filepath):
                    # Remove read-only flag first
                    os.chmod(filepath, 0o644)
                    os.remove(filepath)
            except Exception:
                pass

        self.honeyfiles.clear()