#handle filesystem paths safely no matter the operating system
#ensure_dir creates directories in case they dont exist
#normalize_path returns normalized absolute path (used for cross platform)

import os

def ensure_dir(path: str):
    os.makedirs(path, exist_ok=True)

def normalize_path(path: str) -> str:
    return os.path.abspath(os.path.expanduser(path))