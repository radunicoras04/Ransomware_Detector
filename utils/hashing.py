import hashlib

def sha256_file(path: str, chunk_size: int = 1024 * 1024) -> str:
    sha256 = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            sha256.update(chunk)
    return sha256.hexdigest()
