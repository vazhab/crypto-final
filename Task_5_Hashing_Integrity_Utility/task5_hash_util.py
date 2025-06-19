import hashlib
import json

def compute_hash(filepath):
    with open(filepath, 'rb') as f:
        data = f.read()
    return {
        "sha256": hashlib.sha256(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "md5": hashlib.md5(data).hexdigest()
    }

def check_integrity(original_path, tampered_path, hash_file):
    with open(hash_file, 'r') as f:
        saved_hashes = json.load(f)

    for file_path in [original_path, tampered_path]:
        computed = compute_hash(file_path)
        expected = saved_hashes.get(os.path.basename(file_path), {})
        print(f"Checking: {file_path}")
        result = "PASS" if computed == expected else "FAIL"
        print(f"Result: {result}\n")

if __name__ == "__main__":
    import os
    check_integrity("original.txt", "tampered.txt", "hashes.json")