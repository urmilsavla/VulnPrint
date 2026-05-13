import os
import hashlib
from collections import defaultdict

def hash_file(filepath):
    hasher = hashlib.md5()
    try:
        with open(filepath, 'rb') as f:
            buf = f.read()
            hasher.update(buf)
        return hasher.hexdigest()
    except Exception:
        return None

duplicates = defaultdict(list)

for root, _, files in os.walk('src'):
    for filename in files:
        filepath = os.path.join(root, filename)
        file_hash = hash_file(filepath)
        if file_hash:
            duplicates[file_hash].append(filepath)

print("Duplicate Files Found:")
for h, paths in duplicates.items():
    if len(paths) > 1:
        print(f"Duplicates: {paths}")
