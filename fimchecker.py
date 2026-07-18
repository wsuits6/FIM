#!/usr/bin/env python3
"""
File Integrity Checker
-----------------------
Creates a baseline of SHA256 hashes for every file in a directory,
then lets you re-run it later to detect added, removed, or modified files.
"""

# ---- Imports ----
import os          # for walking directories, joining paths, chmod
import hashlib      # for SHA256 hashing
import json         # for saving/loading the baseline as structured data
import stat         # for setting read-only file permissions
import time         # for timestamping the baseline
import sys          # for clean exits on error


# ---- Config ----
BASELINE_FILE = "baseline.json"   # where we store the hash database
CHUNK_SIZE = 8192                 # read files in 8KB chunks (memory-safe for big files)


def hash_file(filepath):
    """
    Compute the SHA256 hash of a single file's CONTENTS.
    We read in chunks instead of the whole file at once,
    so this works even on very large files.
    """
    sha256 = hashlib.sha256()          # create a new hash object for this file
    try:
        with open(filepath, "rb") as f:      # "rb" = read binary, critical for correct hashing
            while True:
                chunk = f.read(CHUNK_SIZE)   # read a chunk of bytes
                if not chunk:                # empty chunk means we hit end of file
                    break
                sha256.update(chunk)         # feed the chunk into the running hash
        return sha256.hexdigest()            # final hash as a hex string
    except (PermissionError, FileNotFoundError) as e:
        # Some files might be locked or vanish mid-scan; don't crash the whole tool
        print(f"  [!] Could not read {filepath}: {e}")
        return None


def scan_directory(dir_path):
    """
    Walk the entire directory tree and build a dict of
    {file_path: hash} for every file found.
    """
    file_hashes = {}

    # os.walk yields (current_folder, list_of_subfolders, list_of_filenames)
    # for every folder in the tree, including dir_path itself.
    for root, _dirs, files in os.walk(dir_path):
        for filename in files:
            full_path = os.path.join(root, filename)   # build the real path
            file_hash = hash_file(full_path)
            if file_hash is not None:
                file_hashes[full_path] = file_hash      # store it in the dict

    return file_hashes


def save_baseline(file_hashes, dir_path):
    """
    Save the hash dictionary to a JSON file, along with metadata
    (scanned directory + timestamp), then lock the file read-only.
    """
    data = {
        "directory": dir_path,
        "created_at": time.ctime(),   # human-readable timestamp
        "hashes": file_hashes,
    }

    with open(BASELINE_FILE, "w") as f:
        json.dump(data, f, indent=2)   # indent=2 just makes it human-readable

    # "Lock" the file: remove write permission so it resists casual edits/tampering.
    # stat.S_IREAD = read-only for the owner.
    os.chmod(BASELINE_FILE, stat.S_IREAD)

    print(f"\nBaseline saved to '{BASELINE_FILE}' and locked read-only.")
    print(f"Tracked {len(file_hashes)} files.")


def load_baseline():
    """
    Load a previously saved baseline JSON file back into memory.
    """
    if not os.path.exists(BASELINE_FILE):
        print(f"No baseline found at '{BASELINE_FILE}'. Run in 'create' mode first.")
        sys.exit(1)

    with open(BASELINE_FILE, "r") as f:
        data = json.load(f)

    return data


def compare(old_hashes, new_hashes):
    """
    Compare the old baseline hashes to a fresh scan.
    Returns three lists: modified, added, removed.
    """
    old_paths = set(old_hashes.keys())
    new_paths = set(new_hashes.keys())

    added = new_paths - old_paths                     # files present now but not before
    removed = old_paths - new_paths                    # files present before but not now
    common = old_paths & new_paths                     # files present in both

    modified = [p for p in common if old_hashes[p] != new_hashes[p]]  # hash changed

    return modified, sorted(added), sorted(removed)


def print_report(modified, added, removed):
    """
    Print a clear, human-readable summary of what changed.
    """
    print("\n----- Integrity Report -----")

    if not modified and not added and not removed:
        print("No changes detected. All files match the baseline.")
        return

    if modified:
        print(f"\nMODIFIED ({len(modified)}):")
        for path in modified:
            print(f"  ~ {path}")

    if added:
        print(f"\nADDED ({len(added)}):")
        for path in added:
            print(f"  + {path}")

    if removed:
        print(f"\nREMOVED ({len(removed)}):")
        for path in removed:
            print(f"  - {path}")


def unlock_baseline_if_exists():
    """
    Before overwriting an old baseline, remove the read-only lock,
    otherwise the OS will block the write.
    """
    if os.path.exists(BASELINE_FILE):
        os.chmod(BASELINE_FILE, stat.S_IWRITE | stat.S_IREAD)


def main():
    print("File Integrity Checker")
    print("1. Create new baseline")
    print("2. Check directory against existing baseline")
    choice = input("Choose an option (1/2): ").strip()

    if choice == "1":
        dir_path = input("Directory to baseline: ").strip()
        if not os.path.isdir(dir_path):
            print("That path is not a valid directory.")
            sys.exit(1)

        unlock_baseline_if_exists()         # allow overwrite if one already exists
        print(f"\nScanning '{dir_path}'...")
        file_hashes = scan_directory(dir_path)
        save_baseline(file_hashes, dir_path)

    elif choice == "2":
        data = load_baseline()
        dir_path = data["directory"]
        old_hashes = data["hashes"]

        print(f"\nRe-scanning '{dir_path}' (baseline from {data['created_at']})...")
        new_hashes = scan_directory(dir_path)

        modified, added, removed = compare(old_hashes, new_hashes)
        print_report(modified, added, removed)

    else:
        print("Invalid choice. Please enter 1 or 2.")


# This ensures main() only runs when the script is executed directly,
# not if it's imported as a module elsewhere.
if __name__ == "__main__":
    main()