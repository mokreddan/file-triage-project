
import hashlib
import csv
import argparse
from pathlib import Path
from datetime import datetime


# Calculate the SHA-256 hash of a file
def calculate_sha256(file_path):
    sha256 = hashlib.sha256()

    with open(file_path, "rb") as file:
        for chunk in iter(lambda: file.read(4096), b""):
            sha256.update(chunk)

    return sha256.hexdigest()


# Load known hashes from the reference CSV
def load_reference_hashes(csv_path):
    reference_hashes = {}

    try:
        with open(csv_path, "r", newline="", encoding="utf-8") as file:
            reader = csv.DictReader(file)

            if not reader.fieldnames or not {"sha256", "label"}.issubset(reader.fieldnames):
                raise ValueError("CSV must contain sha256 and label columns")

            for row in reader:
                file_hash = (row.get("sha256") or "").strip().lower()
                label = (row.get("label") or "").strip()

                if len(file_hash) != 64 or any(
                    c not in "0123456789abcdef" for c in file_hash
                ):
                    print("Warning: Skipping invalid reference hash")
                    continue

                reference_hashes[file_hash] = label

    except (OSError, ValueError, csv.Error) as error:
        print(f"Error loading reference CSV: {error}")

    return reference_hashes


# Detect duplicate files
def find_duplicates(file_hashes):
    hash_groups = {}
    duplicate_groups = []

    for filename, file_hash in file_hashes.items():
        hash_groups.setdefault(file_hash, []).append(filename)

    print("\n=== DUPLICATE FILE REPORT ===")

    for file_hash, filenames in hash_groups.items():
        if len(filenames) > 1:
            duplicate_groups.append(filenames)
            print(f"Duplicate files: {', '.join(filenames)}")
            print(f"SHA-256: {file_hash}")

    if not duplicate_groups:
        print("No duplicate files found.")

    return duplicate_groups


# Save analysis results to CSV
def generate_report(results, output_file):
    fieldnames = [
        "filename",
        "extension",
        "size_bytes",
        "last_modified",
        "sha256",
        "status",
        "label"
    ]

    try:
        with open(output_file, "w", newline="", encoding="utf-8") as file:
            writer = csv.DictWriter(file, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(results)

        print(f"\nCSV report saved: {output_file}")

    except OSError as error:
        print(f"Error saving CSV report: {error}")


# Main program
def main():
    parser = argparse.ArgumentParser(
        description="Safe File Triage and SHA-256 Analysis"
    )

    parser.add_argument(
        "folder",
        nargs="?",
        default=str(Path(__file__).resolve().parent),
        help="Folder containing safe files to analyse"
    )

    args = parser.parse_args()

    project_folder = Path(__file__).resolve().parent
    target_folder = Path(args.folder)

    if not target_folder.is_dir():
        print("Error: The selected folder does not exist.")
        return

    reference_file = project_folder / "hashes_reference.csv"
    reference_hashes = load_reference_hashes(reference_file)

    file_hashes = {}
    results = []

    print("=== FILE TRIAGE & HASH ANALYSIS ===\n")

    try:
        sample_files = sorted(
            path for path in target_folder.iterdir()
            if path.is_file()
            and path.suffix.lower() in (".txt", ".bin")
            and path.name.lower() != "readme.txt"
        )
    except OSError as error:
        print(f"Error reading folder: {error}")
        return

    if not sample_files:
        print("No supported sample files found.")

    for file_path in sample_files:
        try:
            file_hash = calculate_sha256(file_path)

            file_info = file_path.stat()

            modified = datetime.fromtimestamp(
                file_info.st_mtime
            ).strftime("%Y-%m-%d %H:%M:%S")

            if file_hash in reference_hashes:
                status = "KNOWN"
                label = reference_hashes[file_hash]
            else:
                status = "UNKNOWN"
                label = "No reference match"

            file_hashes[file_path.name] = file_hash

            print(f"File: {file_path.name}")
            print(f"Extension: {file_path.suffix}")
            print(f"Size: {file_info.st_size} bytes")
            print(f"Last Modified: {modified}")
            print(f"SHA-256: {file_hash}")
            print(f"Status: {status}")
            print(f"Label: {label}")
            print("-" * 50)

            results.append({
                "filename": file_path.name,
                "extension": file_path.suffix,
                "size_bytes": file_info.st_size,
                "last_modified": modified,
                "sha256": file_hash,
                "status": status,
                "label": label
            })

        except OSError as error:
            print(f"Error processing {file_path.name}: {error}")

    find_duplicates(file_hashes)

    generate_report(
        results,
        project_folder / "triage_report.csv"
    )


if __name__ == "__main__":
    main()
