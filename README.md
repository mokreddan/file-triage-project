# File Triage & Hash Analysis

## Project Description
This is a Python cybersecurity project that analyses files using SHA-256 hashing. It helps identify known files, unknown files, and duplicate files.

## Features
- Calculates SHA-256 hashes.
- Displays filename, extension, size, and last modified date.
- Compares hashes with `hashes_reference.csv`.
- Classifies files as KNOWN or UNKNOWN.
- Detects duplicate files using matching hashes.
- Handles errors such as missing folders and unreadable files.
- Generates a CSV report called `triage_report.csv`.

## Requirements
- Python 3
- No additional Python packages required.

## How to Run
1. Download the project files from this repository.
2. Keep the sample files and `hashes_reference.csv` in the same folder as `file_triage.py`.
3. Open a terminal in the project folder.
4. Run:

   `python file_triage.py`

To analyse a different folder:

`python file_triage.py "C:\path\to\folder"`

## Expected Results
- 3 known files
- 2 unknown files
- 1 duplicate group containing `sample_a.txt` and `sample_b.txt`

## Cybersecurity Notes
SHA-256 helps identify identical file content and compare files with a known reference list. However, an UNKNOWN result does not automatically mean a file is malicious, and a KNOWN result does not guarantee a file is safe.

## Output
The program displays results in the terminal and saves them to `triage_report.csv`.
