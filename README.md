# nichash v2.5.1

nichash is a command-line tool designed for generating hash values for files. It’s a quick and efficient solution for checking file integrity and verifying that files remain unchanged. With support for Linux, nichash provides an easy-to-use hashing solution.

## Features
#### Hash Generation: Securely generates file hashes using various algorithms, including:
- SHA256, SHA512, SHA1, MD5, and SHA3-256 for flexible security and compatibility.
#### Batch Hashing: Process multiple files recursively in a folder, making it easy to hash entire directories at once.
#### Customizable Output Formats: Save hash results in your preferred format:
- TXT: Human-readable text format.
- CSV: Structured tabular format for data analysis.
- JSON: Ideal for integration with other tools or applications.
#### Verification Mode: Check file integrity by comparing calculated hashes against expected values.
#### User-Friendly CLI:
- Minimal arguments required for quick hash generation.
- Displays clear messages for errors, process updates, and results.

## Different than Others
- Supports SHA3-256 Algorithm: Offering cutting-edge hashing technology beyond standard algorithms.
- Batch File Hashing: Process multiple files in a folder effortlessly.
- Flexible Output Formats: Save results in TXT, CSV, or JSON formats to suit your needs.

## Installation
Download the appropriate binary for your Linux AMD64 operating system from the [Releases](https://github.com/ferizco/Nichash/releases) page.

### For Linux
1. Download `nichash` from the latest release. (you can use wget)
2. Then unzip the file. 
3. Make the installer executable:
   ```bash
   chmod +x nichash-installer.sh
4. Run the installer:
   ```bash
   ./nichash-installer.sh
5. Check help options for use:
   ```bash
   nichash -help

## Usage 
Basic Usage
 ```bash
nichash -file <file_path> -hash <algorithm> 
nichash -dir <directory_path> -hash <algorithm>
```
With the output (TXT, CSV, JSON) 
 ```bash
nichash -file <file_path> -hash <algorithm> -o <filename.format>
nichash -dir <directory_path> -hash <algorithm> -o <filename.format>
```
Check the integrity
```bash
nichash -file <file_path> -hash <algorithm> -verify <expected_hash>
```
