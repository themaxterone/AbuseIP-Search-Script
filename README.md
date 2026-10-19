# AbuseIPDB Threat Intelligence Lookup (`ipsearcher.py`)

A comprehensive Python utility to inspect single IP addresses or process bulk IP lists against the **AbuseIPDB API v2**. It displays real-time progress, detailed metadata, and color-coded risk bars directly in the terminal, while automatically generating an interactive HTML dashboard with live searching and risk-based filtering.

---

## Table of Contents

1. [Features](#features)
2. [How It Works](#how-it-works)
3. [Prerequisites & Dependencies](#prerequisites--dependencies)
4. [Installation Guide](#installation-guide)
   - [Option 1: Using Anaconda (Recommended)](#option-1-using-anaconda-recommended)
   - [Option 2: Using Standard Python (CMD / PowerShell / macOS / Linux)](#option-2-using-standard-python-cmd--powershell--macos--linux)
5. [Configuration](#configuration)
6. [Workflow](#workflow)
7. [Usage & Execution](#usage--execution)
   - [1. Single IP Lookup (-i)](#1-single-ip-lookup--i)
   - [2. Bulk File Processing (-f)](#2-bulk-file-processing--f)
   - [3. Verbose Mode (-v)](#3-verbose-mode--v)
   - [Command-Line Arguments Reference](#command-line-arguments-reference)
8. [Generated HTML Dashboard](#generated-html-dashboard)
9. [Corporate Proxy & SSL Troubleshooting](#corporate-proxy--ssl-troubleshooting)

---

## Features

- **Single IP Inspection (`-i`)**: Checks geolocation, ISP, domain, 90-day report count, reported attack categories, and displays an ANSI color-coded confidence score bar in the terminal.
- **Bulk File Processing (`-f`)**: Automatically parses IPv4 addresses from text files, ignoring spaces, commas, newlines, and CIDR suffixes (such as `/32`), while removing duplicates.
- **Dual Output Modes**:
  - **Standard Progress Mode (Default)**: Clean, single-line dynamic progress bar displaying completion percentage without cluttering the screen.
  - **Verbose Mode (`-v`)**: Real-time per-IP breakdown in the terminal including geolocation, ISP, attack categories, and visual confidence meters.
- **Interactive HTML Dashboard**: Automatically exported during bulk processing, featuring summary statistics cards, instant search across all columns, and quick risk filters (*All / Malicious / Suspicious / Clean*).
- **Corporate Proxy & SSL Ready**: Includes native handling for corporate SSL interception and firewall inspection without throwing certificate validation errors.

---

## How It Works

1. **Extraction & Deduplication**: If executed with `-f`, a regular expression parses all valid IPv4 strings from the input file and strips out duplicate entries while preserving order.
2. **API Query Engine**: Sends HTTPS requests to the AbuseIPDB `/check` endpoint (`maxAgeInDays=90`, `verbose=true`).
3. **Attack Category Mapping**: Translates numerical category IDs returned by the API (e.g., SSH, Port Scan, Brute-Force) into standard human-readable descriptions.
4. **Scoring & Risk Assignment**:
   - **Malicious**: Abuse Confidence Score $\ge 60\%$ (Red).
   - **Suspicious**: Abuse Confidence Score between $20\%$ and $59\%$ (Yellow).
   - **Clean**: Abuse Confidence Score $< 20\%$ (Green).
5. **Report Generation**: Builds a self-contained, responsive `.html` report that requires no external CSS or JavaScript dependencies.

---

## Prerequisites & Dependencies

- Python 3.8+ (Standard Python or Anaconda/Miniconda)
- An active API key from [AbuseIPDB](https://www.abuseipdb.com/)
- Required Python packages:
  - `requests`
  - `urllib3`

---

## Installation Guide

### Option 1: Using Anaconda (Recommended)

1. Open **Anaconda Prompt**.
2. Install the necessary network package:
   ```bash
   conda install requests
   ```
   *(Confirm with `y` if prompted)*.

### Option 2: Using Standard Python (CMD / PowerShell / macOS / Linux)

1. Open your terminal.
2. Install dependencies using `pip`:
   ```bash
   pip install requests urllib3
   ```

---

## Configuration

1. Place `ipsearcher.py` in your working directory.
2. Open the file in an editor (VS Code, Notepad, Vim, etc.).
3. Locate the `API_KEY` configuration line near the top of the script and paste your AbuseIPDB key:
   ```python
   # ==========================================
   # PASTE YOUR ABUSEIPDB API KEY HERE
   API_KEY = "YOUR_ACTUAL_API_KEY_HERE"
   # ==========================================
   ```
4. Save the file.

---

## Workflow

```text
[Start Execution]
       │
       ▼
[Parse CLI Arguments: -i <IP> or -f <File>]
       │
       ├─────────────────────────────────┐
       ▼                                 ▼
 [-i Single IP]                   [-f File Mode]
       │                                 │
       │                          [Extract & Deduplicate IPv4s]
       │                                 │
       └───────────────┬─────────────────┘
                       ▼
         [Query AbuseIPDB API (/check)]
                       │
       ┌───────────────┴───────────────┐
       ▼                               ▼
 [Default Mode]                  [-v Verbose Mode]
 Inline % Progress Bar           Print Detailed IP Cards
       │                               │
       └───────────────┬───────────────┘
                       ▼
       [Render Terminal Summary Box]
                       │
       [Export Interactive HTML Dashboard]
                       │
                       ▼
                   [Complete]
```

---

## Usage & Execution

Navigate to your script folder:
```bash
cd "C:\Path\To\iplookup"
```

### 1. Single IP Lookup (-i)

Query an individual IP address and view its risk analysis directly in the terminal:

```bash
python ipsearcher.py -i 8.8.8.8
```

#### Terminal Output Example:
```text
=================================================================
 AbuseIPDB Lookup Result: 8.8.8.8
=================================================================
 Location     : US
 ISP          : Google LLC
 Domain       : google.com
 Total Reports: 0 (Last 90 days)
 Last Reported: Never

 Malicious Score (Abuse Confidence):
 [------------------------------] 0%

 Reported Attack Categories:
  - None (IP clean / No reports)
=================================================================
```

### 2. Bulk File Processing (-f)

Check a list of IP addresses stored in a text file. The file can contain addresses formatted in lines, spaces, commas, or CIDR notations like `/32`:

```text
144.31.34.104/32 144.31.34.109/32 2.27.98.43/32
93.88.206.223/32
2.20.49.149
```

Run the bulk check (displays the real-time progress bar and final summary box):

```bash
python ipsearcher.py -f ips.txt
```

#### Bulk Execution Progress & Summary:
```text
[+] Extracted 4 unique IP address(es) from 'ips.txt'.
[+] Starting queries against AbuseIPDB...

[+] Checking AbuseIPDB |██████████████████████████████| 100.0% (4/4)

=================================================================
 ABUSEIPDB BULK SUMMARY | TOTAL UNIQUE IPs: 4
=================================================================
 Total Checked : 4
 Malicious     : 1 (Score >= 60%)
 Suspicious    : 1 (Score 20-59%)
 Clean         : 2 (Score < 20%)
=================================================================

[+] Interactive HTML report saved to: abuseipdb_ips_20261019_153022.html
```

### 3. Verbose Mode (-v)

Enable full real-time terminal output for each evaluated IP in bulk mode:

```bash
python ipsearcher.py -f ips.txt -v
```

### Command-Line Arguments Reference

| Argument | Type | Default | Required | Description |
| :--- | :--- | :--- | :--- | :--- |
| `-i`, `--ip` | String | *None* | Mutually Exclusive | Target IPv4 address to inspect individually. |
| `-f`, `--file` | String | *None* | Mutually Exclusive | Path to a text file containing target IP addresses to check in bulk. |
| `-v`, `--verbose` | Flag | `False` | No | Enables detailed per-IP output cards in the terminal. |

---

## Generated HTML Dashboard

When running in bulk mode (`-f`), the script generates a timestamped report named `abuseipdb_<filename>_<timestamp>.html`. Double-click the file to open it in any web browser.

Key dashboard features include:
- **Summary Cards**: At-a-glance metrics showing total IPs, malicious count, suspicious count, and clean count.
- **Instant Search Box**: Real-time filtering across IP address, country, ISP, domain, and attack categories.
- **Risk Filter Buttons**: Filter rows instantly by risk classification (*All*, *Malicious*, *Suspicious*, *Clean*).
- **Color-Coded Confidence Meters**: Visual progress bars representing the Abuse Confidence Score for each entry.

---

## Corporate Proxy & SSL Troubleshooting

In corporate environments where firewalls or web proxies perform SSL/TLS decryption (deep packet inspection), standard Python requests calls can fail with:

```text
SSLError(SSLCertVerificationError: certificate verify failed: self-signed certificate in certificate chain)
```

The script natively handles this behavior by:
1. Disabling insecure request warnings:
   ```python
   import urllib3
   urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
   ```
2. Passing `verify=False` within API requests:
   ```python
   requests.get(url, headers=headers, params=params, timeout=15, verify=False)
   ```