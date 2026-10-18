# AbuseIPDB Threat Intelligence Lookup (`ipsearcher.py`)

A comprehensive Python utility to inspect single IP addresses or process bulk IP lists against the **AbuseIPDB API v2**. It displays detailed information and color-coded risk bars directly in the terminal and automatically generates an interactive HTML dashboard with client-side searching and risk-based filtering.

---

## Table of Contents

1. [Features](#features)
2. [How It Works](#how-it-works)
3. [Prerequisites & Dependencies](#prerequisites--dependencies)
4. [Installation Guide](#installation-guide)
5. [Usage & Execution](#usage--execution)
6. [Execution Workflow & Outputs](#execution-workflow--outputs)
---

## Features

- **Single IP Lookup (`-i`)**: Checks geolocation, ISP, domain, 90-day report count, reported attack categories, and displays an ANSI color-coded confidence score bar in the terminal.
- **Bulk File Processing (`-f`)**: Extracts IPv4 addresses from text files (supports newlines, commas, spaces, or CIDR notation like `/32`), showing live terminal output for each entry.
- **Interactive HTML Dashboard**: When processing a file, automatically generates an HTML report featuring real-time search, quick filters (*All / Malicious / Suspicious / Clean*), progress bars, and risk badges.
- **Corporate Proxy & SSL Ready**: Built-in support to bypass SSL verification failures caused by corporate inspection firewalls and proxies.

---

## How It Works

1. **Query Engine**: Connects via HTTPS to the official AbuseIPDB endpoint (`https://api.abuseipdb.com/api/v2/check`) using your private API key.
2. **Category Normalization**: Parses numerical attack category IDs returned by the API (e.g., SSH, Port Scan, Brute-Force, Bad Web Bot) and translates them into human-readable labels.
3. **Regex Extraction**: When given a text file, a regular expression extracts valid IPv4 addresses and discards duplicates while preserving order.
4. **Interactive Dashboard**: The generated `.html` file is completely standalone (no external CSS/JS frameworks required) and can be opened in any web browser.

---

## Prerequisites & Dependencies

- Python 3.8+ (or Anaconda / Miniconda)
- An active API key from [AbuseIPDB](https://www.abuseipdb.com/)
- Required Python libraries:
  - `requests`
  - `urllib3`

---

## Installation Guide

### Using Anaconda (Recommended)

1. Open **Anaconda Prompt** from the Windows Start menu.
2. Install the necessary package:
```
conda install requests urllib3
pip install requests urllib3
```
3. Remember to change the API KEY in the script file.

```
# ==========================================
# PASTE YOUR ABUSEIPDB API KEY HERE
API_KEY = "YOUR_API_KEY_HERE"
# ==========================================
``` 

---
   
## Usage & Execution

### 1. Single IP Inspection (-i)

```
python ipsearcher.py -i 8.8.8.8
```

Output:
```
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

### 2. Bulk File Inspection (-f)

Prepare a text file (e.g., ips.txt) with target IP addresses. Lines, spaces, commas, or CIDR suffixes (/32) are supported:

```
144.31.34.104/32 144.31.34.109/32 2.27.98.43/32
93.88.206.223/32
2.20.49.149
```

```
python ipsearcher.py -f ips.txt
```

---

## Execution Workflow & Outputs

Valid IPv4 addresses are extracted and deduplicated.

The script queries AbuseIPDB sequentially, displaying the live score bar for each IP in the terminal.

Once completed, it generates an interactive file named abuseipdb_ips_<timestamp>.html.

Double-click the .html file to view the dashboard in Google Chrome, Microsoft Edge, or Firefox.
