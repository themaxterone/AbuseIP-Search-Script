import argparse
from datetime import datetime
import html
import os
import re
import sys
import time
import requests
import urllib3

# Suppress insecure SSL warnings caused by corporate proxy inspection
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ==========================================
# PASTE YOUR ABUSEIPDB API KEY HERE
API_KEY = "YOUR_API_KEY_HERE"
# ==========================================

# Official AbuseIPDB category mappings
CATEGORIES = {
    3: "Fraud Orders", 4: "DDoS Attack", 9: "Open Proxy", 10: "Web Spam",
    11: "Email Spam", 14: "Port Scan", 15: "Hacking", 18: "Brute-Force",
    19: "Bad Web Bot", 20: "Exploited Host", 21: "Web App Attack",
    22: "SSH", 23: "IoT Targeted"
}

def print_progress(iteration, total, prefix="Progress", length=30):
    """Renders a dynamic percentage progress bar on a single line."""
    percent = ("{0:.1f}").format(100 * (iteration / float(total)))
    filled_length = int(length * iteration // total)
    bar = "█" * filled_length + "-" * (length - filled_length)
    sys.stdout.write(f"\r{prefix} |{bar}| {percent}% ({iteration}/{total})")
    sys.stdout.flush()
    if iteration == total:
        sys.stdout.write("\n")

def create_progress_bar(score, length=30):
    """Generates an ANSI color-coded visual progress bar for terminal output."""
    filled_length = int(length * score // 100)
    bar = '█' * filled_length + '-' * (length - filled_length)
    
    if score < 20:
        color = '\033[92m'  # Green
    elif score < 60:
        color = '\033[93m'  # Yellow
    else:
        color = '\033[91m'  # Red
    reset = '\033[0m'
    
    return f"{color}[{bar}] {score}%{reset}"

def query_abuseipdb(ip, api_key):
    """Queries AbuseIPDB v2 endpoint for a single IP address."""
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Accept": "application/json",
        "Key": api_key
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": "90",
        "verbose": "true"
    }

    try:
        response = requests.get(url, headers=headers, params=params, timeout=15, verify=False)
        if response.status_code == 401:
            print("\n\033[91m[!] Error: Invalid AbuseIPDB API key.\033[0m")
            sys.exit(1)
        elif response.status_code == 429:
            print("\n\033[91m[!] Rate limit reached for AbuseIPDB API (HTTP 429).\033[0m")
            return None
        response.raise_for_status()
        data = response.json().get("data", {})
    except requests.exceptions.RequestException as e:
        print(f"\n\033[91m[!] Connection error while checking {ip}: {e}\033[0m")
        return None

    reported_categories = set()
    for report in data.get("reports", []):
        for cat in report.get("categories", []):
            reported_categories.add(cat)

    cat_names = [CATEGORIES.get(c, f"Unknown (ID: {c})") for c in reported_categories]

    return {
        "ip": ip,
        "country": data.get("countryCode") or "N/A",
        "isp": data.get("isp") or "N/A",
        "domain": data.get("domain") or "N/A",
        "score": data.get("abuseConfidenceScore", 0),
        "reports": data.get("totalReports", 0),
        "categories": sorted(cat_names),
        "last_reported": data.get("lastReportedAt") or "Never"
    }

def print_result_terminal(result):
    """Outputs the IP lookup details to the terminal."""
    if not result:
        return
    
    ip = result["ip"]
    score = result["score"]
    
    print("\n" + "=" * 65)
    print(f" AbuseIPDB Lookup Result: \033[1m{ip}\033[0m")
    print("=" * 65)
    print(f" Location     : {result['country']}")
    print(f" ISP          : {result['isp']}")
    print(f" Domain       : {result['domain']}")
    print(f" Total Reports: {result['reports']} (Last 90 days)")
    print(f" Last Reported: {result['last_reported']}")
    print("\n Malicious Score (Abuse Confidence):")
    print(f" {create_progress_bar(score)}")
    print("\n Reported Attack Categories:")
    if result["categories"]:
        for cat in result["categories"]:
            print(f"  - \033[93m{cat}\033[0m")
    else:
        print("  - \033[92mNone (IP clean / No reports)\033[0m")
    print("=" * 65 + "\n")

def export_html_report(filename, results):
    """Generates a modern, interactive dashboard in HTML format."""
    total_ips = len(results)
    malicious_count = sum(1 for r in results if r and r["score"] >= 60)
    suspicious_count = sum(1 for r in results if r and 20 <= r["score"] < 60)
    clean_count = sum(1 for r in results if r and r["score"] < 20)

    rows_html = []
    for r in results:
        if not r:
            continue
        
        score = r["score"]
        if score >= 60:
            badge_class = "badge-danger"
            risk_label = "Malicious"
            bar_color = "#dc2626"
        elif score >= 20:
            badge_class = "badge-warning"
            risk_label = "Suspicious"
            bar_color = "#d97706"
        else:
            badge_class = "badge-success"
            risk_label = "Clean"
            bar_color = "#16a34a"

        if r["categories"]:
            cats_badges = "".join([f'<span class="category-tag">{html.escape(c)}</span>' for c in r["categories"]])
        else:
            cats_badges = '<span class="text-muted">None</span>'

        rows_html.append(f"""
        <tr data-risk="{risk_label}">
            <td class="font-mono"><strong>{html.escape(r['ip'])}</strong></td>
            <td><span class="badge {badge_class}">{risk_label}</span></td>
            <td>
                <div class="score-container">
                    <span class="score-val">{score}%</span>
                    <div class="progress-bar-bg">
                        <div class="progress-bar-fill" style="width: {score}%; background-color: {bar_color};"></div>
                    </div>
                </div>
            </td>
            <td>{html.escape(r['country'])}</td>
            <td>{html.escape(r['isp'])}</td>
            <td>{html.escape(r['domain'])}</td>
            <td class="font-mono">{r['reports']}</td>
            <td>{cats_badges}</td>
        </tr>
        """)

    template = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AbuseIPDB Threat Intelligence Report</title>
    <style>
        :root {{
            --bg-primary: #f8fafc;
            --surface: #ffffff;
            --text-main: #0f172a;
            --text-muted: #64748b;
            --border-color: #e2e8f0;
            --primary: #2563eb;
            --success: #16a34a;
            --success-bg: #dcfce7;
            --warning: #d97706;
            --warning-bg: #fef3c7;
            --danger: #dc2626;
            --danger-bg: #fee2e2;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg-primary);
            color: var(--text-main);
            padding: 24px;
        }}
        .header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 16px;
            margin-bottom: 24px;
        }}
        .header h1 {{ font-size: 1.5rem; font-weight: 700; }}
        .header p {{ color: var(--text-muted); font-size: 0.85rem; }}
        .stats {{
            display: flex;
            gap: 12px;
            flex-wrap: wrap;
        }}
        .stat-card {{
            background: var(--surface);
            padding: 10px 18px;
            border-radius: 8px;
            border: 1px solid var(--border-color);
            display: flex;
            flex-direction: column;
            align-items: center;
            min-width: 90px;
        }}
        .stat-card .num {{ font-size: 1.25rem; font-weight: 700; }}
        .stat-card .label {{ font-size: 0.75rem; color: var(--text-muted); text-transform: uppercase; }}
        .controls {{
            display: flex;
            gap: 12px;
            margin-bottom: 16px;
            flex-wrap: wrap;
        }}
        .search-box {{
            flex: 1;
            min-width: 250px;
            padding: 10px 14px;
            border: 1px solid var(--border-color);
            border-radius: 6px;
            font-size: 0.9rem;
            outline: none;
        }}
        .search-box:focus {{ border-color: var(--primary); }}
        .filter-btn {{
            background: var(--surface);
            border: 1px solid var(--border-color);
            padding: 8px 14px;
            border-radius: 6px;
            cursor: pointer;
            font-size: 0.85rem;
            font-weight: 600;
        }}
        .filter-btn.active {{
            background: var(--primary);
            color: white;
            border-color: var(--primary);
        }}
        .table-container {{
            background: var(--surface);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            overflow: auto;
            max-height: 75vh;
            box-shadow: 0 1px 3px rgba(0,0,0,0.05);
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            text-align: left;
            font-size: 0.85rem;
        }}
        thead {{
            position: sticky;
            top: 0;
            background: #f1f5f9;
            z-index: 10;
        }}
        th {{
            padding: 12px 14px;
            font-weight: 600;
            color: #334155;
            border-bottom: 2px solid var(--border-color);
            white-space: nowrap;
        }}
        td {{
            padding: 12px 14px;
            border-bottom: 1px solid var(--border-color);
            vertical-align: middle;
        }}
        tr:hover {{ background-color: #f8fafc; }}
        .font-mono {{ font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; }}
        .text-muted {{ color: var(--text-muted); font-size: 0.8rem; }}
        .badge {{
            display: inline-block;
            padding: 4px 10px;
            border-radius: 12px;
            font-weight: 600;
            font-size: 0.75rem;
            text-align: center;
        }}
        .badge-success {{ background-color: var(--success-bg); color: var(--success); }}
        .badge-warning {{ background-color: var(--warning-bg); color: var(--warning); }}
        .badge-danger {{ background-color: var(--danger-bg); color: var(--danger); }}
        .score-container {{
            display: flex;
            align-items: center;
            gap: 8px;
            min-width: 140px;
        }}
        .score-val {{ font-weight: 700; font-size: 0.8rem; width: 35px; }}
        .progress-bar-bg {{
            flex: 1;
            height: 8px;
            background-color: #e2e8f0;
            border-radius: 4px;
            overflow: hidden;
        }}
        .progress-bar-fill {{
            height: 100%;
            border-radius: 4px;
        }}
        .category-tag {{
            display: inline-block;
            background-color: #f1f5f9;
            color: #475569;
            padding: 2px 7px;
            border-radius: 4px;
            font-size: 0.75rem;
            margin: 2px;
            border: 1px solid #cbd5e1;
        }}
    </style>
</head>
<body>
    <div class="header">
        <div>
            <h1>AbuseIPDB Threat Intelligence Report</h1>
            <p>Generated on: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
        </div>
        <div class="stats">
            <div class="stat-card">
                <span class="num">{total_ips}</span>
                <span class="label">Total IPs</span>
            </div>
            <div class="stat-card">
                <span class="num" style="color: var(--danger);">{malicious_count}</span>
                <span class="label">Malicious</span>
            </div>
            <div class="stat-card">
                <span class="num" style="color: var(--warning);">{suspicious_count}</span>
                <span class="label">Suspicious</span>
            </div>
            <div class="stat-card">
                <span class="num" style="color: var(--success);">{clean_count}</span>
                <span class="label">Clean</span>
            </div>
        </div>
    </div>

    <div class="controls">
        <input type="text" id="searchInput" class="search-box" placeholder="Search by IP, country, ISP, domain, attack type...">
        <button class="filter-btn active" onclick="filterRisk('all', this)">All</button>
        <button class="filter-btn" onclick="filterRisk('Malicious', this)">Malicious</button>
        <button class="filter-btn" onclick="filterRisk('Suspicious', this)">Suspicious</button>
        <button class="filter-btn" onclick="filterRisk('Clean', this)">Clean</button>
    </div>

    <div class="table-container">
        <table id="ipTable">
            <thead>
                <tr>
                    <th>IP Address</th>
                    <th>Risk Level</th>
                    <th>Confidence Score</th>
                    <th>Country</th>
                    <th>ISP</th>
                    <th>Domain</th>
                    <th>Reports</th>
                    <th>Attack Categories</th>
                </tr>
            </thead>
            <tbody>
                {''.join(rows_html)}
            </tbody>
        </table>
    </div>

    <script>
        const searchInput = document.getElementById('searchInput');
        const rows = document.querySelectorAll('#ipTable tbody tr');
        let currentFilter = 'all';

        function applyFilters() {{
            const query = searchInput.value.toLowerCase();
            rows.forEach(row => {{
                const matchSearch = row.innerText.toLowerCase().includes(query);
                const rowRisk = row.getAttribute('data-risk');
                const matchRisk = (currentFilter === 'all') || (rowRisk === currentFilter);
                row.style.display = (matchSearch && matchRisk) ? '' : 'none';
            }});
        }}

        searchInput.addEventListener('input', applyFilters);

        function filterRisk(risk, btn) {{
            currentFilter = risk;
            document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            applyFilters();
        }}
    </script>
</body>
</html>
"""
    try:
        with open(filename, mode="w", encoding="utf-8") as f:
            f.write(template)
        print(f"\n\033[92m[+] Interactive HTML report saved to:\033[0m \033[1m{filename}\033[0m")
    except Exception as e:
        print(f"\033[91m[!] Error saving HTML report: {e}\033[0m")

def extract_ips_from_file(file_path):
    """Reads a text file and extracts IPv4 addresses (handles /32, commas, spaces, newlines)."""
    if not os.path.isfile(file_path):
        print(f"\033[91m[!] Error: File '{file_path}' not found.\033[0m")
        sys.exit(1)

    ip_regex = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    ips = []
    
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            matches = ip_regex.findall(line)
            ips.extend(matches)

    seen = set()
    unique_ips = [ip for ip in ips if not (ip in seen or seen.add(ip))]
    return unique_ips

def main():
    parser = argparse.ArgumentParser(description="Check IP reputation against AbuseIPDB and export interactive reports.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-i", "--ip", help="Single target IP address to query")
    group.add_argument("-f", "--file", help="Path to text file containing IP addresses to query in bulk")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose terminal output (show detailed IP breakdown)")
    args = parser.parse_args()

    if API_KEY == "YOUR_API_KEY_HERE":
        print("\033[91m[!] Error: Please configure your 'API_KEY' inside the script.\033[0m")
        sys.exit(1)

    # 1. Single IP Lookup
    if args.ip:
        res = query_abuseipdb(args.ip.strip(), API_KEY)
        print_result_terminal(res)

    # 2. Bulk File Lookup
    elif args.file:
        ips = extract_ips_from_file(args.file)
        if not ips:
            print(f"\033[93m[!] No valid IPv4 addresses found in '{args.file}'.\033[0m")
            sys.exit(0)

        total_ips = len(ips)
        print(f"\n[+] Extracted {total_ips} unique IP address(es) from '{args.file}'.")
        print("[+] Starting queries against AbuseIPDB...\n")

        results = []
        for idx, ip in enumerate(ips, start=1):
            if not args.verbose:
                print_progress(idx, total_ips, prefix="[+] Checking AbuseIPDB")
            else:
                print(f"[{idx}/{total_ips}] Checking IP: {ip}...")

            res = query_abuseipdb(ip, API_KEY)
            if res:
                results.append(res)
                if args.verbose:
                    print_result_terminal(res)

            time.sleep(0.3)

        # Print final statistical summary
        malicious = sum(1 for r in results if r["score"] >= 60)
        suspicious = sum(1 for r in results if 20 <= r["score"] < 60)
        clean = sum(1 for r in results if r["score"] < 20)

        print("\n" + "=" * 65)
        print(f" ABUSEIPDB BULK SUMMARY | TOTAL UNIQUE IPs: {total_ips}")
        print("=" * 65)
        print(f" Total Checked : {len(results)}")
        print(f" Malicious     : \033[91m{malicious}\033[0m (Score >= 60%)")
        print(f" Suspicious    : \033[93m{suspicious}\033[0m (Score 20-59%)")
        print(f" Clean         : \033[92m{clean}\033[0m (Score < 20%)")
        print("=" * 65)

        # Generate HTML report
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_name = os.path.splitext(os.path.basename(args.file))[0]
        html_file = f"abuseipdb_{base_name}_{timestamp}.html"
        
        export_html_report(html_file, results)

if __name__ == "__main__":
    main()