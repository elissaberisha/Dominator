# main.py
import argparse
import os
import sys
import time
from datetime import datetime

from config import RED, GREEN, YELLOW, RESET, WEBHOOK_URL
from scanner import run_subfinder, scan_domain, save_results
from utils import print_banner, parse_interval, send_discord_alert

def monitor_loop(domain, prefix, webhook_url=None):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    print(f"{YELLOW}[{timestamp}] Scanning: {domain}{RESET}")
    subdomains = run_subfinder(domain)
    print(f"{GREEN}Subdomains found: {len(subdomains)}{RESET}")

    results = []
    takeover_subdomains = []

    for sub in subdomains:
        print(f"→ {sub}")
        res = scan_domain(sub)

        if res.get("potential_takeover"):
            print(f"{GREEN}✅ {sub} - Potential Takeover{RESET}")
            takeover_subdomains.append(sub)
        else:
            print(f"{RED}❌ {sub} - No Takeover{RESET}")

        results.append(res)

    if takeover_subdomains and webhook_url:
        message = "🚨 ALERT: Potential Subdomain Takeover on:\n" + "\n".join(takeover_subdomains)
        send_discord_alert(message, webhook_url)

    output_name = f"{prefix}_{timestamp}"
    save_results(results, output_name)
    print(f"{GREEN}Results saved to {output_name}.json and .csv{RESET}")

def main():
    print_banner()
    parser = argparse.ArgumentParser(description="DOMINATOR - Subdomain Takeover Scanner")
    parser.add_argument("--domain", help="Single domain to scan")
    parser.add_argument("--list", help="File with list of domains")
    parser.add_argument("--output", "-o", default="dominator_results", help="Output file prefix")
    parser.add_argument("--interval", "-i", type=parse_interval, default=0, help="Monitor interval (e.g. 24h, 30m)")
    args = parser.parse_args()

    domains = []
    if args.domain:
        domains.append(args.domain)
    if args.list:
        if not os.path.isfile(args.list):
            print(f"{RED}[!] Domain list file not found: {args.list}{RESET}")
            sys.exit(1)
        with open(args.list, 'r') as f:
            domains.extend([line.strip() for line in f if line.strip()])

    if not domains:
        print(f"{RED}[!] No domain provided. Use --domain or --list{RESET}")
        sys.exit(1)

    try:
        while True:
            for dom in domains:
                monitor_loop(dom, f"{args.output}_{dom.replace('.', '_')}", WEBHOOK_URL)
            if args.interval <= 0:
                break
            print(f"{YELLOW}Sleeping {args.interval} seconds...{RESET}")
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print(f"\n{RED}[!] Interrupted by user. Exiting...{RESET}")
        sys.exit(0)

if __name__ == "__main__":
    main()
