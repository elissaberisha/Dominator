# main.py
import argparse
import os
import sys
import time
from datetime import datetime
from config import RED, GREEN, RESET, WEBHOOK_URL, CYAN
from scanner import run_subfinder, scan_domain, save_results
from utils import print_banner, parse_interval, send_discord_alert

class SingleLineHelpFormatter(argparse.HelpFormatter):
    def __init__(self, *args, **kwargs):
        kwargs['max_help_position'] = 32 
        kwargs['width'] = 100             
        super().__init__(*args, **kwargs)

    def _format_usage(self, usage, actions, groups, prefix):
        if prefix is None:
            prefix = 'usage: '
        return f"{CYAN}{super()._format_usage(usage, actions, groups, prefix)}{RESET}"

    def start_section(self, heading):
        heading = f"{heading}{RESET}"
        return super().start_section(heading)

    def _get_help_string(self, action):
        help_text = action.help or ''
        if (action.default is not argparse.SUPPRESS and
            action.default is not None and action.option_strings and action.default != 0):
            help_text += f" (default: {action.default})"
        return help_text  

def monitor_loop(domain, prefix, webhook_url=None):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    print(f"{CYAN}[{timestamp}] Scanning: {domain}{RESET}")
    subdomains = run_subfinder(domain)
    print(f"{CYAN}Subdomains found: {len(subdomains)}{RESET}")
    results = []
    takeover_subdomains = []

    for sub in subdomains:
        print(f"→ {sub}")
        res = scan_domain(sub)
        if res.get("potential_takeover"):
            print(f"{sub} - {RED}Potential Takeover{RESET}")
            takeover_subdomains.append(sub)
        else:
            print(f"{sub} - {GREEN}No Takeover{RESET}")
        results.append(res)

    if takeover_subdomains and webhook_url:
        message = "🚨 ALERT: Potential Subdomain Takeover on:\n" + "\n".join(takeover_subdomains)
        send_discord_alert(message, webhook_url)

    output_name = f"{prefix}_{timestamp}"
    
    if len(results) == 0:
        print(f"{CYAN}[Warning] No results for {output_name}.{RESET}")
    else:
        save_results(results, output_name)
        print(f"{CYAN}Results saved to {output_name}.json and .csv{RESET}")

def main():
    print_banner()
    parser = argparse.ArgumentParser(
       
        formatter_class=SingleLineHelpFormatter,
        usage=f"main.py [-h] [--domain DOMAIN] [--list LIST] [--output OUTPUT] [--interval INTERVAL]"
    )
    parser.add_argument("--domain", metavar="DOMAIN", help="Single domain to scan")
    parser.add_argument("--list", metavar="LIST", help="File with list of domains")
    parser.add_argument("--output", "-o", metavar="OUTPUT", default="dominator_results", help="Output file prefix")
    parser.add_argument("--interval", "-i", metavar="INTERVAL", type=parse_interval, default=0, help="Monitor interval (e.g. 24h, 30m, 120s)")
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
        print(f"{CYAN}[!] No domain provided. Use --domain or --list{RESET}")
        sys.exit(1)

    try:
        while True:
            for dom in domains:
                monitor_loop(dom, f"{args.output}_{dom.replace('.', '_')}", WEBHOOK_URL)
            if args.interval <= 0:
                break
            print(f"{CYAN}Sleeping {args.interval} seconds...{RESET}")
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print(f"\n{RED}[!] Interrupted by user. Exiting...{RESET}")
        sys.exit(0)

if __name__ == "__main__":
    main()
