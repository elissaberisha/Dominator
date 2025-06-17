# utils.py
import os
import re
import json
import argparse
import requests
from config import RED, GREEN, CYAN, RESET

def print_banner():
    print(fr"""{CYAN}
  _____   ____  __  __ _____ _   _       _______ ____  _____  
 |  __ \ / __ \|  \/  |_   _| \ | |   /\|__   __/ __ \|  __ \ 
 | |  | | |  | | \  / | | | |  \| |  /  \  | | | |  | | |__) |
 | |  | | |  | | |\/| | | | | . ` | / /\ \ | | | |  | |  _  / 
 | |__| | |__| | |  | |_| |_| |\  |/ ____ \| | | |__| | | \ \ 
 |_____/ \____/|_|  |_|_____|_| \_/_/    \_\_|  \____/|_|  \_|
{RESET}
{GREEN}Welcome to DOMINATOR - Subdomain Takeover Monitoring Tool{RESET}
""")

def parse_interval(interval_str):
    pattern = re.compile(r"^(?:(\d+)h)?(?:(\d+)m)?(?:(\d+)s)?$")
    match = pattern.fullmatch(interval_str.strip())
    if not match:
        raise argparse.ArgumentTypeError("Format must be like 24h, 30m, 15s or 1h30m")
    h = int(match.group(1) or 0)
    m = int(match.group(2) or 0)
    s = int(match.group(3) or 0)
    total = h * 3600 + m * 60 + s
    if total == 0:
        raise argparse.ArgumentTypeError("Interval cannot be zero")
    return total

def load_fingerprints(filepath="fingerprints.json"):
    if not os.path.isfile(filepath):
        print(f"{RED}[!] Fingerprints file not found: {filepath}{RESET}")
        return []
    with open(filepath, "r") as f:
        return json.load(f)

def send_discord_alert(message, webhook_url):
    data = {"content": message}
    resp = requests.post(webhook_url, json=data)
    if resp.status_code != 204:
        print(f"Discord webhook error: {resp.status_code} - {resp.text}")
    else:
        print(f"{GREEN}Alert sent to Discord successfully!{RESET}")
