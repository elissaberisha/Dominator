# scanner.py
import os
import json
import csv
import subprocess
import requests
import dns.resolver
from config import OUTPUT_FOLDER, VULNERABLE_FILE, VIRUSTOTAL_API_KEY, SHODAN_API_KEY, SECURITYTRAILS_API_KEY, WHOISXML_API_KEY, RED, GREEN
from utils import load_fingerprints

fingerprints = load_fingerprints()

def run_subfinder(domain):
    try:
        result = subprocess.run(["subfinder", "-d", domain, "-silent"], capture_output=True, text=True, timeout=120)
        if result.returncode != 0:
            print(f"[!] subfinder error: {result.stderr}")
            return []
        return [sd for sd in result.stdout.strip().split("\n") if sd]
    except Exception as e:
        print(f"[!] subfinder exception: {e}")
        return []

def resolve_cname(domain):
    try:
        answers = dns.resolver.resolve(domain, 'CNAME')
        for rdata in answers:
            return str(rdata.target).rstrip('.')  # Heq pikën fundore
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
        return None
    except Exception as e:
        print(f"[!] DNS error resolving CNAME for {domain}: {e}")
        return None

def resolve_a_record(domain):
    try:
        answers = dns.resolver.resolve(domain, 'A')
        for rdata in answers:
            return rdata.address
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
        return None
    except Exception as e:
        print(f"[!] DNS error resolving A record for {domain}: {e}")
        return None

def check_fingerprint(domain, cname):
    if not cname:
        return None
    for fp in fingerprints:
        provider = fp.get("provider", "")
        fps = fp.get("fingerprints", [])
        for pattern in fps:
            if pattern.lower() in cname.lower():
                return provider
    return None

def http_check(domain):
    try:
        r = requests.get(f"http://{domain}", timeout=5)
        body = r.text.lower()
        for fp in fingerprints:
            for kw in fp.get("keywords", []):
                if kw.lower() in body:
                    return fp.get("provider", "")
    except:
        pass
    return None

def virustotal_check(domain):
    try:
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        resp = requests.get(url, headers=headers, timeout=10)
        if resp.status_code == 200:
            stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
            mal, sus = stats.get("malicious", 0), stats.get("suspicious", 0)
            return f"Malicious: {mal}, Suspicious: {sus}" if (mal or sus) else "Clean"
        return f"VT Error: {resp.status_code}"
    except Exception as e:
        return f"VT Exception: {e}"

def shodan_check(ip):
    if not ip:
        return "No IP"
    try:
        url = f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_API_KEY}"
        resp = requests.get(url, timeout=10)
        if resp.status_code == 200:
            ports = resp.json().get("ports", [])
            return f"Ports: {ports}" if ports else "No open ports"
        elif resp.status_code == 404:
            return "No data on Shodan"
        return f"Shodan Error: {resp.status_code}"
    except Exception as e:
        return f"Shodan Exception: {e}"

def securitytrails_check(domain):
    try:
        headers = {"APIKEY": SECURITYTRAILS_API_KEY}
        url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
        resp = requests.get(url, headers=headers, timeout=10)
        if resp.status_code == 200:
            subs = resp.json().get("subdomains", [])
            return f"SecurityTrails found {len(subs)} subdomains"
        return f"SecurityTrails Error: {resp.status_code}"
    except Exception as e:
        return f"SecurityTrails Exception: {e}"

def whoisxml_lookup(domain):
    try:
        url = f"https://www.whoisxmlapi.com/whoisserver/WhoisService"
        params = {
            "apiKey": WHOISXML_API_KEY,
            "domainName": domain,
            "outputFormat": "JSON"
        }
        response = requests.get(url, params=params, timeout=10)
        if response.status_code == 200:
            data = response.json()
            created = data.get("WhoisRecord", {}).get("createdDate", "N/A")
            expires = data.get("WhoisRecord", {}).get("expiresDate", "N/A")
            registrar = data.get("WhoisRecord", {}).get("registrarName", "N/A")
            return f"Created: {created}, Expires: {expires}, Registrar: {registrar}"
        else:
            return f"WHOISXML Error: {response.status_code}"
    except Exception as e:
        return f"WHOISXML Exception: {e}"

def scan_domain(domain):
    cname = resolve_cname(domain)
    ip = resolve_a_record(domain)
    
    provider = check_fingerprint(domain, cname) or http_check(domain)
    potential = provider is not None and cname is not None

    if potential:
        with open(VULNERABLE_FILE, "a") as vf:
            vf.write(f"{domain} - {provider}\n")

    return {
        "domain": domain,
        "cname": cname or "-",
        "ip": ip or "-",
        "resolvable": bool(ip or cname),
        "provider": provider or "-",
        "potential_takeover": potential,
        "virustotal": virustotal_check(domain),
        "shodan": shodan_check(ip),
        "securitytrails": securitytrails_check(domain),
        "whoisxml": whoisxml_lookup(domain)
    }

def save_results(results, prefix):
    os.makedirs(OUTPUT_FOLDER, exist_ok=True)
    with open(f"{OUTPUT_FOLDER}/{prefix}.json", "w") as jf:
        json.dump(results, jf, indent=2)
    with open(f"{OUTPUT_FOLDER}/{prefix}.csv", "w", newline='', encoding="utf-8") as cf:
        writer = csv.DictWriter(cf, fieldnames=results[0].keys())
        writer.writeheader()
        for r in results:
            writer.writerow(r)