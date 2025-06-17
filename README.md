# Dominator

**Dominator** is a security automation tool designed to detect and monitor subdomain takeover vulnerabilities. It continuously scans target domains for subdomains, resolves their CNAME records, analyzes HTTP responses, and matches them against known fingerprints of misconfigured cloud services. The tool can send real-time alerts via Discord Webhooks and save comprehensive reports in JSON and CSV formats.

---

## Description

Dominator aims to:

- Provide a reliable and user-friendly CLI tool for subdomain takeover detection.
- Support scanning of single or multiple domains.
- Continuously monitor target domains with configurable scan intervals.
- Export scan results to `.json` and `.csv` formats for analysis and reporting.
- Detect DNS misconfigurations and fingerprint known vulnerable cloud providers.
- Integrate multiple APIs for enriched data and verification (VirusTotal, Shodan, SecurityTrails, WhoisXML).

---

## Project Structure

```plaintext
/dominator
│
├── main.py               # Entry point of the program, handles CLI commands and main logic
├── scanner.py            # Core scanning logic for subdomains and takeover detection
├── config.py             # Global configuration and environment variables (API keys, paths)
├── utils.py              # Helper functions (HTTP requests, DNS resolution, etc.)
├── fingerprints.json     # Fingerprint database for detecting cloud providers
├── list.txt              # Input file with list of target domains
├── .env                  # Stores environment variables and API keys (not committed)
├── .gitignore            # Prevents sensitive files like .env from being tracked by Git
├── requirements.txt      # Python dependencies for the project
└── output/               # Directory where JSON and CSV scan results are saved
```

## Features

-  Subdomain enumeration using **Subfinder**
-  CNAME resolution to detect delegations to external services
-  Fingerprint matching using `fingerprints.json`
-  HTTP body analysis for takeover clues
-  VirusTotal API integration to check domain/IP reputation
-  Shodan API integration to retrieve IP-related data
-  **SecurityTrails API** for DNS and domain history analysis
-  **WhoisXML API** for WHOIS and DNS record enrichment
-  Exporting results to `.json` and `.csv`
-  Discord webhook notifications for real-time alerts
-  Continuous monitoring mode with customizable interval

## Technologies Used

- **Python** 3.13.1
- **Subfinder** for enumeration
- **APIs**: VirusTotal, Shodan, SecurityTrails, WhoisXML
- **JSON/CSV** standard libraries
- **Discord Webhooks** for alerting

## Security Notes

- API keys are stored in a `.env` file and loaded using `dotenv`.
- The `.env` file is **excluded** from Git via `.gitignore`.
- Never upload your `.env` file or API keys to GitHub.

## Getting Started

1. Clone the repository:
   ```bash
   git clone https://github.com/elissaberisha/dominator.git
   cd dominator
   ```

2. Install required Python packages:
   ```bash
   pip install -r requirements.txt
   ```

3. Create a `.env` file and add your API keys:
   ```env
   VIRUSTOTAL_API_KEY=...
   SHODAN_API_KEY=...
   SECURITYTRAILS_API_KEY=...
   WHOISXML_API_KEY=...
   WEBHOOK_URL=...
   ```

4. Run the tool (example):
   ```bash
   python main.py --list list.txt -o results -i 24h
   ```

### External Tools

- `subfinder`: Required for subdomain enumeration  
  **Note:** Make sure you have **Go** installed on your system to run the install command below.  
  Install with:
  ```bash
  go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
  ```
---

## References

- [Subfinder GitHub Repository](https://github.com/projectdiscovery/subfinder)
- [VirusTotal API Documentation](https://developers.virustotal.com/reference)
- [Shodan API Documentation](https://developer.shodan.io/)
- [SecurityTrails API Documentation](https://securitytrails.com/corp/api)
- [WhoisXML API](https://whoisxmlapi.com/)
- [Fingerprints.json](https://github.com/haccer/subjack/blob/master/fingerprints.json)

---