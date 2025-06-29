# config.py
import os
import sys
from dotenv import load_dotenv

load_dotenv()


RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RESET = "\033[0m"
LIGHT_PURPLE = "\033[38;2;224;170;255m"  
DARK_PURPLE = "\033[38;2;60;9;108m"

# API Keys
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")
SECURITYTRAILS_API_KEY = os.getenv("SECURITYTRAILS_API_KEY")
WEBHOOK_URL = os.getenv("WEBHOOK_URL")
WHOISXML_API_KEY = os.getenv("WHOISXML_API_KEY")

if not VIRUSTOTAL_API_KEY or not SHODAN_API_KEY:
    print(f"{RED}[!] API keys not found. Set them in .env file{RESET}")
    sys.exit(1)

OUTPUT_FOLDER = "output"
VULNERABLE_FILE = "vulnerable.txt"
