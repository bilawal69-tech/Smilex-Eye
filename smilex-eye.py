#!/usr/bin/env python3
import shodan
import argparse
import os
import sys
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

# --- Configuration ---
KEY_FILE = os.path.expanduser("~/.smilex_key")
console = Console()

# --- THE COMPLETE 67-FILTER DATABASE (Tier-Mapped) ---
# Tiers: 0=Free, 1=Membership, 2=Small Business, 3=Corporate
FILTER_GROUPS = {
    "General": [
        ["after", "after:01/01/2026", "Results after a date (dd/mm/yyyy)", 0],
        ["asn", "asn:AS15169", "Autonomous System Number", 0],
        ["before", "before:01/01/2026", "Results before a date (dd/mm/yyyy)", 0],
        ["category", "category:ics", "Predefined categories (ics, malware)", 0],
        ["city", "city:London", "City name", 0],
        ["country", "country:AE", "2-letter country code", 0],
        ["device", "device:webcam", "Type of device", 0],
        ["geo", "geo:25.2,55.3", "Search by latitude and longitude", 0],
        ["hash", "hash:-12345", "Banner data hash (integer)", 0],
        ["hostname", "hostname:edu", "Search by hostname/domain suffix", 0],
        ["ip", "ip:1.1.1.1", "Search for a specific IP", 0],
        ["isp", "isp:Comcast", "Internet Service Provider", 0],
        ["net", "net:192.168.1.0/24", "Network range (CIDR)", 0],
        ["org", "org:Microsoft", "Organization owning the IP", 0],
        ["os", "os:Windows", "Operating System", 0],
        ["port", "port:445", "Specific port number", 0],
        ["product", "product:nginx", "Software brand/name", 0],
        ["version", "version:1.18", "Software version", 0],
        ["state", "state:NY", "State or province", 0],
        ["postal", "postal:90210", "Postal/Zip code (US)", 0]
    ],
    "Web (HTTP)": [
        ["http.component", "http.component:wordpress", "Web technology/framework", 1],
        ["http.component_category", "http.component_category:CMS", "Component category", 1],
        ["http.dom_hash", "http.dom_hash:54321", "Hash of the website DOM", 1],
        ["http.favicon.hash", "http.favicon.hash:1234", "Favicon MMH3 hash", 1],
        ["http.headers_hash", "http.headers_hash:4321", "Hash of HTTP headers", 1],
        ["http.html", "http.html:login", "Search text inside HTML body", 1],
        ["http.html_hash", "http.html_hash:9876", "Hash of HTML body", 1],
        ["http.robots_hash", "http.robots_hash:1122", "Hash of robots.txt", 1],
        ["http.securitytxt", "http.securitytxt:contact", "Search security.txt", 1],
        ["http.server_header", "http.server_header:apache", "Specific server header", 1],
        ["http.status", "http.status:200", "HTTP response status code", 1],
        ["http.title", "http.title:dashboard", "Text in <title> tag", 1],
        ["http.waf", "http.waf:cloudflare", "WAF brand", 1]
    ],
    "SSL / Certificates": [
        ["ssl", "ssl:expired:true", "Search all SSL data", 1],
        ["ssl.alpn", "ssl.alpn:h2", "Application protocol (h2, spdy)", 1],
        ["ssl.cert.alg", "ssl.cert.alg:sha256", "Cert signature algorithm", 1],
        ["ssl.cert.expired", "ssl.cert.expired:true", "Find expired certificates", 1],
        ["ssl.cert.extension", "ssl.cert.extension:ocsp", "Names of cert extensions", 1],
        ["ssl.cert.issuer.cn", "ssl.cert.issuer.cn:R3", "CA Common Name", 1],
        ["ssl.cert.pubkey.bits", "ssl.cert.pubkey.bits:2048", "Pubkey bit length", 1],
        ["ssl.cert.pubkey.type", "ssl.cert.pubkey.type:rsa", "Public key type", 1],
        ["ssl.cert.serial", "ssl.cert.serial:12345", "Certificate serial number", 1],
        ["ssl.cert.subject.cn", "ssl.cert.subject.cn:google", "Cert Common Name", 1],
        ["ssl.chain_count", "ssl.chain_count:3", "Certs in chain", 1],
        ["ssl.version", "ssl.version:tlsv1.3", "Specific SSL/TLS version", 1],
        ["has_ssl", "has_ssl:true", "Hosts with SSL/TLS enabled", 0]
    ],
    "Security & Vulns": [
        ["has_vuln", "has_vuln:true", "Find hosts with confirmed CVEs", 1],
        ["vuln", "vuln:CVE-2019-0708", "Search by specific CVE ID", 2],
        ["has_screenshot", "has_screenshot:true", "Hosts with images", 1],
        ["screenshot.label", "screenshot.label:ics", "Type of image", 1],
        ["screenshot.hash", "screenshot.hash:1234", "Screenshot hash", 1]
    ],
    "Cloud & Infrastructure": [
        ["cloud.provider", "cloud.provider:aws", "Cloud host (aws, azure)", 1],
        ["cloud.region", "cloud.region:us-east-1", "Cloud data center region", 1],
        ["cloud.service", "cloud.service:EC2", "Specific cloud service name", 1],
        ["domain", "domain:example.com", "Search all subdomains/records", 1]
    ],
    "Specialized Protocols": [
        ["ssh.hassh", "ssh.hassh:12345", "SSH client fingerprint", 1],
        ["ssh.type", "ssh.type:OpenSSH", "SSH server software type", 1],
        ["telnet.do", "telnet.do:echo", "Telnet 'Do' options", 1],
        ["telnet.dont", "telnet.dont:echo", "Telnet 'Dont' options", 1],
        ["telnet.option", "telnet.option:echo", "General Telnet options", 1],
        ["bitcoin.ip", "bitcoin.ip:1.2.3.4", "IP of a Bitcoin node", 1],
        ["bitcoin.version", "bitcoin.version:70015", "Bitcoin protocol version", 1],
        ["ntp.ip", "ntp.ip:1.1.1.1", "IPs in NTP monlist", 1],
        ["ntp.more", "ntp.more:true", "Extra data in NTP monlist", 1],
        ["snmp.contact", "snmp.contact:admin", "SNMP contact string", 1],
        ["snmp.location", "snmp.location:DC1", "SNMP location string", 1],
        ["snmp.name", "snmp.name:router", "SNMP name string", 1]
    ]
}

BANNER = r"""[bold cyan]
   _____           _ _             ______             
  / ___/____ ___  (_) /__  _  __  / ____/_  _____     
  \__ \/ __ `__ \/ / / _ \| |/_/ / __/ / / / / _ \    
 ___/ / / / / / / / /  __/>  <  / /___/ /_/ /  __/    
/____/_/ /_/ /_/_/_/\___/_/|_| /_____/\__, /\___/     
                                     /____/           [/][bold white]
          >> [bold yellow]SMILEX-EYE ULTIMATE[/] v20.0 <<
          >> [bold green]CREATED BY: 0x0smilex[/] <<[/]
"""

def get_api_key():
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, 'r') as f: return f.read().strip()
    console.print(Panel("[bold yellow]Setup Mode[/]\nEnter your Shodan API Key.", title="SMILEX-EYE"))
    key = input("> ").strip()
    if key:
        with open(KEY_FILE, 'w') as f: f.write(key)
        return key
    sys.exit(1)

def get_user_tier(api):
    try:
        info = api.info()
        plan = info.get('plan', 'free').lower()
        if any(x in plan for x in ['corporate', 'enterprise']): return 3, plan
        if 'small-business' in plan: return 2, plan
        if any(x in plan for x in ['membership', 'academic', 'dev']): return 1, plan
        return 0, plan
    except: return 0, "free"

def list_filters(api, category=None):
    tier_level, plan_name = get_user_tier(api)
    console.print(f"[*] Shodan Plan: [bold magenta]{plan_name.upper()}[/] | Showing authorized filters:")
    
    if not category or category.lower() == "all":
        table = Table(title="Available Categories", header_style="bold magenta")
        table.add_column("Category Name", style="cyan")
        table.add_column("Filters Inside", style="white")
        for cat, items in FILTER_GROUPS.items():
            unlocked = [f for f in items if f[3] <= tier_level]
            if unlocked: table.add_row(cat.lower(), str(len(unlocked)))
        console.print(table)
    else:
        key = next((k for k in FILTER_GROUPS.keys() if k.lower().startswith(category.lower())), None)
        if key:
            table = Table(title=f"Filters: {key.upper()}", show_lines=True)
            table.add_column("Filter", style="bold yellow")
            table.add_column("Example", style="cyan")
            table.add_column("Description", style="white")
            for f in FILTER_GROUPS[key]:
                if f[3] <= tier_level: table.add_row(f[0], f[1], f[2])
            console.print(table)

def analyze_ip(api, ip):
    try:
        host = api.host(ip)
        tags = host.get('tags', [])
        if 'honeypot' in tags: return "[bold red]HONEYPOT[/]"
        keywords = ["honeypot", "dionaea", "cowrie", "conpot"]
        for b in host.get('data', []):
            if any(k in str(b.get('data','')).lower() for k in keywords): return "[bold yellow]SUSPICIOUS[/]"
        return "[bold green]CLEAN[/]"
    except: return "[dim]Unknown[/]"

def main():
    console.print(BANNER)
    parser = argparse.ArgumentParser(
        prog="smilex-eye",
        usage="smilex-eye [-q QUERY] [-l LIMIT] [-c CHECK] [--honeypot] [--save SAVE] [--list [LIST]] [-h]",
        add_help=False
    )
    
    mining = parser.add_argument_group('🛠️  MINING')
    mining.add_argument("-q", "--query", help="Search query")
    mining.add_argument("-l", "--limit", type=int, default=15, help="Result limit")
    
    hunting = parser.add_argument_group('🎯  HUNTING')
    hunting.add_argument("-c", "--check", help="Check 1 IP")
    hunting.add_argument("--honeypot", action="store_true", help="Analyze results for deception")
    
    export = parser.add_argument_group('💾  EXPORT')
    export.add_argument("--save", help="Save IPs to .txt")

    ref = parser.add_argument_group('📚  REF')
    ref.add_argument("--list", nargs='?', const='all', help="List filters for your plan")
    ref.add_argument("-h", "--help", action="help", help="Show this help message")
    
    args = parser.parse_args()
    api = shodan.Shodan(get_api_key())

    if args.list: list_filters(api, args.list); return
    if args.check:
        console.print(f"[*] Analyzing: {args.check}...")
        console.print(Panel(f"Verdict: {analyze_ip(api, args.check)}", title=args.check)); return
    if not args.query:
        console.print("[dim]Use -q to search. Example: smilex-eye -q 'port:21'[/]"); return

    try:
        res = api.search(args.query, limit=args.limit)
        table = Table(title=f"Results for {args.query}", show_lines=True)
        table.add_column("IP:PORT", style="white")
        table.add_column("ORGANIZATION", style="green")
        if args.honeypot: table.add_column("DECEPTION", style="bold magenta")

        for m in res['matches']:
            row = [f"{m['ip_str']}:{m['port']}", m.get('org', 'N/A')[:20]]
            if args.honeypot: row.append(analyze_ip(api, m['ip_str']))
            table.add_row(*row)
            
        console.print(table)
        if args.save:
            with open(args.save, "w") as f:
                for m in res['matches']: f.write(f"{m['ip_str']}\n")
            console.print(f"[bold green][+][/] Saved to {args.save}")
    except Exception as ex: console.print(f"[bold red]Error:[/] {ex}")

if __name__ == "__main__":
    main()
