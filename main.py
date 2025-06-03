# main.py
import argparse
from modules.passive import whois_lookup, dns_enum, subdomain_enum

parser = argparse.ArgumentParser(description="Custom Recon Tool")
parser.add_argument("domain", help="Target domain (e.g. example.com)")
parser.add_argument("--whois", action="store_true", help="Run WHOIS Lookup")
parser.add_argument("--dns", action="store_true", help="Run DNS Enumeration")
parser.add_argument("--subs", action="store_true", help="Run Subdomain Enumeration")

args = parser.parse_args()

if args.whois:
    print("[*] Running WHOIS Lookup...")
    print(whois_lookup.whois_lookup(args.domain))

if args.dns:
    print("[*] Running DNS Enumeration...")
    records = dns_enum.get_dns_records(args.domain)
    for rtype, recs in records.items():
        print(f"{rtype}: {', '.join(recs)}")

if args.subs:
    print("[*] Running Subdomain Enumeration...")
    subs = subdomain_enum.subdomain_enum_crtsh(args.domain)
    print("\n".join(subs))
