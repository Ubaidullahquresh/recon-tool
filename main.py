import argparse
from modules.passive import whois_lookup, dns_enum, subdomain_enum
from modules.active import port_scan, banner_grab, tech_detect

def parse_args():
    parser = argparse.ArgumentParser(description="Custom Recon Tool by Ubaidullah Qureshi")

    parser.add_argument("--target", required=True, help="Target domain or IP")
    parser.add_argument("--mode", choices=["passive", "active", "all"], default="all", help="Recon mode to run")
    parser.add_argument("--output", help="Save results to file (e.g., report.txt)")

    # Passive options
    parser.add_argument("--whois", action="store_true", help="Run WHOIS lookup")
    parser.add_argument("--dns", action="store_true", help="Run DNS enumeration")
    parser.add_argument("--subdomains", action="store_true", help="Run subdomain enumeration")

    # Active options
    parser.add_argument("--portscan", action="store_true", help="Run port scanning")
    parser.add_argument("--banner", action="store_true", help="Run banner grabbing")
    parser.add_argument("--tech", action="store_true", help="Run technology detection")

    return parser.parse_args()

def main():
    args = parse_args()
    results = []

    print(f"[+] Starting reconnaissance on: {args.target}\n")

    # Passive recon
    if args.mode in ["passive", "all"]:
        if args.whois:
            print("[*] Running WHOIS lookup...")
            results.append(whois_lookup.whois_lookup(args.target))

        if args.dns:
            print("[*] Running DNS enumeration...")
            results.append(dns_enum.dns_enum(args.target))

        if args.subdomains:
            print("[*] Running subdomain enumeration...")
            results.append(subdomain_enum.subdomain_enum(args.target))

    # Active recon
    if args.mode in ["active", "all"]:
        if args.portscan:
            print("[*] Running port scan...")
            results.append(port_scan.port_scan(args.target))

        if args.banner:
            print("[*] Running banner grabbing...")
            results.append(banner_grab.banner_grab(args.target))

        if args.tech:
            print("[*] Running technology detection...")
            results.append(tech_detect.tech_detect(args.target))

    final_report = "\n\n".join(results)
    print("\n[+] Reconnaissance Complete!\n")
    print(final_report)

    # Save to file
    if args.output:
        try:
            with open(args.output, "w") as f:
                f.write(final_report)
            print(f"\n[+] Results saved to: {args.output}")
        except Exception as e:
            print(f"[-] Failed to save output: {e}")

if __name__ == "__main__":
    main()
