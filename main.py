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

    # Auto-enable all modules if --mode all
    if args.mode == "all":
        args.whois = True
        args.dns = True
        args.subdomains = True
        args.portscan = True
        args.banner = True
        args.tech = True

    print(f"[+] Starting reconnaissance on: {args.target}\n")

    # Passive recon
    if args.mode in ["passive", "all"]:
        if args.whois:
            print("[*] Running WHOIS lookup...")
            output = whois_lookup.whois_lookup(args.target)
            if output:
                results.append("=== WHOIS LOOKUP ===\n" + output)

        if args.dns:
            print("[*] Running DNS enumeration...")
            output = dns_enum.dns_enum(args.target)
            if output:
                results.append("=== DNS ENUMERATION ===\n" + output)

        if args.subdomains:
            print("[*] Running subdomain enumeration...")
            output = subdomain_enum.subdomain_enum(args.target)
            if output:
                results.append("=== SUBDOMAIN ENUMERATION ===\n" + output)

    # Active recon
    if args.mode in ["active", "all"]:
        if args.portscan:
            print("[*] Running port scan...")
            output = port_scan.port_scan(args.target)
            if output:
                results.append("=== PORT SCAN ===\n" + output)

        if args.banner:
            print("[*] Running banner grabbing...")
            output = banner_grab.banner_grab(args.target)
            if output:
                results.append("=== BANNER GRABBING ===\n" + output)

        if args.tech:
            print("[*] Running technology detection...")
            output = tech_detect.tech_detect(args.target)
            if output:
                results.append("=== TECHNOLOGY DETECTION ===\n" + output)

    final_report = "\n\n".join(results)

    print("\n[+] Reconnaissance Complete!\n")
    print(final_report if final_report else "[!] No data was collected. Please check the modules.")

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
