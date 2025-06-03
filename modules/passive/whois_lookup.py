

# modules/passive/whois_lookup.py
import whois

def whois_lookup(domain):
    try:
        data = whois.whois(domain)
        return str(data)
    except Exception as e:
        return f"WHOIS Lookup failed: {e}"
