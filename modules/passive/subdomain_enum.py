
# modules/passive/subdomain_enum.py
import requests

def subdomain_enum_crtsh(domain):
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        res = requests.get(url, timeout=10)
        data = res.json()
        subdomains = sorted(set(entry['name_value'] for entry in data))
        return subdomains
    except Exception as e:
        return [f"Error fetching from crt.sh: {e}"]
