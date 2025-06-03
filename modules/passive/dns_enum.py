


# modules/passive/dns_enum.py
import dns.resolver

def get_dns_records(domain):
    record_types = ['A', 'MX', 'TXT', 'NS']
    results = {}
    for record in record_types:
        try:
            answers = dns.resolver.resolve(domain, record)
            results[record] = [r.to_text() for r in answers]
        except Exception:
            results[record] = []
    return results
