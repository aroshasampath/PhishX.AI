import dns.resolver
import whois
from datetime import datetime

def dns_resolves(domain):
    try:
        dns.resolver.resolve(domain, "A")
        return True
    except:
        return False

def has_mx_record(domain):
    try:
        dns.resolver.resolve(domain, "MX")
        return True
    except:
        return False

def get_domain_age_days(domain):
    try:
        data = whois.whois(domain)
        creation_date = data.creation_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if not creation_date:
            return None

        return (datetime.now() - creation_date).days
    except:
        return None

def scan_domain(domain):
    reasons = []

    if not domain:
        return {
            "domain": domain,
            "dns_resolves": False,
            "has_mx": False,
            "domain_age_days": None,
            "domain_reasons": ["No sender domain found"]
        }

    dns_ok = dns_resolves(domain)
    mx_ok = has_mx_record(domain)
    age_days = get_domain_age_days(domain)

    if not dns_ok:
        reasons.append("DNS resolve failed")

    if not mx_ok:
        reasons.append("MX record not found")

    if age_days is not None and age_days < 30:
        reasons.append("Domain is very new")

    return {
        "domain": domain,
        "dns_resolves": dns_ok,
        "has_mx": mx_ok,
        "domain_age_days": age_days,
        "domain_reasons": reasons
    }
