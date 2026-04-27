import socket
import difflib

POPULAR_BRANDS = [
    "paypal.com",
    "google.com",
    "microsoft.com",
    "apple.com",
    "facebook.com",
    "amazon.com",
    "netflix.com",
    "github.com",
    "linkedin.com",
    "bankofamerica.com",
]

def domain_exists(domain):
    try:
        socket.gethostbyname(domain)
        return True
    except Exception:
        return False

def scan_domain(sender_domain):
    reasons = []
    score = 0

    if not sender_domain:
        return score, reasons

    domain = sender_domain.lower().replace("www.", "")

    if not domain_exists(domain):
        score += 15
        reasons.append(f"Sender domain does not resolve: {domain}")

    for brand in POPULAR_BRANDS:
        ratio = difflib.SequenceMatcher(None, domain, brand).ratio()

        if ratio > 0.72 and domain != brand:
            score += 20
            reasons.append(f"Possible brand spoofing: {domain} looks like {brand}")

    if domain.startswith("xn--"):
        score += 25
        reasons.append("Punycode domain detected, possible Unicode spoofing")

    return score, reasons
