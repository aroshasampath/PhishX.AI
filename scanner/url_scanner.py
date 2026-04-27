import re
from urllib.parse import urlparse
import difflib

POPULAR_BRANDS = [
    "paypal.com",
    "google.com",
    "microsoft.com",
    "apple.com",
]

def extract_urls(text):
    pattern = r"(https?://[^\s]+)"
    return re.findall(pattern, text)


def scan_urls(text, sender_domain=""):
    urls = extract_urls(text)
    reasons = []
    score = 0

    for url in urls:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()

        # 🔥 Lookalike detection
        for brand in POPULAR_BRANDS:
            ratio = difflib.SequenceMatcher(None, domain, brand).ratio()

            if ratio > 0.7 and domain != brand:
                score += 30
                reasons.append(f"Lookalike phishing domain: {domain} mimics {brand}")

        # hyphen
        if "-" in domain:
            score += 5
            reasons.append(f"Hyphenated domain detected: {domain}")

        # sensitive mismatch
        if sender_domain and sender_domain not in domain:
            score += 10
            reasons.append("Sender domain mismatch")

    return score, reasons, urls
