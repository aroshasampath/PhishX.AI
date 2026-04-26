import re
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import tldextract

URL_REGEX = r"https?://[^\s\"'>]+"

SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "is.gd", "buff.ly", "cutt.ly", "rebrand.ly"
]

SUSPICIOUS_TLDS = [
    "xyz", "top", "click", "tk", "ml", "ga", "cf",
    "gq", "work", "zip", "mov", "country", "rest"
]

BRANDS = [
    "paypal", "google", "microsoft", "apple", "facebook",
    "instagram", "amazon", "netflix", "binance", "bank",
    "outlook", "office365", "linkedin"
]

def extract_urls(text):
    return re.findall(URL_REGEX, text)

def get_registered_domain_from_url(url):
    try:
        ext = tldextract.extract(url)
        return ext.registered_domain
    except:
        return ""


def normalize_text(text):
    text = text.replace("http //", "http://")
    text = text.replace("https //", "https://")
    text = text.replace("www .", "www.")
    return text

def get_tld(url):
    try:
        return tldextract.extract(url).suffix
    except:
        return ""

def is_ip_url(url):
    host = urlparse(url).hostname or ""
    return re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host) is not None

def is_shortener(url):
    host = urlparse(url).hostname or ""
    return host.replace("www.", "") in SHORTENERS

def has_at_symbol_trick(url):
    return "@" in urlparse(url).netloc

def has_punycode(url):
    host = urlparse(url).hostname or ""
    return "xn--" in host

def has_suspicious_tld(url):
    return get_tld(url) in SUSPICIOUS_TLDS

def detect_fake_visible_links(html):
    results = []
    soup = BeautifulSoup(html, "html.parser")

    for a in soup.find_all("a"):
        visible = a.get_text(strip=True)
        actual = a.get("href", "")

        if visible.startswith("http") and actual.startswith("http"):
            visible_domain = get_registered_domain_from_url(visible)
            actual_domain = get_registered_domain_from_url(actual)

            if visible_domain and actual_domain and visible_domain != actual_domain:
                results.append({
                    "visible_text": visible,
                    "actual_link": actual,
                    "reason": "Visible link domain is different from actual href domain"
                })

    return results

def detect_brand_spoofing(domain):
    findings = []

    for brand in BRANDS:
        if brand in domain and not domain.startswith(brand + "."):
            findings.append(f"Possible brand spoofing: {brand}")

    return findings

def detect_lookalike_domain(domain):
    findings = []

    suspicious_chars = ["0", "1", "3", "5", "rn", "vv"]

    for ch in suspicious_chars:
        if ch in domain:
            findings.append("Possible lookalike domain characters detected")
            break

    return findings

def scan_urls(text, sender_domain=""):
    text = normalize_text(text)
    urls = extract_urls(text)
    fake_links = detect_fake_visible_links(text)
    suspicious_urls = []

    for url in urls:
        reasons = []
        domain = get_registered_domain_from_url(url)

        if is_shortener(url):
            reasons.append("URL shortener detected")

        if is_ip_url(url):
            reasons.append("IP address URL detected")

        if has_at_symbol_trick(url):
            reasons.append("@ symbol hidden URL detected")

        if has_suspicious_tld(url):
            reasons.append("Suspicious TLD detected")

        if has_punycode(url):
            reasons.append("Punycode / Unicode spoofing detected")

        if url.startswith("http://"):
            reasons.append("HTTP instead of HTTPS detected")

        if sender_domain and domain and sender_domain != domain:
            reasons.append("Sender domain vs link domain mismatch")

        reasons.extend(detect_brand_spoofing(domain))
        reasons.extend(detect_lookalike_domain(domain))

        if reasons:
            suspicious_urls.append({
                "url": url,
                "domain": domain,
                "reasons": list(set(reasons))
            })

    return {
        "urls_found": urls,
        "fake_visible_links": fake_links,
        "suspicious_urls": suspicious_urls
    }
