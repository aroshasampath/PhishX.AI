from email.utils import parseaddr
import tldextract

def get_email_domain(value):
    name, email_addr = parseaddr(value or "")
    if "@" not in email_addr:
        return ""
    return email_addr.split("@")[-1].lower()

def get_registered_domain(domain):
    ext = tldextract.extract(domain)
    return ext.registered_domain

def scan_headers(msg):
    auth = msg.get("Authentication-Results", "").lower()

    from_value = msg.get("From", "")
    reply_to_value = msg.get("Reply-To", "")
    subject = msg.get("Subject", "")

    sender_domain = get_registered_domain(get_email_domain(from_value))
    reply_domain = get_registered_domain(get_email_domain(reply_to_value))

    result = {
        "from": from_value,
        "reply_to": reply_to_value,
        "subject": subject,
        "sender_domain": sender_domain,
        "reply_to_domain": reply_domain,
        "spf": "unknown",
        "dkim": "unknown",
        "dmarc": "unknown",
        "header_reasons": []
    }

    if "spf=pass" in auth:
        result["spf"] = "pass"
    elif "spf=fail" in auth or "spf=softfail" in auth:
        result["spf"] = "fail"
        result["header_reasons"].append("SPF failed")

    if "dkim=pass" in auth:
        result["dkim"] = "pass"
    elif "dkim=fail" in auth:
        result["dkim"] = "fail"
        result["header_reasons"].append("DKIM failed")

    if "dmarc=pass" in auth:
        result["dmarc"] = "pass"
    elif "dmarc=fail" in auth:
        result["dmarc"] = "fail"
        result["header_reasons"].append("DMARC failed")

    if sender_domain and reply_domain and sender_domain != reply_domain:
        result["header_reasons"].append("From domain and Reply-To domain mismatch")

    return result
