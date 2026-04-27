def scan_headers(headers):
    reasons = []
    score = 0

    if not headers:
        return score, reasons

    lower = headers.lower()

    if "spf=fail" in lower or "spf: fail" in lower:
        score += 20
        reasons.append("SPF authentication failed")

    if "dkim=fail" in lower or "dkim: fail" in lower:
        score += 20
        reasons.append("DKIM authentication failed")

    if "dmarc=fail" in lower or "dmarc: fail" in lower:
        score += 20
        reasons.append("DMARC authentication failed")

    if "received:" in lower and lower.count("received:") > 5:
        score += 8
        reasons.append("Email passed through many mail servers")

    if "reply-to:" in lower and "from:" in lower:
        score += 5
        reasons.append("Reply-To header exists, verify if it differs from From address")

    return score, reasons
