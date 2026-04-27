from scanner.text_scanner import scan_text
from scanner.url_scanner import scan_urls
from scanner.domain_scanner import scan_domain
from scanner.header_scanner import scan_headers
from scanner.attachment_scanner import scan_attachments
from scanner.risk_engine import calculate_risk
from scanner.ai_classifier import ai_phishing_classifier


def analyze_email(text="", sender="", headers="", attachments=None):
    if attachments is None:
        attachments = []

    total_score = 0
    all_reasons = []

    text_score, text_reasons = scan_text(text)
    total_score += text_score
    all_reasons.extend(text_reasons)

    ai_score, ai_reasons = ai_phishing_classifier(text)
    total_score += ai_score
    all_reasons.extend(ai_reasons)

    url_score, url_reasons, urls = scan_urls(text, sender)
    total_score += url_score
    all_reasons.extend(url_reasons)

    domain_score, domain_reasons = scan_domain(sender)
    total_score += domain_score
    all_reasons.extend(domain_reasons)

    header_score, header_reasons = scan_headers(headers)
    total_score += header_score
    all_reasons.extend(header_reasons)

    attachment_score, attachment_reasons = scan_attachments(attachments)
    total_score += attachment_score
    all_reasons.extend(attachment_reasons)

    lower_text = text.lower()

    if (
        ("account" in lower_text or "acount" in lower_text)
        and (
            "risk" in lower_text
            or "closure" in lower_text
            or "terminate" in lower_text
            or "teminate" in lower_text
        )
    ):
        total_score += 25
        all_reasons.append("Account risk / closure phishing combination detected")

    if (
        ("verify" in lower_text or "very" in lower_text or "vety" in lower_text)
        and ("account" in lower_text or "acount" in lower_text)
    ):
        total_score += 25
        all_reasons.append("Account verification phishing pattern detected")

    if ("password" in lower_text or "otp" in lower_text) and len(urls) > 0:
        total_score += 20
        all_reasons.append("Password/OTP request combined with external link detected")

    risk, score = calculate_risk(total_score)

    if not all_reasons:
        all_reasons.append("No strong phishing indicators detected")

    return {
        "risk": risk,
        "score": score,
        "reasons": all_reasons,
        "urls": urls,
        "total_urls": len(urls),
        "ai_score": ai_score
    }
