def calculate_risk(text_result, url_result, header_result, attachment_result, domain_result):
    score = 0
    reasons = []

    if text_result.get("suspicious_words_found"):
        score += len(text_result["suspicious_words_found"]) * 10
        reasons.append("Suspicious words/phrases detected")

    if text_result.get("sensitive_requests_found"):
        score += len(text_result["sensitive_requests_found"]) * 20
        reasons.append("Password / OTP / PIN / card details request detected")

    if url_result.get("suspicious_urls"):
        score += len(url_result["suspicious_urls"]) * 15
        reasons.append("Suspicious URL rules matched")

    if url_result.get("fake_visible_links"):
        score += 25
        reasons.append("HTML visible link vs actual link mismatch detected")

    if header_result.get("spf") == "fail":
        score += 15
        reasons.append("SPF failed")

    if header_result.get("dkim") == "fail":
        score += 15
        reasons.append("DKIM failed")

    if header_result.get("dmarc") == "fail":
        score += 20
        reasons.append("DMARC failed")

    if header_result.get("header_reasons"):
        score += len(header_result["header_reasons"]) * 5
        reasons.extend(header_result["header_reasons"])

    if attachment_result.get("suspicious_attachments"):
        score += len(attachment_result["suspicious_attachments"]) * 20
        reasons.append("Suspicious attachment detected")

    if domain_result.get("domain_reasons"):
        score += len(domain_result["domain_reasons"]) * 10
        reasons.extend(domain_result["domain_reasons"])

    score = min(score, 100)

    if score >= 70:
        risk_level = "High"
        verdict = "Likely Phishing"
    elif score >= 40:
        risk_level = "Medium"
        verdict = "Suspicious"
    else:
        risk_level = "Low"
        verdict = "Probably Safe"

    return {
        "verdict": verdict,
        "risk_level": risk_level,
        "risk_score": score,
        "reasons": list(set(reasons)),
        "report": {
            "urls_found": url_result.get("urls_found", []),
            "suspicious_urls": url_result.get("suspicious_urls", []),
            "fake_visible_links": url_result.get("fake_visible_links", []),
            "attachments": attachment_result.get("attachments", []),
            "suspicious_attachments": attachment_result.get("suspicious_attachments", []),
            "email_authentication": {
                "spf": header_result.get("spf", "unknown"),
                "dkim": header_result.get("dkim", "unknown"),
                "dmarc": header_result.get("dmarc", "unknown")
            },
            "domain_check": domain_result
        },
        "details": {
            "text_result": text_result,
            "url_result": url_result,
            "header_result": header_result,
            "attachment_result": attachment_result,
            "domain_result": domain_result
        }
    }
