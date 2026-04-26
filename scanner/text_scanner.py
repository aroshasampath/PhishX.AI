def scan_text(email_text):
    text = email_text.lower()

    suspicious_phrases = [
        "urgent", "verify your account", "account suspended",
        "account has been suspended", "click here", "login now",
        "confirm immediately", "security alert", "payment failed",
        "limited time", "your account has been locked",
        "unusual activity", "act now", "reset your password",
        "update your account", "verify immediately"
    ]

    sensitive_words = [
        "password", "otp", "one time password", "pin",
        "credit card", "debit card", "card number",
        "cvv", "cvc", "bank account", "login details",
        "login credentials"
    ]

    found_suspicious = [w for w in suspicious_phrases if w in text]
    found_sensitive = [w for w in sensitive_words if w in text]

    # 🔥 EXTRA RULES
    if "click" in text and "link" in text:
        found_suspicious.append("click link pattern")

    if "verify" in text:
        found_suspicious.append("verification request")

    if "login" in text:
        found_suspicious.append("login request")

    return {
        "suspicious_words_found": found_suspicious,
        "sensitive_requests_found": found_sensitive
    }
