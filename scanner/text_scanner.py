
import re
import difflib

SUSPICIOUS_KEYWORDS = [
    "verify your account",
    "account suspended",
    "urgent action",
    "login immediately",
    "password expired",
    "confirm your identity",
    "unauthorized login",
    "payment failed",
    "security alert",
    "limited time",
    "click here",
    "reset your password",
    "bank account",
    "otp",
    "pin",
    "credit card",
    "debit card",
    "cvv",
    "invoice attached",
    "gift card",
    "crypto wallet",
    "account is at risk",
    "terminate your account",
    "closure of your account",
    "office 365",
    "helpdesk",
]

OCR_FUZZY_WORDS = [
    "verify",
    "account",
    "terminate",
    "closure",
    "password",
    "urgent",
    "risk",
    "helpdesk",
    "office",
    "administrator",
    "failure",
    "login",
    "security",
]

def fuzzy_contains(text, target, threshold=0.72):
    words = re.findall(r"[a-zA-Z0-9]+", text.lower())

    for word in words:
        ratio = difflib.SequenceMatcher(None, word, target).ratio()
        if ratio >= threshold:
            return True

    return False


def scan_text(text):
    reasons = []
    score = 0

    if not text:
        return score, reasons

    lower_text = text.lower()

    for word in SUSPICIOUS_KEYWORDS:
        if word in lower_text:
            score += 10
            reasons.append(f"Suspicious phrase detected: '{word}'")

    fuzzy_hits = []

    for word in OCR_FUZZY_WORDS:
        if fuzzy_contains(lower_text, word):
            fuzzy_hits.append(word)

    if len(fuzzy_hits) >= 3:
        score += 30
        reasons.append(
            "OCR/fuzzy phishing words detected: " + ", ".join(fuzzy_hits)
        )

    if re.search(r"\b(password|otp|pin|cvv|card number|account)\b", lower_text):
        score += 20
        reasons.append("Email requests sensitive or account-related information")

    if re.search(r"\b(urgent|immediately|within 24 hours|final warning|risk|closure|terminate)\b", lower_text):
        score += 20
        reasons.append("Urgency, risk, termination or pressure tactic detected")

    if "http" in lower_text or "www" in lower_text or "url" in lower_text:
        score += 15
        reasons.append("Email asks user to visit or copy a URL")

    if "helpdesk" in lower_text or "administrator" in lower_text:
        score += 10
        reasons.append("Helpdesk/admin impersonation detected")

    if "office" in lower_text or "365" in lower_text or "385" in lower_text:
        score += 10
        reasons.append("Office 365 style account phishing indicator detected")

    return score, reasons
