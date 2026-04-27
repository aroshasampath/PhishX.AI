import re
import difflib

PHISHING_PATTERNS = [
    "verify your account",
    "account suspended",
    "login immediately",
    "password expired",
    "unauthorized login",
    "confirm your identity",
    "payment failed",
    "security alert",
    "click here",
    "otp",
    "pin",
    "cvv",
    "credit card",
    "bank account",
    "limited time",
    "final warning",
    "account is at risk",
    "terminate your account",
    "closure of your account",
    "office 365",
    "helpdesk",
    "administrator",
]

FUZZY_PATTERNS = [
    "verify",
    "account",
    "terminate",
    "closure",
    "failure",
    "risk",
    "office",
    "helpdesk",
    "administrator",
    "password",
    "security",
]

SAFE_PATTERNS = [
    "meeting",
    "newsletter",
    "receipt",
    "thank you",
    "schedule",
    "invoice paid",
    "confirmation",
]

def fuzzy_word_found(text, target, threshold=0.70):
    words = re.findall(r"[a-zA-Z0-9]+", text.lower())

    for word in words:
        if difflib.SequenceMatcher(None, word, target).ratio() >= threshold:
            return True

    return False


def ai_phishing_classifier(text=""):
    text = text.lower()
    score = 0
    reasons = []

    if not text.strip():
        return 0, ["AI classifier skipped: empty text"]

    phishing_hits = 0

    for pattern in PHISHING_PATTERNS:
        if pattern in text:
            phishing_hits += 1
            score += 12

    fuzzy_hits = []

    for word in FUZZY_PATTERNS:
        if fuzzy_word_found(text, word):
            fuzzy_hits.append(word)

    if len(fuzzy_hits) >= 3:
        score += 35
        reasons.append("AI fuzzy OCR phishing pattern detected")

    safe_hits = 0

    for pattern in SAFE_PATTERNS:
        if pattern in text:
            safe_hits += 1
            score -= 3

    if re.search(r"(http|www\.|url)", text):
        score += 12
        reasons.append("AI detected URL-related email behavior")

    if re.search(r"(password|otp|pin|cvv|card|account|verify|vety|very)", text):
        score += 20
        reasons.append("AI detected account or sensitive information request")

    if re.search(r"(urgent|immediately|within 24 hours|26 hours|final warning|risk|terminate|closure)", text):
        score += 20
        reasons.append("AI detected urgency / account closure pressure tactic")

    if "office" in text or "365" in text or "385" in text:
        score += 15
        reasons.append("AI detected Microsoft/Office account phishing pattern")

    if phishing_hits >= 3:
        score += 25
        reasons.append("AI classified message as strongly phishing-like")

    if safe_hits >= 2 and phishing_hits == 0 and len(fuzzy_hits) < 3:
        score -= 10
        reasons.append("AI found normal email patterns")

    score = max(0, min(score, 100))

    if not reasons:
        reasons.append("AI classifier found no strong phishing pattern")

    return score, reasons
