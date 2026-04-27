DANGEROUS_EXTENSIONS = [
    ".exe", ".scr", ".bat", ".cmd", ".js", ".vbs",
    ".jar", ".msi", ".ps1", ".apk", ".com"
]

DOCUMENT_EXTENSIONS = [
    ".docm", ".xlsm", ".pptm"
]

def scan_attachments(attachments):
    reasons = []
    score = 0

    if not attachments:
        return score, reasons

    for file in attachments:
        filename = file.lower()

        if any(filename.endswith(ext) for ext in DANGEROUS_EXTENSIONS):
            score += 25
            reasons.append(f"Dangerous attachment extension detected: {file}")

        if any(filename.endswith(ext) for ext in DOCUMENT_EXTENSIONS):
            score += 15
            reasons.append(f"Macro-enabled document detected: {file}")

        parts = filename.split(".")
        if len(parts) >= 3:
            score += 15
            reasons.append(f"Double extension attachment detected: {file}")

    return score, reasons
