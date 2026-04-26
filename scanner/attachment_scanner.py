SUSPICIOUS_EXTENSIONS = [
    ".exe", ".scr", ".bat", ".cmd", ".vbs", ".js",
    ".jar", ".iso", ".html", ".htm", ".docm",
    ".xlsm", ".zip", ".rar", ".7z"
]

def scan_attachments(msg):
    attachments = []
    suspicious = []

    for part in msg.walk():
        filename = part.get_filename()

        if filename:
            lower = filename.lower()
            attachments.append(filename)

            for ext in SUSPICIOUS_EXTENSIONS:
                if lower.endswith(ext):
                    suspicious.append({
                        "filename": filename,
                        "reason": f"Suspicious attachment extension: {ext}"
                    })

            if lower.count(".") >= 2:
                suspicious.append({
                    "filename": filename,
                    "reason": "Double-extension attachment detected"
                })

    return {
        "attachments": attachments,
        "suspicious_attachments": suspicious
    }
