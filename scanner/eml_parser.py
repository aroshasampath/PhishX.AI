from email import policy
from email.parser import BytesParser

def parse_eml_file(path):
    with open(path, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)

    subject = msg.get("subject", "")
    sender = msg.get("from", "")
    headers = str(msg)

    body = ""

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()

            if content_type == "text/plain":
                try:
                    body += part.get_content()
                except Exception:
                    pass
    else:
        try:
            body = msg.get_content()
        except Exception:
            body = ""

    attachments = []
    for part in msg.iter_attachments():
        filename = part.get_filename()
        if filename:
            attachments.append(filename)

    return {
        "subject": subject,
        "sender": sender,
        "headers": headers,
        "body": body,
        "attachments": attachments
    }
