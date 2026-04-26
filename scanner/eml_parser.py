from email import policy
from email.parser import BytesParser

def parse_eml(content):
    msg = BytesParser(policy=policy.default).parsebytes(content)

    subject = msg.get("Subject", "")
    sender = msg.get("From", "")
    reply_to = msg.get("Reply-To", "")

    body = ""

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()

            if content_type in ["text/plain", "text/html"]:
                try:
                    body += "\n" + part.get_content()
                except:
                    pass
    else:
        try:
            body = msg.get_content()
        except:
            body = ""

    return {
        "msg": msg,
        "subject": subject,
        "sender": sender,
        "reply_to": reply_to,
        "body": body,
        "full_text": subject + "\n" + sender + "\n" + reply_to + "\n" + body
    }
