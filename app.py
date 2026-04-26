import os
from fastapi import FastAPI, Form, UploadFile, File, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from scanner.text_scanner import scan_text
from scanner.url_scanner import scan_urls
from scanner.header_scanner import scan_headers
from scanner.attachment_scanner import scan_attachments
from scanner.domain_scanner import scan_domain
from scanner.risk_engine import calculate_risk
from scanner.eml_parser import parse_eml
from scanner.image_scanner import extract_text_from_image


app = FastAPI(
    title="PhishX.AI",
    docs_url=None,
    redoc_url=None,
    openapi_url=None
)

app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)


@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request):
    return templates.TemplateResponse(request, "dashboard.html")

@app.get("/security-advice", response_class=HTMLResponse)
def security_advice_page(request: Request):
    return templates.TemplateResponse(request, "security_advice.html")

@app.get("/text-scan", response_class=HTMLResponse)
def text_scan_page(request: Request):
    return templates.TemplateResponse(request, "text_scan.html")


@app.get("/image-scan", response_class=HTMLResponse)
def image_scan_page(request: Request):
    return templates.TemplateResponse(request, "image_scan.html")


@app.post("/scan-text")
def scan_email_text(
    email_text: str = Form(...),
    sender_domain: str = Form("")
):
    text_result = scan_text(email_text)
    url_result = scan_urls(email_text, sender_domain)
    domain_result = scan_domain(sender_domain)

    header_result = {
        "from": "",
        "reply_to": "",
        "subject": "Text Scan",
        "sender_domain": sender_domain,
        "reply_to_domain": "",
        "spf": "unknown",
        "dkim": "unknown",
        "dmarc": "unknown",
        "header_reasons": []
    }

    attachment_result = {
        "attachments": [],
        "suspicious_attachments": []
    }

    result = calculate_risk(
        text_result,
        url_result,
        header_result,
        attachment_result,
        domain_result
    )

    result["email_info"] = {
        "sender": "",
        "reply_to": "",
        "subject": "Text Scan",
        "sender_domain": sender_domain
    }

    return result


@app.post("/scan-image")
async def scan_image(
    file: UploadFile = File(...),
    sender_domain: str = Form("")
):
    safe_filename = file.filename.replace("/", "_").replace("\\", "_")
    file_path = os.path.join(UPLOAD_DIR, safe_filename)

    with open(file_path, "wb") as f:
        f.write(await file.read())

    extracted_text = extract_text_from_image(file_path)

    text_result = scan_text(extracted_text)
    url_result = scan_urls(extracted_text, sender_domain)
    domain_result = scan_domain(sender_domain)

    header_result = {
        "from": "",
        "reply_to": "",
        "subject": "Image OCR Scan",
        "sender_domain": sender_domain,
        "reply_to_domain": "",
        "spf": "unknown",
        "dkim": "unknown",
        "dmarc": "unknown",
        "header_reasons": []
    }

    attachment_result = {
        "attachments": [safe_filename],
        "suspicious_attachments": []
    }

    result = calculate_risk(
        text_result,
        url_result,
        header_result,
        attachment_result,
        domain_result
    )

    extracted_lower = extracted_text.lower()

    if len(extracted_text.strip()) > 50:
        result["risk_score"] = min(result["risk_score"] + 10, 100)
        result["reasons"].append("OCR text extracted from image")

    if "password" in extracted_lower:
        result["risk_score"] = min(result["risk_score"] + 20, 100)
        result["reasons"].append("Password request found in image text")

    if "otp" in extracted_lower:
        result["risk_score"] = min(result["risk_score"] + 20, 100)
        result["reasons"].append("OTP request found in image text")

    if "verify" in extracted_lower:
        result["risk_score"] = min(result["risk_score"] + 10, 100)
        result["reasons"].append("Verification request found in image text")

    if "login" in extracted_lower:
        result["risk_score"] = min(result["risk_score"] + 10, 100)
        result["reasons"].append("Login request found in image text")

    score = result["risk_score"]

    if score >= 70:
        result["risk_level"] = "High"
        result["verdict"] = "Likely Phishing"
    elif score >= 40:
        result["risk_level"] = "Medium"
        result["verdict"] = "Suspicious"
    else:
        result["risk_level"] = "Low"
        result["verdict"] = "Probably Safe"

    result["reasons"] = list(set(result["reasons"]))

    result["email_info"] = {
        "sender": "",
        "reply_to": "",
        "subject": "Image OCR Scan",
        "sender_domain": sender_domain
    }

    result["extracted_text"] = extracted_text

    return result


@app.post("/scan-eml")
async def scan_eml(file: UploadFile = File(...)):
    content = await file.read()
    parsed = parse_eml(content)

    msg = parsed["msg"]
    full_text = parsed["full_text"]

    header_result = scan_headers(msg)
    sender_domain = header_result.get("sender_domain", "")

    text_result = scan_text(full_text)
    url_result = scan_urls(full_text, sender_domain)
    attachment_result = scan_attachments(msg)
    domain_result = scan_domain(sender_domain)

    result = calculate_risk(
        text_result,
        url_result,
        header_result,
        attachment_result,
        domain_result
    )

    result["email_info"] = {
        "sender": parsed["sender"],
        "reply_to": parsed["reply_to"],
        "subject": parsed["subject"],
        "sender_domain": sender_domain
    }

    return result
