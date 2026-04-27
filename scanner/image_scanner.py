from PIL import Image
import pytesseract

from scanner.pro_scanner import analyze_email

def analyze_image_basic(image_path):
    reasons = []
    extracted_text = ""

    try:
        image = Image.open(image_path)
        extracted_text = pytesseract.image_to_string(image)
    except Exception as e:
        return {
            "risk": "Medium",
            "score": 45,
            "reasons": [
                "Image uploaded successfully",
                "OCR scan failed or Tesseract is not installed",
                "Install Tesseract OCR to enable screenshot text scanning"
            ],
            "urls": [],
            "total_urls": 0,
            "ocr_text": ""
        }

    if not extracted_text.strip():
        return {
            "risk": "Low",
            "score": 15,
            "reasons": [
                "Image uploaded successfully",
                "No readable text detected in screenshot"
            ],
            "urls": [],
            "total_urls": 0,
            "ocr_text": ""
        }

    result = analyze_email(text=extracted_text)
    result["ocr_text"] = extracted_text
    result["reasons"].insert(0, "OCR extracted text from uploaded image")

    return result
