from PIL import Image
import pytesseract
import cv2
import numpy as np

def preprocess_image(image_path):
    image = cv2.imread(image_path)

    # grayscale
    gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)

    # noise removal
    gray = cv2.medianBlur(gray, 3)

    # threshold
    _, thresh = cv2.threshold(gray, 150, 255, cv2.THRESH_BINARY)

    return thresh

def extract_text_from_image(image_path):
    try:
        processed = preprocess_image(image_path)

        text = pytesseract.image_to_string(
            processed,
            config='--oem 3 --psm 6'
        )

        return text
    except Exception as e:
        return f"OCR_ERROR: {str(e)}"
