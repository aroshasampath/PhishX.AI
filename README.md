
# 🛡️ PhishX.AI – AI-Powered Phishing Detection Platform

PhishX.AI is a cybersecurity-focused phishing detection system that analyzes emails, URLs, domains, attachments, and screenshots using rule-based intelligence + AI-style heuristics.

---

## 🚀 Features

### 🧠 Email Analysis Engine
- Phishing keyword & phrase detection  
- Sensitive data request detection (password, OTP, card info)  
- Urgency / pressure tactic detection  
- OCR-aware fuzzy text detection (handles misspellings)

### 🌐 URL Intelligence
- URL extraction  
- URL shortener detection  
- Suspicious TLD detection  
- Lookalike domain detection (e.g. micr0soft)  
- Sender vs link domain mismatch  

### 🌍 Domain Intelligence
- DNS resolution check  
- Brand spoofing detection  
- Punycode / Unicode attack detection  

### 📧 Email Header Analysis
- SPF / DKIM / DMARC fail detection  
- Mail relay chain analysis  
- Reply-To vs From mismatch detection  

### 📎 Attachment Scanner
- Dangerous file detection (.exe, .bat, etc.)  
- Macro-enabled files (.docm, .xlsm)  
- Double extension attacks  

### 🤖 AI Detection Layer
- Pattern-based phishing classifier  
- Fuzzy OCR-aware detection  
- Combined AI + rule-based scoring  

### 🖼 Image Phishing Detection
- Screenshot upload  
- OCR text extraction (Tesseract)  
- Image → text → phishing analysis  

### 📂 EML File Analysis
- Full email parsing  
- Attachments + headers + body analysis  
- AI-based phishing detection  

### 📊 Risk Engine
- Score: 0–100  
- Classification:
  - Low  
  - Medium  
  - High  
- Detailed reason-based reporting  

### 🌐 API Support
POST /api/scan

---

## 🖥️ Dashboard Pages

- Dashboard  
- Email Text Scan  
- Image Scan (OCR)  
- Threat Report  
- EML AI Scan  
- Security Advice  

---

## 🛠️ Tech Stack

- Backend: Flask (Python)  
- AI Logic: Rule-based + heuristic scoring  
- OCR: Tesseract  
- Frontend: HTML + CSS  

---

## ⚙️ Installation

```bash
git clone https://github.com/aroshasampath/PhishX.AI.git
cd PhishX.AI
```

### Install dependencies

```bash
pip install -r requirements.txt
```

### Install Tesseract (Linux)

```bash
sudo apt install tesseract-ocr
```

---

## ▶️ Run the Application

```bash
python app.py
```

Open in browser:

```
http://127.0.0.1:5000
```

---

## 🧪 Sample Test

```
URGENT! Your account has been suspended.

Verify your account immediately:
http://paypal-security-login.xyz

Enter your password and OTP.
```

Expected Result: High Risk

---

## 📡 API Usage

```bash
curl -X POST http://127.0.0.1:5000/api/scan \
-H "Content-Type: application/json" \
-d '{
  "text": "Your account is at risk. Verify now.",
  "sender": "paypal.com"
}'
```

---

## 🔮 Future Improvements

- Machine Learning model  
- VirusTotal integration  
- User login system  
- Scan history  
- PDF report export  
- Cloud deployment  

---

## ⚠️ Disclaimer

This tool is for educational and defensive cybersecurity purposes only.

---

## 👨‍💻 Author

Arosha Sampath Premathilaka
