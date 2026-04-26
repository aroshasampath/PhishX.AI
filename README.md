# 🛡️ PhishX.AI - Phishing Email Detection Platform

A user-friendly web-based platform to detect phishing emails using text, URLs, domains, headers, and screenshots.

---

## 🚀 Features

* 📄 **Email Text Scan**
  Analyze suspicious email content and get a risk report instantly.

* 🌐 **URL & Domain Detection**
  Identify malicious or suspicious links inside emails.

* 🖼️ **Image Scan (Screenshot Analysis)**
  Upload screenshots of emails and detect phishing attempts.

* 📊 **Simple Risk Report**
  Easy-to-understand results for non-technical users.

* 🔐 **Security Advice Section**
  Get actionable tips to stay safe from phishing attacks.

---

## 🛠️ Tech Stack

* **Backend:** Python (Flask/Django)
* **Frontend:** HTML, CSS
* **Other:** Machine Learning / Rule-based detection

---

## 📁 Project Structure

```
phishingmail/
│── app.py
│── scanner/
│── templates/
│── static/
│── uploads/
│── reports/
│── __pycache__/
│── venv/
```

---

## ⚙️ Installation

### 1. Clone the repository

```bash
git clone https://github.com/aroshasampath/PhishX.AI.git
cd phishingmail
```

### 2. Create virtual environment

```bash
python -m venv venv
source venv/bin/activate   # Linux
venv\Scripts\activate      # Windows
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Run the application

```bash
python app.py
```

---

## 🌐 Usage

1. Open browser and go to:

```
http://127.0.0.1:5000/
```

2. Choose:

* Text Scan
* Image Scan

3. Upload or paste suspicious content

4. View the generated risk report

---

## ⚠️ Security Notes

* Do not upload sensitive personal data
* This tool provides **assistance**, not guaranteed detection
* Always verify emails manually when in doubt

---

## 📌 Future Improvements

* AI-based phishing detection
* Real-time URL reputation API integration
* Email header deep analysis
* User authentication system

---

## 👨‍💻 Author

**Arosha Sampath**

---

## ⭐ Support

If you like this project, give it a ⭐ on GitHub!
