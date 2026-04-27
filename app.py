import os
from flask import Flask, render_template, request, jsonify
from werkzeug.utils import secure_filename

from scanner.pro_scanner import analyze_email
from scanner.image_scanner import analyze_image_basic
from scanner.eml_parser import parse_eml_file

app = Flask(__name__)

UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER


@app.route("/")
def dashboard():
    return render_template("dashboard.html")


@app.route("/text-scan", methods=["GET", "POST"])
def text_scan():
    result = None

    if request.method == "POST":
        email_text = request.form.get("email_text", "")
        sender = request.form.get("sender", "")
        headers = request.form.get("headers", "")
        attachments_text = request.form.get("attachments", "")

        attachments = [
            item.strip()
            for item in attachments_text.split(",")
            if item.strip()
        ]

        result = analyze_email(
            text=email_text,
            sender=sender,
            headers=headers,
            attachments=attachments
        )

    return render_template("text_scan.html", result=result)


@app.route("/image-scan", methods=["GET", "POST"])
def image_scan():
    result = None
    filename = None
    error = None

    if request.method == "POST":
        file = request.files.get("image")

        if not file or file.filename == "":
            error = "Please select an image first."
        else:
            filename = secure_filename(file.filename)
            path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            file.save(path)

            result = analyze_image_basic(path)

    return render_template(
        "image_scan.html",
        result=result,
        filename=filename,
        error=error
    )


@app.route("/eml-scan", methods=["GET", "POST"])
def eml_scan():
    result = None
    filename = None
    error = None

    if request.method == "POST":
        file = request.files.get("eml_file")

        if not file or file.filename == "":
            error = "Please select an .eml file first."

        elif not file.filename.lower().endswith(".eml"):
            error = "Only .eml files are allowed."

        else:
            filename = secure_filename(file.filename)
            path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            file.save(path)

            try:
                parsed = parse_eml_file(path)

                result = analyze_email(
                    text=parsed.get("body", ""),
                    sender=parsed.get("sender", ""),
                    headers=parsed.get("headers", ""),
                    attachments=parsed.get("attachments", [])
                )

            except Exception as e:
                error = f"Failed to analyze EML file: {str(e)}"

    return render_template(
        "index.html",
        page="eml",
        result=result,
        filename=filename,
        error=error
    )


@app.route("/report")
def report():
    return render_template("index.html", page="report")


@app.route("/security-advice")
def security_advice():
    return render_template("security_advice.html")


@app.route("/api/scan", methods=["POST"])
def api_scan():
    data = request.get_json()

    if not data:
        return jsonify({"error": "No JSON data received"}), 400

    result = analyze_email(
        text=data.get("text", ""),
        sender=data.get("sender", ""),
        headers=data.get("headers", ""),
        attachments=data.get("attachments", [])
    )

    return jsonify(result)


if __name__ == "__main__":
    app.run(debug=True)
