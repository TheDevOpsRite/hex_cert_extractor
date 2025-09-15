#!/usr/bin/env python3
"""
Simple Flask backend to extract certificate bytes (and derived hex keys)
from an uploaded APK (META-INF/*.RSA|*.DSA|*.EC).

POST /extract-cert
  - form file field name: 'apk' (required)
Response JSON:
  {
    "cert_name": "META-INF/CERT.RSA",
    "cert_len": 1234,
    "first16_hex": "0123abcd...",
    "md5_hex": "a1b2c3...",
    "sha1_hex": "deadbeef...",
    "sha1_first16_hex": "...",
    "sha256_hex": "...",
    "sha256_first16_hex": "...",
    "full_cert_hex_preview": "0123ab... (first 64 bytes shown)"
  }
"""
import binascii
import hashlib
from flask import Flask, request, jsonify
from zipfile import ZipFile
from io import BytesIO
from flasgger import Swagger
from flask_cors import CORS

app = Flask(__name__)
# Enable CORS for all routes (adjust origins as needed)
CORS(app, resources={r"/extract-cert": {"origins": "https://hex-cert-extractor.vercel.app/"}})
swagger = Swagger(app)

# Maximum upload size (20 MB default)
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024


def find_cert_in_apk(apk_bytes: bytes):
    """
    Return (cert_name, cert_bytes) for the first META-INF/*.RSA|*.DSA|*.EC entry
    found in the APK zip. Returns (None, None) if none found.
    """
    with ZipFile(BytesIO(apk_bytes)) as z:
        names = z.namelist()
        cand = [n for n in names if n.upper().startswith("META-INF/")]
        sigs = [n for n in cand if n.upper().endswith((".RSA", ".DSA", ".EC"))]
        if not sigs:
            return None, None
        # prefer RSA > DSA > EC
        sigs.sort(key=lambda n: (0 if n.upper().endswith(".RSA") else 1, n))
        name = sigs[0]
        return name, z.read(name)


def hex_preview(b: bytes, length=64):
    return binascii.hexlify(b[:length]).decode()


@app.route("/extract-cert", methods=["POST"])
def extract_cert():
    """
    Upload APK and extract cert
    ---
    consumes:
      - multipart/form-data
    parameters:
      - in: formData
        name: apk
        type: file
        required: true
        description: The APK file to analyze
    responses:
      200:
        description: Extraction result
        schema:
          type: object
          properties:
            cert_name:
              type: string
            cert_len:
              type: integer
            first16_hex:
              type: string
            md5_hex:
              type: string
            sha1_hex:
              type: string
            sha1_first16_hex:
              type: string
            sha256_hex:
              type: string
            sha256_first16_hex:
              type: string
            full_cert_hex_preview:
              type: string
    """
    if "apk" not in request.files:
        return jsonify({"error": "missing file field 'apk'"}), 400

    try:
        apk_bytes = request.files["apk"].read()
    except Exception as e:
        return jsonify({"error": f"failed to read uploaded file: {str(e)}"}), 400

    cert_name, cert_bytes = find_cert_in_apk(apk_bytes)
    if cert_name is None:
        return jsonify({"error": "no certificate signature file found in APK"}), 400

    out = {
        "cert_name": cert_name,
        "cert_len": len(cert_bytes),
        "first16_hex": binascii.hexlify(cert_bytes[:16]).decode()
        if len(cert_bytes) >= 16
        else None,
        "md5_hex": binascii.hexlify(hashlib.md5(cert_bytes).digest()).decode(),
        "sha1_hex": binascii.hexlify(hashlib.sha1(cert_bytes).digest()).decode(),
        "sha1_first16_hex": binascii.hexlify(
            hashlib.sha1(cert_bytes).digest()[:16]
        ).decode(),
        "sha256_hex": binascii.hexlify(
            hashlib.sha256(cert_bytes).digest()
        ).decode(),
        "sha256_first16_hex": binascii.hexlify(
            hashlib.sha256(cert_bytes).digest()[:16]
        ).decode(),
        "full_cert_hex_preview": hex_preview(cert_bytes, 64),
        "has_16_bytes": len(cert_bytes) >= 16,
        "note": (
            "This returns the first certificate signature file inside the APK "
            "(e.g., META-INF/*.RSA). Common decryptors use the first 16 bytes "
            "as the AES key; md5/sha1/sha256 derivations are provided too."
        ),
    }
    return jsonify(out), 200


@app.route("/", methods=["GET"])
def index():
    return jsonify(
        {"info": "APK cert extractor. POST form-file 'apk' to /extract-cert"}
    ), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
