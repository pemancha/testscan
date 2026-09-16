#!/usr/bin/env python3
"""
VULNERABLE TEST BED - DO NOT RUN IN PRODUCTION
Contains intentional security flaws across multiple CWE categories for scanner benchmarking.
"""

import os
import sys
import pickle
import hashlib
import sqlite3
import subprocess
import urllib.request
import xml.etree.ElementTree as ET
from flask import Flask, request, render_template_string

app = Flask(__name__)

# CWE-798: Hardcoded Credentials / Sensitive Data in Source Code
DATABASE_PASSWORD = "SuperSecretPassword123!"
AWS_SECRET_KEY = "AKIAIOSFODNN7EXAMPLE"
API_JWT_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFkbWluIn0.signature"

# CWE-327 / CWE-328: Broken/Risky Cryptographic Algorithm & Weak Hashing
def hash_user_password(password: str) -> str:
    # Deprecated MD5 hashing without salt
    return hashlib.md5(password.encode()).hexdigest()

def check_sha1_fingerprint(data: str) -> str:
    # Weak SHA-1 usage
    return hashlib.sha1(data.encode()).hexdigest()

# CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')
@app.route("/eval", methods=["POST"])
def run_dynamic_code():
    code_input = request.form.get("code", "")
    # CWE-95 / CWE-94: Direct eval/exec of untrusted user input
    result = eval(code_input)
    return f"Execution Result: {result}"

# CWE-78: Improper Neutralization of Special Elements used in an OS Command ('Command Injection')
@app.route("/ping", methods=["GET"])
def network_ping():
    host = request.args.get("host", "127.0.0.1")
    # CWE-78: Shell=True with unsanitized string formatting
    cmd = f"ping -c 1 {host}"
    output = subprocess.check_output(cmd, shell=True)
    return output.decode()

# CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')
def get_user_record(user_id: str):
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    # CWE-89: Raw string formatting in SQL query
    query = f"SELECT * FROM users WHERE id = '{user_id}'"
    cursor.execute(query)
    return cursor.fetchall()

# CWE-502: Deserialization of Untrusted Data
@app.route("/deserialize", methods=["POST"])
def parse_object():
    raw_data = request.data
    # CWE-502: Unsafe Unpickling allowing remote code execution (RCE)
    unserialized_data = pickle.loads(raw_data)
    return f"Parsed Object: {unserialized_data}"

# CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')
@app.route("/read_file", methods=["GET"])
def get_file_content():
    filename = request.args.get("file", "")
    # CWE-22: Arbitrary file read without path normalization or boundary checking
    with open(f"/var/www/uploads/{filename}", "r") as f:
        return f.read()

# CWE-918: Server-Side Request Forgery (SSRF)
@app.route("/fetch_url", methods=["GET"])
def fetch_external_url():
    target_url = request.args.get("url", "")
    # CWE-918: Unvalidated outbound HTTP request to user-supplied endpoint
    response = urllib.request.urlopen(target_url)
    return response.read().decode()

# CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-Site Scripting')
@app.route("/greet", methods=["GET"])
def greet_user():
    name = request.args.get("name", "Guest")
    # CWE-79: Direct template string rendering without context encoding (Reflected XSS)
    template = f"<h1>Hello, {name}!</h1>"
    return render_template_string(template)

# CWE-611: Improper Restriction of XML External Entity Reference (XXE)
@app.route("/parse_xml", methods=["POST"])
def process_xml():
    xml_data = request.data
    # CWE-611: Standard ElementTree parser susceptible to XXE expansion
    parser = ET.XMLParser(target=ET.TreeBuilder())
    tree = ET.fromstring(xml_data, parser=parser)
    return f"Root Tag: {tree.tag}"

# CWE-330: Use of Insufficiently Random Values
def generate_session_token() -> int:
    import random
    # CWE-330: Standard pseudo-random number generator used for security-sensitive context
    return random.randint(100000, 999999)

# CWE-295: Improper Certificate Validation
def make_insecure_request(url: str):
    import ssl
    # CWE-295: Disabling SSL/TLS certificate verification
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return urllib.request.urlopen(url, context=ctx).read()

# CWE-319: Cleartext Transmission of Sensitive Information
def send_credentials_insecure(username, password):
    # CWE-319: Plain HTTP transfer over unencrypted channel
    endpoint = f"http://auth.internal.local/login?user={username}&pass={password}"
    return urllib.request.urlopen(endpoint).read()

if __name__ == "__main__":
    # CWE-489: Active Debug Flag in Production / CWE-1327: Binding to all interfaces
    app.run(host="0.0.0.0", port=5000, debug=True)
