import os
import sys
from flask import Flask, jsonify, send_file
from flask_httpauth import HTTPBasicAuth
from werkzeug.security import check_password_hash

app = Flask(__name__)
auth = HTTPBasicAuth()

# --- Configuration ---
# The base path where the Secret Provider Class mounts the files
SECRET_BASE_PATH = "/mnt/secrets/flask-auth-creds" 
SBOM_PATH = "/app/scan_file/sbom_raw.json"
VULN_PATH = "/app/scan_file/vulnerability_report.json"
# ---------------------

def read_secret_file(filename: str) -> str:
    """Safely reads the content of a mounted secret file."""
    try:
        with open(os.path.join(SECRET_BASE_PATH, filename), 'r') as f:
            # .strip() is crucial to remove any trailing newline character
            return f.read().strip()
    except Exception as e:
        print(f"Error reading secret file {filename}: {e}", file=sys.stderr)
        # Log and exit or return an error state if security credentials can't be read
        return "" 

@auth.verify_password
def verify_password(username, password):
    """
    Reads credentials from the mounted files and verifies them.
    This function executes on every request that requires authentication.
    """
    # 1. Read the credentials from the files mounted by the CSI driver
    # The filenames are based on the 'objectAlias' fields in the SecretProviderClass YAML
    expected_username = read_secret_file("username")
    expected_password_hash = read_secret_file("password_hash")
    
    if not expected_username or not expected_password_hash:
        # Fails closed if the secret can't be read
        return None 

    # 2. Check the provided username and hash
    if username == expected_username and \
       check_password_hash(expected_password_hash, password):
        return username

    return None

@app.route('/health', methods=['GET'])
def health_check():
    """
    Returns a simple success status for Kubernetes probes.
    This check ensures the application process is running and responsive.
    """
    # For a simple check, return a JSON status and an HTTP 200 OK code.
    return jsonify({"status": "ok"}), 200

# 1. New Route for SBOM Data
@app.route('/sbom-report', methods=['GET'])
@auth.login_required 
def get_sbom_report():
    if os.path.exists(SBOM_PATH):
        # Serves the raw SBOM JSON
        return send_file(SBOM_PATH, as_attachment=False, mimetype='application/json')
    else:
        return jsonify({"error": "SBOM report not found."}), 404

# 2. Updated Route for Vulnerability Data (Current /scan-report logic)
@app.route('/vulnerability-report', methods=['GET'])
@auth.login_required 
def get_vulnerability_report():
    if os.path.exists(VULN_PATH):
        # Serves the vulnerability report JSON
        return send_file(VULN_PATH, as_attachment=False, mimetype='application/json')
    else:
        return jsonify({"error": "Vulnerability report not found."}), 404
