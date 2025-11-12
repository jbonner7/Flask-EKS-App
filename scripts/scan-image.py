import subprocess
import json
import sys
from typing import List, Dict, Any

# --- Configuration (Define Output Files) ---
IMAGE_NAME = "python:3.9-slim"
SEVERITY_FILTER = ["Critical", "High"]

# File names for the two distinct outputs
SBOM_FILE_NAME = "sbom_raw.json"
VULN_FILE_NAME = "vulnerability_report.json"
SBOM_FILTERED_NAME = "sbom_filtered.json"
# ---------------------

def run_command(command: List[str], error_message: str) -> str:
    """Execute a shell command and return the raw stdout string."""
    print(f"Executing: {' '.join(command)}...")
    try:
        result = subprocess.run(
            command, 
            capture_output=True, 
            text=True, 
            check=True
        )
        return result.stdout # Return raw string output
    except subprocess.CalledProcessError as e:
        print(f"\n🚨 Error running command: {error_message}")
        print(f"Stdout:\n{e.stdout}")
        print(f"Stderr:\n{e.stderr}")
        sys.exit(1)

# Generate SBOM -------------------------------------------------------------------------------

def generate_sbom(image: str) -> Dict[str, Any]:
    """Generates an SBOM using Syft, saves the JSON result, and returns the dictionary."""
    print(f"Generating SBOM for {image} and saving to {SBOM_FILE_NAME}...")
    sbom_command = ["syft", image, "-o", "json"]
    
    raw_json_output = run_command_raw(sbom_command, f"Syft SBOM generation failed for {image}")

    # Write the raw output to a local file
    try:
        with open(SBOM_FILE_NAME, "w") as f:
            f.write(raw_json_output)
        print(f"✅ SBOM successfully saved to {SBOM_FILE_NAME}")
    except Exception as e:
        print(f"❌ Error writing SBOM file: {e}")
        sys.exit(1)

    # Parse the string and return the dictionary
    return json.loads(raw_json_output)

# Parse SBOM -------------------------------------------------------------------------------

def parse_sbom():
    """
    Parses the raw SBOM file using jq to extract package names and versions,
    saving the simplified output to a new file.
    """
    print(f"\nParsing raw SBOM ({SBOM_FILE_NAME}) and saving to {SBOM_FILTERED_NAME}...")
    
    # jq command to extract only name and version for each artifact
    jq_command = f"jq '.artifacts[] | {{name: .name, version: .version, type: .type, location: .location}}' {SBOM_FILE_NAME} > {SBOM_FILTERED_NAME}"
    
    try:
        # Use shell=True for robust input/output handling
        subprocess.run(
            jq_command,
            shell=True,
            check=True, 
            text=True, 
            capture_output=False, # Allow output to write directly to file (if modified)
            stderr=subprocess.PIPE
        )
        print(f"✅ Filtered SBOM saved to {SBOM_FILTERED_NAME}")
        
    except subprocess.CalledProcessError as e:
        print(f"\n🚨 Error running jq for SBOM parsing.")
        print(f"Stderr:\n{e.stderr}")
        sys.exit(1)

# Scan Image -------------------------------------------------------------------------------

def scan_image(image: str) -> Dict[str, Any]:
    """Scans the image using Grype, saves the raw JSON vulnerability report, and returns the parsed dictionary."""
    print(f"\nScanning image {image} and saving to {VULN_FILE_NAME}...")
    scan_command = ["grype", image, "-o", "json"]
    
    # 1. Run command and get raw JSON string
    raw_json_output = run_command_raw(scan_command, f"Grype scan failed for {image}")

    # 2. Write the raw output to a local file for hosting
    try:
        with open(VULN_FILE_NAME, "w") as f:
            f.write(raw_json_output)
        print(f"✅ Vulnerability Report saved to {VULN_FILE_NAME}")
    except Exception as e:
        print(f"❌ Error writing vulnerability report file: {e}")
        sys.exit(1)
        
    # 3. Parse the string into a dictionary and return it for filtering
    try:
        return json.loads(raw_json_output)
    except json.JSONDecodeError:
        print("\n🚨 Error: Failed to parse Grype JSON output for internal use.")
        sys.exit(1)

# Parse Vuln results -------------------------------------------------------------------------------

def parse_vulnerabilities(report_string: str, filter_levels: List[str]):
    """Parses the Grype JSON report (string) and filters for specified severity levels."""
    
    # Load the JSON string from the file read operation
    try:
        report_dict = json.loads(report_string)
    except json.JSONDecodeError:
        print("\n🚨 Error: Failed to parse Grype JSON output.")
        sys.exit(1)
        
    filtered_vulnerabilities = []
    
    # Grype JSON structure: we iterate over the 'matches' list
    for match in report_dict.get("matches", []):
        vulnerability = match.get("vulnerability", {})
        artifact = match.get("artifact", {})

        severity = vulnerability.get("severity")
        
        # Check if the vulnerability severity is in our filter list
        if severity and severity.upper() in [s.upper() for s in filter_levels]:
            
            # Extract key information for the readable output
            entry = {
                "Severity": severity,
                "CVE": vulnerability.get("id", "N/A"),
                "Package": artifact.get("name", "N/A"),
                "Version": artifact.get("version", "N/A"),
                "Fix_State": vulnerability.get("fix", {}).get("state", "No Fix Available"),
                "Fix_Versions": ", ".join(vulnerability.get("fix", {}).get("versions", [])),
                "Source": match.get("matchDetails", [{}])[0].get("matcher", "N/A"),
                "URL": vulnerability.get("dataSource", "N/A")
            }
            filtered_vulnerabilities.append(entry)

    return filtered_vulnerabilities

# Run Command Raw ------------------------------------------------------------------------

def run_command_raw(command: List[str], error_message: str) -> str:
    """Execute a shell command and return the raw stdout string."""
    print(f"Executing: {' '.join(command)}...")
    try:
        # Use subprocess.run to execute the command
        result = subprocess.run(
            command, 
            capture_output=True, 
            text=True, 
            check=True
        )
        # Return the raw string output
        return result.stdout 
    except subprocess.CalledProcessError as e:
        print(f"\n🚨 Error running command: {error_message}")
        print(f"Stdout:\n{e.stdout}")
        print(f"Stderr:\n{e.stderr}")
        sys.exit(1)

# Run main -------------------------------------------------------------------------------

def main():
    """Main execution function."""
    print(f"*** Scanning Docker Image: {IMAGE_NAME} ***")

    # Step 1: Generate and save raw SBOM
    generate_sbom(IMAGE_NAME)
    
    # Step 2: Filter the SBOM data
    parse_sbom()

    # Step 3: Scan image and save raw report (The function must still be called to generate the file)
    scan_image(IMAGE_NAME) 
    
    # Read the raw vulnerability report back from the disk file
    try:
        with open(VULN_FILE_NAME, "r") as f:
            raw_vuln_report_string = f.read()
    except FileNotFoundError:
        print(f"\n🚨 Error: Vulnerability report file '{VULN_FILE_NAME}' not found locally.")
        sys.exit(1)

    # Step 4: Parse and filter results using the file content string
    # We now pass the string directly to the fixed parsing function.
    filtered_results = parse_vulnerabilities(raw_vuln_report_string, SEVERITY_FILTER)
    
    # Step 5: Output the filtered results (Output logic is now correct)
    print("\n" + "="*50)
    print(f"🔥 Critical/High Vulnerability Report Summary for: {IMAGE_NAME}")
    print(f"   ({len(filtered_results)} total findings)")
    print("="*50)

    # Output the filtered list in JSON format
    output_json = json.dumps(filtered_results, indent=2)
    print(output_json)

if __name__ == "__main__":
    main()
