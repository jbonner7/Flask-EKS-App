# ----------------------------------------------------------------
# SCRIPT 3: Deploy Application, Install CSI, and Run Scan (Python)
# ----------------------------------------------------------------
# This file requires all previously defined Python functions (run_command, 
# install_secrets_manager_csi_driver, create_irsa_role, etc.) to be defined above main().

import subprocess
import os
import sys
import time

# --- Configuration ---
CLUSTER_NAME = "scan-demo-cluster"
AWS_REGION = "us-east-1"
K8S_DEPLOY_DIR = "k8s_manifests" # Directory containing your .yaml files
IRSA_POLICY_NAME = "SecretsManagerReadOnlyFlask"

# --- URL Definitions  ---
# 1. CORE DRIVER: Official Kubernetes SIGs manifest
CORE_DRIVER_URL = "https://github.com/kubernetes-sigs/secrets-store-csi-driver/releases/download/v1.5.4/secrets-store-csi-driver.yaml"

# 2. --- HELM REPO SETUP FOR AWS PROVIDER ---
AWS_HELM_REPO_NAME = "aws-secrets-manager"
AWS_HELM_REPO_URL = "https://aws.github.io/secrets-store-csi-driver-provider-aws"
CHART_NAME = "secrets-store-csi-driver-provider-aws"

#### Execute shell -------------------------------------------------------

def run_command(command: list, error_message: str):
    """Execute a shell command with real-time output."""
    print(f"\nExecuting: {' '.join(command)}")
    try:
        # Popen allows for real-time streaming of stdout/stderr
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        for line in process.stdout:
            print(line, end='')
        
        return_code = process.wait()
        
        if return_code != 0:
            print(f"\n❌ FAILED: {error_message}")
            sys.exit(return_code)
        
        print(f"\n✅ SUCCESS: {error_message}")
        
    except FileNotFoundError:
        print(f"❌ Error: Required tool not found. Check if {command[0]} is installed and in PATH.")
        sys.exit(1)

#### Initial Setup -------------------------------------------------------

def initial_setup():
    """Reads the Node Role ARN from the environment and attaches the ECR Policy."""
    
    NODE_ROLE_ARN = os.environ.get("VERIFIED_NODE_ROLE_ARN")
    ECR_POLICY_ARN = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"

    if not NODE_ROLE_ARN:
        print("\n❌ FATAL ERROR: VERIFIED_NODE_ROLE_ARN environment variable is not set.")
        print("Please run Script 2 manually to retrieve the ARN, set the variable, and re-run.")
        sys.exit(1)

    role_name = NODE_ROLE_ARN.split('/')[-1]
    
    # Attach the ECR Policy (This uses the same reliable logic as before)
    attach_command = [
        "aws", "iam", "attach-role-policy",
        "--role-name", role_name,
        "--policy-arn", ECR_POLICY_ARN
    ]
    
    # We use a try/except block to skip if the policy is already attached
    try:
        run_command(attach_command, f"Attaching {ECR_POLICY_ARN} to Node Instance Role: {role_name}")
    except SystemExit as e:
        if "already exists" in str(e):
            print(f"✅ SKIPPED: Policy already attached.")
        else:
            raise

#### Deploy Flask App -------------------------------------------------------

def deploy_k8s_app():
    """Applies all Kubernetes manifests from the defined directory."""
    print(f"\nApplying Kubernetes manifests from /{K8S_DEPLOY_DIR}...")
    
    # Use kubectl to apply all manifests in the directory
    deploy_command = ["kubectl", "apply", "-f", K8S_DEPLOY_DIR]
    run_command(deploy_command, "Kubernetes deployment")

#### Get Load Balancer -------------------------------------------------------

def get_load_balancer_endpoint():
    """Waits for and prints the Load Balancer DNS name."""
    print("\nWaiting for Load Balancer DNS name (may take a few minutes)...")
    
    for i in range(10): # Try up to 10 times (approx 50 seconds)
        # Use kubectl to get the service endpoint
        command = [
            "kubectl", "get", "svc", "flask-report-service", 
            "-n", "flask-app",
            "-o", "jsonpath='{.status.loadBalancer.ingress[0].hostname}'"
        ]
        try:
            endpoint = subprocess.check_output(command, text=True).strip().strip("'")
            if "hostname" in endpoint or "." in endpoint:
                print(f"\n✨ Load Balancer Endpoint: **http://{endpoint}**")
                print(f"⚠️ Access is restricted by the security group firewall.")
                return endpoint
        except:
            pass # Keep trying if the output isn't ready
        
        time.sleep(5)
    
    print("\n❌ Timed out waiting for Load Balancer endpoint.")
    return None

#### Get AWS Details -------------------------------------------------------

def get_aws_account_id():
    """Retrieves the current AWS Account ID dynamically."""
    # (Implementation for getting Account ID remains the same)
    try:
        account_id = subprocess.check_output(
            ["aws", "sts", "get-caller-identity", "--query", "Account", "--output", "text"],
            text=True
        ).strip()
        if not account_id.isdigit() or len(account_id) != 12:
            raise ValueError("Invalid Account ID format received.")
        return account_id
    except Exception as e:
        print(f"❌ Error retrieving AWS Account ID. Is the AWS CLI configured? Error: {e}")
        sys.exit(1)

#### Install CSI Driver -------------------------------------------------------

def install_secrets_manager_csi_driver():
    """Installs the Secrets Store CSI Driver and the AWS Provider via kubectl apply."""
    
    # ⚠️ Create the Service Account first
    #run_command(["kubectl", "create", "sa", "secrets-store-csi-driver", "-n", "kube-system"], "Creating CSI Driver Service Account")

    print("\n--- Phase: Installing CSI Secrets Driver ---")

    # 1. Install the Core Secrets Store CSI Driver (via YAML)
    run_command(["kubectl", "apply", "-f", CORE_DRIVER_URL], "Installing Core Secrets Store CSI Driver")

    # FORCE RBAC CREATION
    # This ensures the ClusterRoles and Bindings are guaranteed to be created 
    # even if the initial apply failed to create them.
    run_command(["kubectl", "apply", "-f", CORE_DRIVER_URL], "Forcing RBAC Creation for CSI Driver")

    # 2. Force delete the Service Account created by the YAML apply. 
    # Do this so Helm can create its own, owned version.
    run_command(["kubectl", "delete", "sa", "secrets-store-csi-driver", "-n", "kube-system", "--ignore-not-found"], 
                "Cleaning up conflicting CSI Driver Service Account")
    
    # 3. Add the AWS Provider Helm Repository
    run_command(["helm", "repo", "add", AWS_HELM_REPO_NAME, AWS_HELM_REPO_URL], "Adding AWS Helm Repository")
    
    # 4. Update the Helm Repository (fetch latest chart list)
    run_command(["helm", "repo", "update"], "Updating Helm Repository")

    # 5. Install the AWS Provider Plugin (via Helm)
    run_command(
        ["helm", "install", "secrets-provider-aws", f"{AWS_HELM_REPO_NAME}/{CHART_NAME}", "-n", "kube-system"],
        "Installing AWS Secrets Manager Provider (via Helm)"
    )

    # Wait for the CSI driver pods to become ready 
    print("Waiting for CSI driver components to become ready (up to 90s)...")
    time.sleep(10)
    
    # Wait for the core driver pods (DaemonSet)
    run_command(
    ["kubectl", "wait", "--for=condition=ready", 
     # Wait for all Pods with the label app=csi-secrets-store to be ready
     "pods", "-l", "app=csi-secrets-store", 
     "-n", "kube-system", "--timeout=120s"], # Increased timeout for safety
    "Waiting for CSI Driver Pods to stabilize"
)

#### Create IRSA Role -------------------------------------------------------

def create_irsa_role():
    """
    Dynamically creates the IAM Role for the Service Account (IRSA).
    """
    account_id = get_aws_account_id()
    
    # 🎯 Dynamically construct the policy ARN using the Policy Name and Account ID
    secrets_policy_arn = f"arn:aws:iam::{account_id}:policy/{IRSA_POLICY_NAME}"
    
    SA_NAME = "flask-auth-sa"
    SA_NAMESPACE = "flask-app"

    command = [
        "eksctl", "create", "iamserviceaccount",
        "--name", SA_NAME,
        "--namespace", SA_NAMESPACE,
        "--cluster", CLUSTER_NAME,
        "--region", AWS_REGION,
        
        # Dynamic policy attachment 1 (Secrets Manager)
        "--attach-policy-arn", secrets_policy_arn, 
        
        # Static policy attachment 2 (ECR Read)
        "--attach-policy-arn", "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly",
        
        "--override-existing-serviceaccounts",
        "--approve"
    ]
    
    run_command(command, "Creating IAM Role for Service Account (IRSA)")

    # 2. Retrieve the ARN of the created role
    # This command uses eksctl get iamserviceaccount and jq to reliably extract the ARN
    arn_command = [
        "eksctl", "get", "iamserviceaccount",
        "--name", SA_NAME,
        "--namespace", SA_NAMESPACE,
        "--cluster", CLUSTER_NAME,
        "--region", AWS_REGION,
        "-o", "json"
    ]

    try:
        result = subprocess.run(arn_command, capture_output=True, text=True, check=True)
        # Use jq to parse the JSON and get the role ARN
        # The output of eksctl get iamserviceaccount is a list of objects
        role_arn = subprocess.check_output(
            ["jq", "-r", ".[0].status.roleARN"], 
            input=result.stdout, 
            text=True
        ).strip()
        
        if not role_arn or "arn:aws:iam" not in role_arn:
            raise ValueError("Failed to extract valid IAM Role ARN.")
        
        print(f"✅ Successfully extracted IAM Role ARN: **{role_arn}**")
        return role_arn

    except Exception as e:
        print(f"❌ Error retrieving ARN: {e}")
        sys.exit(1)


#### Update IRSA Manifest -------------------------------------------------------

def update_irsa_manifest(role_arn: str):
    """Reads the IRSA config file and injects the dynamically generated IAM Role ARN."""
    
    # 1. Define the manifest path
    K8S_DEPLOY_DIR = "k8s_manifests" # Assuming this is defined globally
    config_path = os.path.join(K8S_DEPLOY_DIR, "irsa-config.yaml")
    
    # 2. Define the exact strings for replacement
    PLACEHOLDER = "<IRSA_ROLE_ARN_PLACEHOLDER>"
    
    # --- Read, Replace, and Write ---
    
    try:
        with open(config_path, 'r') as f:
            content = f.read()
    except FileNotFoundError:
        print(f"❌ Error: Manifest file not found at {config_path}")
        return

    # Only proceed with replacement if the placeholder exists.
    if PLACEHOLDER in content:
        updated_content = content.replace(PLACEHOLDER, role_arn)
        
        # Overwrite the file with the updated content
        try:
            with open(config_path, 'w') as f:
                f.write(updated_content)
            print(f"✅ Injected IAM Role ARN into {config_path}")
        except Exception as e:
            print(f"❌ Error writing to manifest file: {e}")
            
    else:
        # If the placeholder is gone, assume the ARN is already injected.
        print(f"✅ SKIPPED: ARN already injected into {config_path}.")

#### Scan Image and Save Results to Flask App -------------------------------------------------------

def run_scan_and_capture():
    """Executes scan-image.py and captures stdout."""
    
    # Define the command as a single string
    scan_command = "python3 scan-image.py"
    
    print(f"\nExecuting: {scan_command} (Generating two files)...")
    
    try:
        # Pass the command string AND set shell=True
        result = subprocess.run(
            scan_command, 
            check=True, 
            text=True, 
            capture_output=True, 
            shell=True # CRITICAL: Executes the command via the shell
        )
        
    except subprocess.CalledProcessError as e:
        print(f"\n❌ FAILED: Scan failed.")
        print(f"Stdout:\n{e.stdout}")
        print(f"Stderr:\n{e.stderr}")
        sys.exit(1)

#### Copy Results to Flask App -------------------------------------------------------

def execute_scan_and_copy():
    """
    Runs scan, retrieves the Pod name, and streams both the SBOM and 
    Vulnerability files to the container's writable volume.
    """
    # Define the two files generated by scan-image.py and their destination paths
    FILES_TO_TRANSFER = {
        "sbom_filtered.json": "/app/scan_file/sbom_raw.json",
        "vulnerability_report.json": "/app/scan_file/vulnerability_report.json"
    }

    print("\n--- Phase: Execute Scan and Copy Data ---")

    # 1. Run the local scan script (Generates two local files)
    run_scan_and_capture()

    # 2. Get the Pod Name (Logic remains the same)
    try:
        # ... Pod name retrieval logic ...
        pod_name_command = ["kubectl", "get", "pods", "-n", "flask-app", "-l", "app=flask-report", "-o", "jsonpath={.items[0].metadata.name}"]
        pod_name = subprocess.check_output(pod_name_command, text=True).strip()
        if not pod_name:
            raise Exception("Pod name not retrieved.")
    except Exception as e:
        print(f"❌ FAILED: Could not find target Pod name. {e}")
        sys.exit(1)

    # 3. Execute the Streaming Transfer for BOTH files
    for local_file, container_path in FILES_TO_TRANSFER.items():
        try:
            with open(local_file, 'rb') as f:
                file_data = f.read()

            # The streaming command is complex but necessary to bypass kubectl cp
            stream_command = [
                "kubectl", "exec", "-i", "-n", "flask-app", pod_name, "--",
                "sh", "-c", f"cat > {container_path}"
            ]
            
            print(f"Transferring {local_file} via stream to Pod {pod_name}...")

            # Use subprocess.run to manage the streaming of file_data directly to stdin
            subprocess.run(stream_command, input=file_data, check=True, text=False)
            print(f"✅ SUCCESS: {local_file} transfer complete.")
            
        except FileNotFoundError:
            print(f"\n❌ FAILED: Local file '{local_file}' not found. Check scan-image.py output.")
            sys.exit(1)
        except subprocess.CalledProcessError as e:
            # This captures the permission denied error if it still occurs
            print(f"\n❌ FAILED: Streaming {local_file} failed with exit code {e.returncode}.")
            print(f"Stderr: {e.stderr}")
            sys.exit(1)
            
    print("🎉 Final Project Step Complete: Both reports are available on the Flask endpoints!")

#### Main -------------------------------------------------------

def main():
    print("--- Phase: Installing CSI Driver and IRSA ---")

    # 1: Run manual setup logic
    initial_setup()

    # 2. INSTALL CSI DRIVER (Includes Service Account creation, Core Driver, and AWS Provider)
    install_secrets_manager_csi_driver() # Now uses fixed URLs and Helm

    # 3. CREATE IRSA Role (Creates Role/ServiceAccount and gets ARN)
    iam_role_arn = create_irsa_role() 
    
    # 4. DYNAMICALLY UPDATE MANIFEST (Injects ARN into irsa-config.yaml)
    update_irsa_manifest(iam_role_arn) 

    # 5. DEPLOY KUBERNETES APP (Deploys manifests: Deployment, Service, NetworkPolicy)
    deploy_k8s_app()
    
    # 6. Retrieve Load Balancer Endpoint
    get_load_balancer_endpoint()
    
    # 7. EXECUTE SCAN AND COPY (Runs syft/grype and kubectl cp)
    execute_scan_and_copy()

    print("--- Script 3 Complete: Application is live and report is transferred. ---")

if __name__ == "__main__":
    main()