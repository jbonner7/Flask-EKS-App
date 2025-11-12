#!/bin/bash
# ----------------------------------------------------------------
# SCRIPT 1: Deploy EKS Cluster and Configure OIDC
# ----------------------------------------------------------------
CLUSTER_NAME="scan-demo-cluster"
AWS_REGION="us-east-1"

echo "--- 1. Starting EKS Cluster Deployment (Takes 15-25 mins) ---"

# Check if cluster exists (Idempotency)
if aws eks describe-cluster --name "$CLUSTER_NAME" --region "$AWS_REGION" > /dev/null 2>&1; then
    echo "✅ SKIPPING: Cluster '$CLUSTER_NAME' already exists."
else
    # Create EKS Cluster (Blocking command)
    eksctl create cluster \
        --name "$CLUSTER_NAME" \
        --region "$AWS_REGION" \
        --version="1.28" \
        --nodegroup-name="worker-group" \
        --node-type="t3.medium" \
        --nodes=2 \
        --nodes-min=1 \
        --nodes-max=3
fi

# Associate OIDC Provider (Needed for IRSA)
echo "--- 2. Associating IAM OIDC Provider ---"
eksctl utils associate-iam-oidc-provider \
    --cluster "$CLUSTER_NAME" \
    --region "$AWS_REGION" \
    --approve

echo "--- 3. Configuring Local Kubeconfig ---"
aws eks update-kubeconfig \
    --name "$CLUSTER_NAME" \
    --region "$AWS_REGION"

echo "--- 4. Creating Application Namespace ---"
kubectl create namespace flask-app --dry-run=client -o yaml | kubectl apply -f -

echo "--- Script 1 Complete: Cluster is ready for configuration. ---"