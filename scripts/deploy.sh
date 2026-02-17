#!/bin/bash
set -e

echo "=== Private Code Reviewer — EigenCompute Deployment ==="
echo ""

# 1. Install ecloud CLI if not present
if ! command -v ecloud &> /dev/null; then
  echo "[1/5] Installing ecloud CLI..."
  npm install -g @layr-labs/ecloud-cli
else
  echo "[1/5] ecloud CLI already installed"
fi

# 2. Authenticate
echo "[2/5] Authenticating with EigenCompute..."
if ! ecloud auth login 2>/dev/null; then
  echo "  Generating new auth keypair..."
  ecloud auth generate --store
fi

# 3. Subscribe to billing (first-time gets $100 credit)
echo "[3/5] Checking billing subscription..."
ecloud billing subscribe 2>/dev/null || echo "  Already subscribed or subscription updated"

# 4. Build Docker image
echo "[4/5] Building Docker image (linux/amd64 for TEE)..."
docker build --platform linux/amd64 -t private-code-reviewer .

# 5. Deploy to EigenCompute TEE
echo "[5/5] Deploying to EigenCompute TEE..."
ecloud compute app deploy

echo ""
echo "=== Deployment complete! ==="
echo ""
echo "Run 'ecloud compute app info' to get your app URL"
echo "Run 'ecloud compute app logs' to view logs"
