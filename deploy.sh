#!/bin/bash
# Quick deploy to Raspberry Pi
# Usage: ./deploy.sh

PI_HOST="bjorn@bjorn.local"
REMOTE_DIR="/home/bjorn/Bjorn"

echo "Deploying to $PI_HOST..."

# Push local changes
git push origin main 2>/dev/null

# Pull on Pi and restart service
ssh $PI_HOST "cd $REMOTE_DIR && git pull && sudo systemctl restart bjorn.service"

echo "Waiting for Bjorn to start..."
sleep 5

# Check status
ssh $PI_HOST "sudo systemctl status bjorn.service --no-pager | head -8"
echo ""
echo "Deploy complete."
