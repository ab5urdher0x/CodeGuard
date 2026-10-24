#!/bin/bash
# cloud-init user-data for Ubuntu 22.04/24.04. Edit REPO_URL (and BRANCH) before use.
set -euxo pipefail
REPO_URL="https://github.com/YOUR_ORG/CodeGuard.git"   # placeholder
BRANCH="main"

export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y docker.io git
systemctl enable --now docker

rm -rf /opt/codeguard
git clone --depth 1 --branch "$BRANCH" "$REPO_URL" /opt/codeguard
cd /opt/codeguard
docker build -t codeguard .
docker rm -f codeguard 2>/dev/null || true
docker run -d --name codeguard --restart unless-stopped -p 80:8000 codeguard
