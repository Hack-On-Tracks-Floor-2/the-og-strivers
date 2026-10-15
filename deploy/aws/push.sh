#!/usr/bin/env bash
# Deploys a git ref of this repo to the EC2 server. Run locally from the repo root:
#   bash deploy/aws/push.sh <server-ip> <path-to.pem> <frontend-origin> [git-ref]
# Uploads the committed code (git archive, no node_modules/.data) and the local .env (secrets stay
# out of git and are never printed), then runs setup.sh on the server.
# PUBLIC_DEMO=true bash deploy/aws/push.sh ...  also creates the demo developer (hackathon demo only).
set -euo pipefail
IP=${1:?server ip}
KEY=${2:?pem key}
ORIGIN=${3:?frontend origin, e.g. https://proofpatch.vercel.app}
REF=${4:-origin/main}
HOST="$(echo "$IP" | tr . -).sslip.io"   # free hostname that resolves to the IP, so Caddy can get HTTPS
SSH=(ssh -i "$KEY" -o StrictHostKeyChecking=accept-new "ubuntu@$IP")

tmp=$(mktemp -d)
git archive --format=tar.gz -o "$tmp/proofpatch.tar.gz" "$REF"
scp -i "$KEY" -o StrictHostKeyChecking=accept-new "$tmp/proofpatch.tar.gz" deploy/aws/setup.sh "ubuntu@$IP:/tmp/"
grep -v "^PUBLIC_DEMO=" .env > "$tmp/proofpatch.env"
[ "${PUBLIC_DEMO:-false}" = "true" ] && echo "PUBLIC_DEMO=true" >> "$tmp/proofpatch.env"
scp -i "$KEY" "$tmp/proofpatch.env" "ubuntu@$IP:/tmp/proofpatch.env"
rm -rf "$tmp"
"${SSH[@]}" "sudo bash /tmp/setup.sh $HOST $ORIGIN"
echo "Backend: https://$HOST/api/health"
