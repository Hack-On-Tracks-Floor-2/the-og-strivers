#!/usr/bin/env bash
# One-time (and re-runnable) setup of the ProofPatch API on the Ubuntu 24.04 Azure VM.
# Run on the server:  sudo bash setup.sh <public-hostname> <frontend-origin>
#   e.g.            sudo bash setup.sh 13-201-5-7.sslip.io https://proofpatch.vercel.app
# Expects /tmp/proofpatch.tar.gz (code) and /tmp/proofpatch.env (secrets) uploaded by push.sh.
set -euo pipefail
HOST=${1:?public hostname}
ORIGIN=${2:?frontend origin (https://...)}
APP=/opt/proofpatch
USER_NAME=proofpatch

# 1. Packages: Docker (sandbox), Node 22, Python (ast-only helpers), Caddy (HTTPS).
if ! command -v docker >/dev/null; then
  apt-get update -y
  apt-get install -y ca-certificates curl gnupg git python3 debian-keyring debian-archive-keyring apt-transport-https
  curl -fsSL https://get.docker.com | sh
fi
if ! command -v node >/dev/null || ! node -v | grep -q '^v22'; then
  curl -fsSL https://deb.nodesource.com/setup_22.x | bash -
  apt-get install -y nodejs
fi
if ! command -v caddy >/dev/null; then
  curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
  curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' > /etc/apt/sources.list.d/caddy-stable.list
  apt-get update -y && apt-get install -y caddy
fi
# The saved mini classifier uses an isolated Python environment on this same backend.
if ! python3 -c 'import venv, ensurepip' >/dev/null 2>&1; then
  apt-get update -y
  apt-get install -y python3-venv
fi
python3 -c 'import sys; assert sys.version_info[:2] == (3, 12), "The saved classifier requires Python 3.12."'

# 2. Service user (can start sandbox containers, nothing else).
id "$USER_NAME" >/dev/null 2>&1 || useradd --system --create-home --shell /usr/sbin/nologin "$USER_NAME"
usermod -aG docker "$USER_NAME"

# 3. Code + build. The database and work dirs live in $APP/.data and survive redeploys.
mkdir -p "$APP"
find "$APP" -mindepth 1 -maxdepth 1 ! -name .data ! -name .env -exec rm -rf {} +
tar -xzf /tmp/proofpatch.tar.gz -C "$APP"
install -m 600 /tmp/proofpatch.env "$APP/.env"
rm -f /tmp/proofpatch.env
# Production settings override whatever the uploaded .env had.
sed -i -E '/^(NODE_ENV|APP_ORIGIN|API_PORT|PORT|DOCKER_BIN|DETECTOR_[A-Z_]+|HF_HOME|REVIEWER_DEMO_ENABLED|MINI_ML_PYTHON)=/d' "$APP/.env"
cat >> "$APP/.env" <<EOF
NODE_ENV=production
APP_ORIGIN=$ORIGIN
API_PORT=3001
DOCKER_BIN=docker
PYTHON_BIN=python3
MINI_ML_PYTHON=$APP/ml/mini_classifier/.venv/bin/python3
REVIEWER_DEMO_ENABLED=false
EOF
chown -R "$USER_NAME:$USER_NAME" "$APP"
cd "$APP"
ML_PYTHON="$APP/ml/mini_classifier/.venv/bin/python3"
sudo -u "$USER_NAME" python3 -m venv "$APP/ml/mini_classifier/.venv"
sudo -u "$USER_NAME" "$ML_PYTHON" -m pip --disable-pip-version-check install --only-binary=:all: -r ml/mini_classifier/requirements.txt
# Verify the committed artifact hashes and perform real inference before restarting the API.
sudo -u "$USER_NAME" env OMP_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1 "$ML_PYTHON" ml/mini_classifier/predict.py --file ml/mini_classifier/artifacts/heldout-example.java --language java
sudo -u "$USER_NAME" npm ci --no-audit --no-fund
sudo -u "$USER_NAME" npm run build -w @proofpatch/shared
sudo -u "$USER_NAME" npm run build -w @proofpatch/api
docker build -t proofpatch-runner:py312 docker/runner

# 4. API as a service (restarts on crash and on reboot).
cat > /etc/systemd/system/proofpatch-api.service <<EOF
[Unit]
Description=ProofPatch API
After=network-online.target docker.service
Requires=docker.service

[Service]
User=$USER_NAME
WorkingDirectory=$APP/apps/api
ExecStart=/usr/bin/node dist/apps/api/src/server.js
Restart=always
RestartSec=3
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable proofpatch-api
systemctl restart proofpatch-api

# 5. HTTPS reverse proxy (Let's Encrypt certificate is automatic). Only /api is exposed.
cat > /etc/caddy/Caddyfile <<EOF
$HOST {
  handle /api/* {
    reverse_proxy 127.0.0.1:3001
  }
  handle {
    respond "ProofPatch API" 200
  }
}
EOF
systemctl restart caddy

sleep 4
systemctl --no-pager --lines=5 status proofpatch-api || true
curl -fsS "http://127.0.0.1:3001/api/health" && echo && echo "API up. Public: https://$HOST/api/health"
