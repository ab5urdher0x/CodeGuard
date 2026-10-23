# Deploying CodeGuard

## A. AWS EC2 (primary)

1. Launch an instance: Ubuntu 22.04/24.04, `t3.medium`, 20 GB gp3.
2. Security group: inbound 22 from **your IP only**; 80 and 443 from `0.0.0.0/0`.
3. (Optional shortcut) paste `deploy/ec2-user-data.sh` as user data after setting `REPO_URL`, then skip to step 7.
4. Allocate an **Elastic IP** and associate it with the instance so the URL survives reboots.
5. SSH in and install Docker:
   ```bash
   sudo apt-get update && sudo apt-get install -y docker.io git
   sudo systemctl enable --now docker
   ```
6. Build and run (port 80 -> container 8000):
   ```bash
   git clone <REPO_URL> codeguard && cd codeguard
   sudo docker build -t codeguard .
   sudo docker run -d --name codeguard --restart unless-stopped -p 80:8000 codeguard
   ```
7. Smoke test (below) against `http://<ELASTIC_IP>`.

### Optional: HTTPS with Caddy + sslip.io
Use the host `<ELASTIC_IP with dashes>.sslip.io` (for example `203-0-113-10.sslip.io`; nip.io also works). Bind the app to localhost and let Caddy own 80/443:
```bash
sudo docker rm -f codeguard
sudo docker run -d --name codeguard --restart unless-stopped -p 127.0.0.1:8000:8000 codeguard
sudo apt-get install -y caddy
echo '203-0-113-10.sslip.io { reverse_proxy localhost:8000 }' | sudo tee /etc/caddy/Caddyfile
sudo systemctl restart caddy
```
Caddy obtains a Let's Encrypt certificate automatically. Use `https://203-0-113-10.sslip.io`.

## B. Fallback: Cloudflare quick tunnel from a laptop
```bash
.venv/bin/uvicorn app.main:app --port 8000        # or: docker run -p 8000:8000 codeguard
cloudflared tunnel --url http://localhost:8000     # prints https://<random>.trycloudflare.com
```
The URL changes on every run; keep the process alive for the whole evaluation window.

## Smoke test
```bash
BASE=http://<host>          # or https://...
curl -s $BASE/health
curl -s -X POST $BASE/evaluate -H 'Content-Type: application/json' \
  -d '{"code":"import requests\nrequests.get(\"http://169.254.169.254/latest/meta-data/\")"}'
```
Expect `{"status":"ok"}` and a JSON verdict with `verdict`, `risk_score`, `categories`, `code_language`, `reason`, `vulnerable_lines`. The demo UI is at `$BASE/`.
