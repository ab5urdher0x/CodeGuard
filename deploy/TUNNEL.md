# Cloudflare Quick Tunnel , backup public endpoint

A free, instant HTTPS URL that forwards to the local CodeGuard server. No account.
**Ephemeral**: the URL changes every restart and the tunnel must stay running on this
machine. Good as a judging *backup*; use EC2 for a durable endpoint.

## Start (two terminals, keep both open)

```bash
# Terminal 1 , the API (stable: no --reload, 2 workers)
cd ~/CodeGuard
CODEGUARD_USE_ML=0 .venv/bin/python -m uvicorn app.main:app --host 127.0.0.1 --port 8777 --workers 2

# Terminal 2 , the tunnel (prints the https://<name>.trycloudflare.com URL)
cd ~/CodeGuard
./bin/cloudflared tunnel --url http://localhost:8777 --no-autoupdate
```

Copy the `https://….trycloudflare.com` line it prints , that's the public URL.

## Verify
```bash
U=https://<name>.trycloudflare.com
curl -s $U/health
curl -s -X POST $U/evaluate -H 'content-type: application/json' -d '{"code":"eval(input())"}'
```

## Keep it running / restart
- Both processes must stay alive (don't close the terminals / don't suspend the laptop).
- To survive terminal close, prefix each with `nohup ... &` or run under `tmux`/`screen`.
- If the URL stops responding: Ctrl-C the tunnel and start it again (Terminal 2) , you get
  a NEW URL; re-send it to the organizers. The API (Terminal 1) can keep running.
- If the API drops: restart Terminal 1, then restart the tunnel.

## Notes
- The quick-tunnel URL is not stable across restarts , submit the EC2 URL as the primary
  if reliability over hours matters.
- `/evaluate` is static-only; nothing the judges send is executed.
