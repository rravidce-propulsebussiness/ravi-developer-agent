# Self-hosted Browser Runner

This service gives Ravi Developer Agent a browser backend that is limited by your own PC/VPS resources instead of Cloudflare Browser Run minutes.

## Security model

- Every control API request requires a long random `RUNNER_TOKEN`.
- Each session has an explicit hostname allowlist.
- All HTTP/HTTPS subrequests are blocked unless their hostname matches the session allowlist.
- Service workers are blocked.
- Password, API-key/token, OTP/MFA, and payment-card fields are rejected by the typing endpoint.
- Live View uses a random, read-only token that expires after 5 minutes.
- Bind to `127.0.0.1` unless the service is behind HTTPS (for example Cloudflare Tunnel, Caddy, Nginx, or Tailscale Funnel).

## Windows

```powershell
cd runner
Copy-Item .env.example .env
# edit .env and set RUNNER_TOKEN + PUBLIC_BASE_URL
npm install
npx playwright install chromium
Get-Content .env | ForEach-Object {
  if ($_ -match '^([^#=]+)=(.*)$') { [Environment]::SetEnvironmentVariable($matches[1], $matches[2], 'Process') }
}
npm start
```

Set `HEADLESS=false` if you want the Chrome window visible on the PC.

## Linux/VPS

```bash
cd runner
cp .env.example .env
npm install
npx playwright install --with-deps chromium
set -a; . ./.env; set +a
npm start
```

For a 24/7 setup, run it under systemd or Docker and publish it through an HTTPS reverse proxy/tunnel.

## Health check

```bash
curl -H "Authorization: Bearer $RUNNER_TOKEN" http://127.0.0.1:8788/health
```

## Worker integration

Configure these Ravi Developer Agent Worker secrets/variables:

- `SELF_HOSTED_BROWSER_URL=https://browser.example.com`
- `SELF_HOSTED_BROWSER_TOKEN=<same RUNNER_TOKEN>`

When both values exist, the Worker uses this runner first. Cloudflare Browser Run remains the fallback when the self-hosted runner is not configured.
