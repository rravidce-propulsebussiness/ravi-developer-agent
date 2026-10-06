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


## Zero-domain Windows test with Cloudflare Quick Tunnel

You do not need to move `sghomesinterior.in` DNS to Cloudflare for testing.

Run:

```powershell
cd runner
.\setup-windows.ps1
.\start-quick-tunnel-windows.ps1
```

The Quick Tunnel script downloads `cloudflared` locally if needed, creates a temporary `https://*.trycloudflare.com` URL, writes that URL into `.env`, and starts the Chromium runner.

In a second PowerShell window run:

```powershell
cd runner
.\connect-worker-windows.ps1
```

That script reads `RUNNER_TOKEN` locally and writes both `SELF_HOSTED_BROWSER_URL` and `SELF_HOSTED_BROWSER_TOKEN` directly to the `ravi-developer-agent` Worker through Wrangler. The token is never printed into the terminal or copied into ChatGPT.

To stop the local runner and tunnel:

```powershell
.\stop-windows.ps1
```

Quick Tunnel hostnames change when restarted. Run `connect-worker-windows.ps1` again after a new Quick Tunnel is created. For a permanent 24/7 endpoint, use a VPS or a named tunnel on a Cloudflare-managed domain.
