# Oracle Cloud browser runner

This deployment keeps browser execution out of Cloudflare Browser Rendering quotas.

## Recommended topology

ChatGPT -> Ravi Developer Agent Worker -> HTTPS tunnel/reverse proxy -> Oracle Ampere A1 VM -> Docker -> Playwright Chromium

Use an Always Free eligible Ampere A1 VM when it is available in your tenancy. The runner image is multi-architecture because it is built from the official Node Debian image and Playwright installs Chromium during the image build.

## VM setup

Use Ubuntu ARM64 or Oracle Linux ARM64. Install Docker and the Compose plugin, clone this repository, then:

```bash
cd runner
cp .env.example .env
```

Set a random RUNNER_TOKEN of at least 32 characters and set PUBLIC_BASE_URL to the HTTPS origin that will front the runner. Do not publish port 8788 directly to the internet.

Start the service:

```bash
docker compose up -d --build
docker compose ps
```

The compose file publishes the runner only on 127.0.0.1:8788. Put Cloudflare Tunnel, Caddy, Nginx, or another authenticated HTTPS ingress in front of that loopback endpoint.

## Persistent browser state

The named Docker volume `browser-runner-data` stores browser profiles under `/data/browser-profiles`. This lets approved authenticated sessions survive container recreation. Treat the volume as sensitive data.

## Worker connection

Configure the Ravi Developer Agent Worker with:

```text
SELF_HOSTED_BROWSER_URL=https://your-runner.example.com
SELF_HOSTED_BROWSER_TOKEN=<same RUNNER_TOKEN>
```

Do not send the token through ChatGPT. Configure it directly as a Worker secret.

## Production policy

For production, the self-hosted runner should be authoritative. Do not silently fall back to a quota-limited browser provider when the cloud runner is unavailable; report the runner outage instead. Cloudflare can remain the MCP/OAuth/API edge.

## Credentials

Normal text is sent through ordinary browser actions. Passwords and other stored secrets use runner-side aliases/generated-secret actions and are never returned in browser results. OTP/MFA and CAPTCHA remain explicit human-verification steps.
