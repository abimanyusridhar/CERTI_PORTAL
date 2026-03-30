# AWS EC2 Deployment Runbook

## Overview
This repository runs a single Node.js HTTP server (no npm dependencies) that serves:
- Public portals (CST/VAPT) and encrypted certificate verification links
- Admin dashboards (CST/VAPT) for certificate management
- API endpoints under `/api/*`

For production, ensure persistent storage for `data/` and `uploads/` (otherwise certificate records, crypto keys, and attachments will be lost on restart).

## Required environment variables
Set these in your shell, `.env`, or your systemd `EnvironmentFile`.

`PORT` (default: `3000`)
: TCP port the server listens on.

`BASE_ORIGIN` (required)
: Public origin used for generated verification URLs (and embedded email tracking pixels). Must be your externally reachable URL.
Example: `https://your-public-domain.com` (recommended).

`ADMIN_USER` (required)
: Admin username for `/api/auth/login`.

`ADMIN_PASS` (required)
: Admin password for `/api/auth/login`.

## Optional: Tenant isolation
`TENANT_ID` (optional)
: If set, server stores cert records, tracking logs, crypto keys, and uploads under tenant-scoped folders:
`data/<TENANT_ID>/...` and `uploads/<TENANT_ID>/...`.

## Optional: AWS SES (email dispatch)
If you want the admin to dispatch credential emails, configure AWS SES.

`AWS_REGION` (or legacy `AWS_SES_REGION`) - e.g. `ap-south-1`
: AWS region hosting SES.

`AWS_ACCESS_KEY_ID` - IAM key with `ses:SendEmail` (or SES v2 email permissions used by the app)

`AWS_SECRET_ACCESS_KEY`

`AWS_SES_FROM_CST` and `AWS_SES_FROM_VAPT`
: Verified sender identities in SES for the configured region.
Use either:
- `sender@example.com`, or
- `Display Name <sender@example.com>`

If SES is not configured, the server will return `503` for email dispatch endpoints.

## Optional: maintenance
The server returns `maintenance.enabled` from `config/app.config.js` via `/api/health`.
To change behavior, update `config/app.config.js` (tenant override supported via `config/tenants/<TENANT_ID>/app.config.js`).

## Storage / persistence requirements
The server persists to:
- `data/` (JSON records + `.keys.json` crypto material + JSONL logs)
- `uploads/` (images + PDF attachments)

On EC2:
- If you use a single instance, local disk is usually sufficient.
- If you run multiple instances behind a load balancer, you must use shared storage (EFS/S3-backed replacement) so crypto keys and cert data stay consistent.

## Health check
Use:
- `GET /api/health`

This endpoint is public and returns:
- uptime
- operational state (starting/operational/shutting down)
- cert counts and maintenance status

## Run locally (quick start)
1. Export or load env vars (or create a `.env` file next to the server config as described in `.env.example`).
2. Start:
   - `node server/index.js`

The server logs startup info to stdout.

## systemd unit (example)
Create `/etc/systemd/system/synergy-cert-portal.service`:

```ini
[Unit]
Description=Synergy Certificate Portal
After=network.target

[Service]
Type=simple
WorkingDirectory=/home/ec2-user/synergy-cert-portal
EnvironmentFile=/home/ec2-user/synergy-cert-portal/.env
ExecStart=/usr/bin/node server/index.js
Restart=always
RestartSec=3
User=ec2-user

StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

Then:
1. `sudo systemctl daemon-reload`
2. `sudo systemctl enable synergy-cert-portal`
3. `sudo systemctl restart synergy-cert-portal`
4. `sudo journalctl -u synergy-cert-portal -f`

## Operational notes
- Set `BASE_ORIGIN` to your real public HTTPS domain; email open tracking pixels embed it.
- Ensure reverse proxies (ALB/Nginx/Cloudflare) preserve `X-Forwarded-For` so rate limiting works as intended.
- Admin auth uses a signed token with expiry; dashboards re-verify via `/api/auth/verify`.

