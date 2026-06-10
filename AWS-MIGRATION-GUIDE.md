# AWS S3 Migration — Step by Step
## Synergy Cert Portal (Live EC2 → S3 Backed Storage)

---

## WHAT THIS DOES

Your app currently saves data to files on the EC2 disk.
After this migration, all data is saved to AWS S3 automatically.

```
BEFORE:                          AFTER:
EC2 Disk (disappears if          AWS S3 (permanent, replicated,
instance is replaced)            survives any EC2 change)
  data/SYNCERT/                    s3://your-bucket/data/SYNCERT/
    certificates.json                certificates.json
    vapt_certificates.json           vapt_certificates.json
    users.json                       users.json
    groups.json                      groups.json
    ...                              ...
  uploads/                         s3://your-bucket/uploads/SYNCERT/
    cert_abc123.png                  cert_abc123.png
    cert_xyz789.pdf                  cert_xyz789.pdf
```

**No code rewrite. No database server to manage. No npm packages.**
The S3 integration is already built into the application — just needs to be switched on.

**Downtime required: ZERO.** The app keeps working from local files during
migration. S3 becomes the backup automatically. On restart, S3 is primary.

---

## PART 1 — AWS CONSOLE SETUP

### STEP 1 — Create the S3 Bucket

1. Log in to **AWS Console** → go to **S3**
2. Click **"Create bucket"**
3. Fill in:
   - **Bucket name:** `synergy-cert-portal-uploads`
     *(must be globally unique — if taken, try `synergy-cert-portal-uploads-2024`)*
   - **AWS Region:** choose the same region as your EC2 instance
     *(check EC2 → Instances to see your region, e.g. `ap-south-1`)*
4. Under **"Block Public Access settings for this bucket"**
   - Keep **all 4 checkboxes CHECKED** (files stay private — app controls access)
5. Under **"Bucket Versioning"** → click **Enable**
   *(protects against accidental deletion — keeps old versions)*
6. Under **"Default encryption"** → leave as is (SSE-S3 is default)
7. Click **"Create bucket"**

✅ Bucket created.

---

### STEP 2 — Create an IAM User for S3 Access

> **Why a user and not a role?**
> You already have access keys configured for SES email — we follow the same pattern
> for simplicity. If you prefer, you can use an EC2 IAM role instead (no keys needed),
> but that requires attaching the role to the instance in the AWS console.

1. Go to **AWS Console → IAM**
2. Click **"Users"** in the left menu → **"Create user"**
3. **Username:** `synergy-cert-portal-s3`
4. Click **Next** (skip console access — this is a service account)
5. On **"Set permissions"** → choose **"Attach policies directly"**
6. Click **"Create policy"** (this opens in a new tab)

---

### STEP 3 — Create the IAM Policy

*(You should be in the "Create policy" tab from Step 2)*

1. Click the **"JSON"** tab at the top
2. Delete everything in the box and paste this:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "S3CertPortal",
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:PutObject",
        "s3:DeleteObject",
        "s3:ListBucket",
        "s3:HeadObject"
      ],
      "Resource": [
        "arn:aws:s3:::synergy-cert-portal-uploads",
        "arn:aws:s3:::synergy-cert-portal-uploads/*"
      ]
    }
  ]
}
```

> **Important:** if you used a different bucket name in Step 1,
> replace `synergy-cert-portal-uploads` in both Resource lines.

3. Click **"Next"**
4. **Policy name:** `SynergyCertPortalS3Policy`
5. Click **"Create policy"**
6. **Close this tab** and go back to the Create User tab

---

### STEP 4 — Attach Policy to the User

*(Back in the "Create user" tab)*

1. Click the **refresh icon** next to "Search policies"
2. Search for: `SynergyCertPortalS3Policy`
3. Check the box next to it
4. Click **Next** → **"Create user"**

✅ User created.

---

### STEP 5 — Create Access Keys

1. Click on the user `synergy-cert-portal-s3` you just created
2. Click the **"Security credentials"** tab
3. Scroll to **"Access keys"** → click **"Create access key"**
4. **Use case:** select **"Application running outside AWS"** → Next
5. Click **"Create access key"**
6. **IMPORTANT:** You will see:
   - **Access key ID** (looks like: `AKIAxxxxxxxxxxxxxxxx`)
   - **Secret access key** (long string — only shown ONCE)
7. **Copy both and save them somewhere safe** (e.g. a secure notes app)
8. Click **Done**

✅ AWS setup complete. Now go to your EC2 instance.

---

## PART 2 — EC2 INSTANCE SETUP

SSH into your EC2 instance for all commands below.

### STEP 6 — Pull Latest Code

```bash
cd /path/to/your/app        # e.g. cd /home/ec2-user/synergy-cert-portal

git pull origin master
```

This gets the new S3 store code.

---

### STEP 7 — Back Up Your Data (Safety First)

Before touching anything, create a backup:

```bash
# Create a timestamped backup of data and uploads
cp -r data/ data_backup_$(date +%Y%m%d_%H%M%S)/
cp -r uploads/ uploads_backup_$(date +%Y%m%d_%H%M%S)/

echo "Backup created"
ls -la data_backup_* uploads_backup_*
```

✅ You now have a safe copy. If anything goes wrong, your data is here.

---

### STEP 8 — Set Environment Variables

Find how your app starts. Likely one of these:

**Option A — PM2 (most common):**
```bash
pm2 show cert-portal    # or whatever your app name is
```

**Option B — systemd:**
```bash
cat /etc/systemd/system/cert-portal.service
```

**Option C — .env file:**
```bash
cat /path/to/your/app/.env
```

Now add the S3 variables. **Use the method that matches how your app is started:**

---

**If using .env file:**
```bash
cd /path/to/your/app
nano .env
```

Add these lines at the bottom:
```
S3_BUCKET=synergy-cert-portal-uploads
S3_REGION=ap-south-1
S3_ACCESS_KEY=AKIAxxxxxxxxxxxxxxxx
S3_SECRET_KEY=your-secret-key-here
```
*(Replace `ap-south-1` with your actual region, and use your real keys from Step 5)*

Save: press `Ctrl+X`, then `Y`, then `Enter`

---

**If using PM2 ecosystem.config.js:**
```bash
cd /path/to/your/app
nano ecosystem.config.js
```

Add to the `env` section:
```javascript
env: {
  // ... existing variables ...
  S3_BUCKET: 'synergy-cert-portal-uploads',
  S3_REGION: 'ap-south-1',
  S3_ACCESS_KEY: 'AKIAxxxxxxxxxxxxxxxx',
  S3_SECRET_KEY: 'your-secret-key-here',
}
```

---

**If using systemd:**
```bash
sudo nano /etc/systemd/system/cert-portal.service
```

Add to the `[Service]` section:
```ini
Environment="S3_BUCKET=synergy-cert-portal-uploads"
Environment="S3_REGION=ap-south-1"
Environment="S3_ACCESS_KEY=AKIAxxxxxxxxxxxxxxxx"
Environment="S3_SECRET_KEY=your-secret-key-here"
```

Then reload:
```bash
sudo systemctl daemon-reload
```

---

### STEP 9 — Run the Migration Script

This pushes ALL your existing data and files to S3. Run it once:

```bash
cd /path/to/your/app

# Set vars for this terminal session (same values as above)
export S3_BUCKET=synergy-cert-portal-uploads
export S3_REGION=ap-south-1
export S3_ACCESS_KEY=AKIAxxxxxxxxxxxxxxxx
export S3_SECRET_KEY=your-secret-key-here
export TENANT_ID=SYNCERT

node scripts/migrate-to-aws.js
```

Expected output:
```
═══════════════════════════════════════════════════════════
 Synergy Cert Portal — S3 Migration
  Tenant : SYNCERT
  Bucket : synergy-cert-portal-uploads
  Region : ap-south-1
═══════════════════════════════════════════════════════════

STEP 1 — Uploading data files to S3
─────────────────────────────────────────────────────────
  [OK]   certificates.json → s3://synergy-cert-portal-uploads/data/SYNCERT/certificates.json  (12 records)
  [OK]   vapt_certificates.json → s3://synergy-cert-portal-uploads/data/SYNCERT/vapt_certificates.json  (3 records)
  [OK]   documents.json → s3://synergy-cert-portal-uploads/data/SYNCERT/documents.json  (5 records)
  [SKIP] doc_access_requests.json — not found locally
  [SKIP] users.json — not found locally
  [SKIP] groups.json — not found locally

STEP 2 — Uploading cert images and attachments to S3
─────────────────────────────────────────────────────────
  16 files uploaded to s3://synergy-cert-portal-uploads  (0 failed)

Migration complete!
```

✅ All data is now in S3.

---

### STEP 10 — Verify Data in S3

Before restarting the app, confirm the files are in S3:

1. Go to **AWS Console → S3 → synergy-cert-portal-uploads**
2. You should see two folders: `data/` and `uploads/`
3. Click `data/` → `SYNCERT/` → you should see `certificates.json`, etc.
4. Click on `certificates.json` → **"Download"** → open it and verify your cert data is there

✅ Data confirmed in S3.

---

### STEP 11 — Restart the Application

**PM2:**
```bash
pm2 restart cert-portal
pm2 logs cert-portal --lines 50
```

**systemd:**
```bash
sudo systemctl restart cert-portal
sudo journalctl -u cert-portal -n 50 -f
```

**Direct node:**
```bash
# Kill existing process
pkill -f "node server/index.js"
# Start again
node server/index.js &
```

Watch the logs for:
```
S3 enabled — uploads and data stores will mirror to S3
```

If you see errors, check STEP 12.

---

### STEP 12 — Test the Application

1. Open your app in the browser — everything should work normally
2. **Add a test certificate** with an image
3. Go to **AWS Console → S3 → synergy-cert-portal-uploads → uploads/SYNCERT/**
   → You should see the new image file appear within seconds
4. **Edit an existing certificate** → change the status → Save
5. Go to **S3 → data/SYNCERT/certificates.json** → Download and open it
   → The change should be reflected

✅ S3 integration is live and working.

---

## WHAT HAPPENS NOW (HOW IT WORKS)

```
User saves a cert
      │
      ▼
  App writes to local disk instantly  ──────────┐
      │                                         │
      │                                         ▼
      │                              Mirrors to S3 async
      │                              (within 50ms)
      ▼
  Response sent to user (fast)

EC2 Instance is replaced / restarted
      │
      ▼
  App starts, looks for local data/
      │ Not found (fresh instance)
      ▼
  Pulls from S3 automatically
      │
      ▼
  App continues with full data ✓
```

**The app is now disaster-proof:**
- EC2 instance terminated → start a new one, data comes from S3
- EC2 disk full → files already in S3, no data loss
- Accidental delete → S3 versioning keeps old copies

---

## ROLLBACK

If anything breaks, revert immediately:

**PM2:**
```bash
# Remove S3 vars from ecosystem.config.js, then:
pm2 restart cert-portal
```

**Or just rename .env line:**
```bash
# Comment out the S3 lines:
# S3_BUCKET=synergy-cert-portal-uploads
```

Without `S3_BUCKET` set, the app falls back to 100% local files.
Your backups from Step 7 are untouched.

---

## COST

| What            | How much                         |
|-----------------|----------------------------------|
| S3 Storage      | ~50 MB data → **< $0.01/month** |
| S3 Requests     | ~500/day → **< $0.01/month**   |
| Data Transfer   | Serving images → **< $0.10/month** |
| **Total**       | **Under $0.15/month**           |

S3 free tier (first 12 months): 5GB storage, 20,000 GET, 2,000 PUT — **$0**.

---

## TROUBLESHOOTING

**Error: "S3 PutObject → 403"**
→ Access key doesn't have permission. Re-check Step 3 policy.
→ Make sure the bucket name in the policy matches exactly.

**Error: "S3 PutObject → 301 / redirect"**
→ Wrong region. Check `S3_REGION` matches the bucket's region.

**Error: "S3_BUCKET is not set"**
→ Environment variables not loaded. Check Step 8.

**App shows no data after restart**
→ Temporary — first load pulls from S3 (async). Refresh the page in 2-3 seconds.

**Files not appearing in S3**
→ Check the app logs: `pm2 logs cert-portal | grep S3`
→ Should show "S3 cert image mirror" lines.
