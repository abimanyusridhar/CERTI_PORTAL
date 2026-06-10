# AWS Migration Guide — Synergy Cert Portal
## DynamoDB (data) + S3 (uploads)

---

## WHAT IS CHANGING

| Currently (EC2 disk)               | After migration (AWS managed)      |
|------------------------------------|------------------------------------|
| `data/SYNCERT/certificates.json`   | DynamoDB table `synergy-cst-certs` |
| `data/SYNCERT/vapt_certificates.json` | DynamoDB table `synergy-vapt-certs` |
| `data/SYNCERT/documents.json`      | DynamoDB table `synergy-documents` |
| `data/SYNCERT/users.json`          | DynamoDB table `synergy-users`     |
| `data/SYNCERT/groups.json`         | DynamoDB table `synergy-groups`    |
| `data/SYNCERT/doc_access_requests.json` | DynamoDB table `synergy-doc-access` |
| `uploads/` directory               | S3 bucket `synergy-cert-portal-uploads` |

**Benefits after migration:**
- Data survives EC2 instance replacement / AMI changes
- No more risk of losing certs if the disk fills up or instance is terminated
- S3 files are replicated across 3 availability zones (99.999999999% durability)
- DynamoDB auto-scales, no storage limits
- Enables running multiple EC2 instances (horizontal scaling) later

---

## PART 1 — AWS CONSOLE SETUP (do this first)

### STEP 1: Create the S3 Bucket

1. Open **AWS Console → S3 → Create bucket**
2. **Bucket name:** `synergy-cert-portal-uploads`  *(must be globally unique — add your account ID suffix if taken)*
3. **Region:** same region as your EC2 instance (e.g. `ap-south-1`)
4. **Block Public Access:** Keep ALL options CHECKED (private bucket — files served via app)
5. **Versioning:** Enable (protects against accidental deletion)
6. **Encryption:** Server-side encryption with Amazon S3 managed keys (SSE-S3)
7. Click **Create bucket**

### STEP 2: Create DynamoDB Tables

Repeat the following for each table (6 total):

1. Open **AWS Console → DynamoDB → Tables → Create table**
2. Use these exact settings for ALL tables:

| Table name               | Partition key | Sort key | Billing mode      |
|--------------------------|---------------|----------|-------------------|
| `synergy-cst-certs`      | `pk` (String) | `sk` (String) | On-demand    |
| `synergy-vapt-certs`     | `pk` (String) | `sk` (String) | On-demand    |
| `synergy-documents`      | `pk` (String) | `sk` (String) | On-demand    |
| `synergy-doc-access`     | `pk` (String) | `sk` (String) | On-demand    |
| `synergy-users`          | `pk` (String) | `sk` (String) | On-demand    |
| `synergy-groups`         | `pk` (String) | `sk` (String) | On-demand    |

- **Billing mode:** On-demand (no capacity planning, pay per request)
- **Encryption:** AWS owned key (default)
- Leave all other settings as default

### STEP 3: Create IAM Policy

1. Open **AWS Console → IAM → Policies → Create policy**
2. Switch to **JSON** tab and paste:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DynamoDBAccess",
      "Effect": "Allow",
      "Action": [
        "dynamodb:GetItem",
        "dynamodb:PutItem",
        "dynamodb:DeleteItem",
        "dynamodb:BatchWriteItem",
        "dynamodb:Scan",
        "dynamodb:Query"
      ],
      "Resource": [
        "arn:aws:dynamodb:ap-south-1:*:table/synergy-cst-certs",
        "arn:aws:dynamodb:ap-south-1:*:table/synergy-vapt-certs",
        "arn:aws:dynamodb:ap-south-1:*:table/synergy-documents",
        "arn:aws:dynamodb:ap-south-1:*:table/synergy-doc-access",
        "arn:aws:dynamodb:ap-south-1:*:table/synergy-users",
        "arn:aws:dynamodb:ap-south-1:*:table/synergy-groups"
      ]
    },
    {
      "Sid": "S3Access",
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:PutObject",
        "s3:DeleteObject",
        "s3:HeadObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::synergy-cert-portal-uploads",
        "arn:aws:s3:::synergy-cert-portal-uploads/*"
      ]
    }
  ]
}
```

> **Replace `ap-south-1`** with your actual region if different.

3. **Policy name:** `SynergyCertPortalPolicy`
4. Click **Create policy**

### STEP 4: Create IAM Role and attach to EC2

1. **IAM → Roles → Create role**
2. **Trusted entity:** AWS service → EC2
3. **Attach policy:** search and select `SynergyCertPortalPolicy`
4. **Role name:** `SynergyCertPortalEC2Role`
5. Click **Create role**

6. **Attach role to EC2:**
   - Go to **EC2 → Instances → select your instance**
   - **Actions → Security → Modify IAM role**
   - Select `SynergyCertPortalEC2Role` → **Update IAM role**

> This lets the EC2 instance authenticate to AWS automatically.
> **No access keys / secret keys needed in the application.**

---

## PART 2 — APPLICATION SETUP (on your EC2 instance)

SSH into your EC2 instance and run these commands:

### STEP 5: Install Node.js dependencies

```bash
cd /path/to/synergy-cert-portal    # your app directory
npm install
```

This installs: `@aws-sdk/client-dynamodb`, `@aws-sdk/client-s3`, `@aws-sdk/lib-dynamodb`, `@aws-sdk/s3-request-presigner`

### STEP 6: Set environment variables

Add these to your process manager or `/etc/environment`:

**If using PM2:**
```bash
pm2 set cert-portal:AWS_REGION ap-south-1
pm2 set cert-portal:S3_BUCKET synergy-cert-portal-uploads
pm2 set cert-portal:STORAGE_BACKEND dynamodb
```

**Or add to your `.env` file / ecosystem.config.js:**
```bash
AWS_REGION=ap-south-1
S3_BUCKET=synergy-cert-portal-uploads
STORAGE_BACKEND=dynamodb
```

### STEP 7: Run the migration script

**Do this ONCE to copy all existing data to AWS:**

```bash
export AWS_REGION=ap-south-1
export S3_BUCKET=synergy-cert-portal-uploads
export TENANT_ID=SYNCERT

node scripts/migrate-to-aws.js
```

Expected output:
```
═══════════════════════════════════════════════════
 Synergy Cert Portal — AWS Migration Script
  Tenant   : SYNCERT
  S3 Bucket: synergy-cert-portal-uploads
  Region   : ap-south-1
═══════════════════════════════════════════════════

STEP 1 — Migrating JSON data files → DynamoDB
─────────────────────────────────────────────
  synergy-cst-certs: 12 records migrated ✓
  synergy-vapt-certs: 3 records migrated ✓
  ...

STEP 2 — Migrating upload files → S3
─────────────────────────────────────
  16 files uploaded to s3://synergy-cert-portal-uploads ✓
```

### STEP 8: Update server/index.js

In `server/index.js`, find the environment check near the top and add:

```javascript
const STORAGE_BACKEND = process.env.STORAGE_BACKEND || 'file'; // 'file' or 'dynamodb'
```

Then swap the store implementations (see the diff in `server/index.js` below).

### STEP 9: Restart the app

```bash
pm2 restart cert-portal
pm2 logs cert-portal   # watch for errors
```

### STEP 10: Verify

1. Open the admin dashboard — check that all certificates are visible
2. Add a test certificate with an image — confirm it uploads and shows
3. Check **DynamoDB Console → Tables → synergy-cst-certs → Explore items** — new cert should appear
4. Check **S3 Console → synergy-cert-portal-uploads** — image file should appear

---

## PART 3 — SERVER CODE CHANGES

The files already created in this repo handle the AWS layer:

- `server/lib/dynamo-store.js` — DynamoDB data store (replaces file JSON stores)
- `server/lib/s3-uploads.js`   — S3 file upload/download (replaces disk writes)
- `scripts/migrate-to-aws.js` — one-time migration script

The `server/index.js` needs these changes (see code diffs in each section below).

### 3a. Add at top of server/index.js (after existing requires)

```javascript
const STORAGE_BACKEND = process.env.STORAGE_BACKEND || 'file';
const S3_BUCKET = process.env.S3_BUCKET || '';

let dynamoStore, s3Store;
if (STORAGE_BACKEND === 'dynamodb') {
  dynamoStore = require('./lib/dynamo-store');
  s3Store     = require('./lib/s3-uploads');
}
```

### 3b. Replace createJsonStore calls

Find each `createJsonStore({ filePath: ... })` call and replace with:

```javascript
// BEFORE (file-based):
const cstStore = createJsonStore({ filePath: DATA_FILE, seedData: SEED, ... });

// AFTER (DynamoDB):
const cstStore = STORAGE_BACKEND === 'dynamodb'
  ? dynamoStore.createDynamoStore({ tableName: 'synergy-cst-certs', tenantId: TENANT_ID, onError: ... })
  : createJsonStore({ filePath: DATA_FILE, seedData: SEED, ... });
```

> Note: DynamoDB store methods are async — you will need to `await` them.
> The existing `loadData()` / `saveData()` functions need to become async.

### 3c. Replace saveCertImageFile with S3 upload

```javascript
// BEFORE:
function saveCertImageFile(files, prefix, existingPath) {
  // ... writes to UPLOADS_DIR
}

// AFTER:
async function saveCertImageFile(files, prefix, existingPath) {
  if (STORAGE_BACKEND === 'dynamodb') {
    const f    = files[prefix] || files[Object.keys(files)[0]];
    const ext  = path.extname(f.name || '.png');
    const key  = s3Store.buildKey(TENANT_ID, `${prefix}${ext}`);
    if (existingPath) await s3Store.deleteFile(existingPath).catch(() => {});
    return await s3Store.uploadFile(f.data, key, f.mimetype || 'image/png');
  }
  // original file code below ...
}
```

### 3d. Replace file-serving route with S3 proxy

```javascript
// BEFORE: app.get('/uploads/*', ...)
// AFTER:
app.get('/uploads/*', async (req, res) => {
  if (STORAGE_BACKEND === 'dynamodb') {
    const key = req.path.replace('/uploads/', '');
    try {
      const { buf, contentType } = await s3Store.getFileBuffer(`${TENANT_ID}/${key}`);
      res.setHeader('Content-Type', contentType);
      res.setHeader('Cache-Control', 'public, max-age=86400');
      return res.end(buf);
    } catch { return res.status(404).end(); }
  }
  // original static file serving below ...
});
```

---

## ROLLBACK PLAN

If anything goes wrong after switching to DynamoDB:

1. Set `STORAGE_BACKEND=file` in your environment
2. Restart the app — it immediately falls back to reading from `data/` directory
3. The JSON files are still intact (migration script only reads, never deletes them)
4. Investigate the issue, then retry

---

## COST ESTIMATE

| Service   | Usage                    | Estimated monthly cost |
|-----------|--------------------------|------------------------|
| DynamoDB  | ~1000 reads/writes/day   | ~$0 (within free tier) |
| S3        | 16 files, ~50MB          | ~$0.001 (< $1)         |
| Data transfer | Serving cert images  | ~$0.01-$0.09           |
| **Total** |                          | **~$0 – $1/month**     |

> DynamoDB free tier: 25GB storage, 200M requests/month — more than enough.
> S3 free tier (first 12 months): 5GB storage, 20,000 GET requests.
