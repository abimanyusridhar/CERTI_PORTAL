# Data Structure Migration Plan

## Purpose

This document defines the next migration alignment after S3 hardening: move from
JSON-file collections toward a database-ready data model without changing current
portal behavior.

Current runtime remains unchanged:

- Source of truth today: `data/<TENANT_ID>/*.json` or legacy `data/*.json`
- Upload storage today: `uploads/<TENANT_ID>/...` with optional S3 mirror
- API behavior today: unchanged

## Current Collections

| Current file | Current role | Target structure |
| --- | --- | --- |
| `certificates.json` | CST certificate records | `certificates` with `type='CST'` |
| `vapt_certificates.json` | VAPT certificate records | `certificates` with `type='VAPT'` |
| `documents.json` | Vessel-level document library | `documents` |
| `users.json` | Portal superintendent/admin users | `users` |
| `groups.json` | User/vessel access groups | `groups`, `group_vessels`, `user_groups` |
| `doc_access_requests.json` | Legacy captain access workflow | `legacy_doc_access_requests` or archived audit table |
| `tracking_events.json` / `*.jsonl` | Public engagement tracking | `audit_events` or `certificate_events` |
| `.keys.json` | Crypto/session signing keys | Secrets Manager or KMS-backed secret, not database |

## Canonical Target Entities

### tenants

One row per deployment tenant.

Required columns:

- `id`
- `name`
- `status`
- `created_at`
- `updated_at`

Migration source:

- `TENANT_ID`
- tenant folder name

### certificates

Single table for both CST and VAPT records.

Required columns:

- `id`
- `tenant_id`
- `type` (`CST` or `VAPT`)
- `status`
- `vessel_imo`
- `vessel_name`
- `recipient_name`
- `recipient_email`
- `issued_at`
- `valid_until`
- `certificate_image_url`
- `notes`
- `created_at`
- `updated_at`

CST-specific nullable columns:

- `chief_engineer`
- `training_title`
- `training_mode`
- `compliance_date`
- `compliance_quarter`
- `organizer`
- `valid_for`
- `verified_by`

VAPT-specific nullable columns:

- `certificate_number`
- `assessment_date`
- `assessing_org`
- `frameworks`
- `scope_items`
- `verified_by`
- `verifier_title`

Migration source:

- `certificates.json`
- `vapt_certificates.json`

### certificate_attachments

Attachments currently embedded inside certificate records.

Required columns:

- `id`
- `tenant_id`
- `certificate_id`
- `file_name`
- `file_url`
- `file_size`
- `mime_type`
- `created_at`

Migration source:

- `certificates[*].attachments`
- `vapt_certificates[*].attachments`

### certificate_events

Engagement and lifecycle events currently embedded inside certificate records.

Required columns:

- `id`
- `tenant_id`
- `certificate_id`
- `event_type`
- `event_at`
- `metadata_json`

Migration source:

- `certificates[*].engagement`
- `vapt_certificates[*].engagement`
- `tracking_events.json`
- `tracking_events.jsonl`

### documents

Vessel-level documents.

Required columns:

- `id`
- `tenant_id`
- `vessel_imo`
- `vessel_name`
- `doc_type`
- `title`
- `description`
- `linked_cert_id`
- `file_name`
- `file_path`
- `file_size`
- `mime_type`
- `uploaded_at`
- `updated_at`

Migration source:

- `documents.json`

### users

Portal users provisioned by admin and matched with Cognito SSO.

Required columns:

- `id`
- `tenant_id`
- `email`
- `name`
- `role`
- `active`
- `sso_sub`
- `created_at`
- `updated_at`

Do not migrate `passwordHash` into the target authentication model unless a
legacy break-glass flow is explicitly approved. The current direction is SSO-only.

Migration source:

- `users.json`

### groups

Access groups.

Required columns:

- `id`
- `tenant_id`
- `name`
- `notes`
- `created_at`
- `updated_at`

Migration source:

- `groups.json`

### group_vessels

Many-to-many table between groups and vessel IMOs.

Required columns:

- `tenant_id`
- `group_id`
- `vessel_imo`

Migration source:

- `groups[*].vesselIMOs`

### user_groups

Many-to-many table between users and groups.

Required columns:

- `tenant_id`
- `user_id`
- `group_id`

Migration source:

- `users[*].groupIds`

### audit_events

Admin and system audit stream.

Required columns:

- `id`
- `tenant_id`
- `actor_type`
- `actor_id`
- `action`
- `entity_type`
- `entity_id`
- `event_at`
- `ip_address`
- `metadata_json`

Migration source:

- `audit.jsonl`
- selected tracking/email events

## Migration Path

### Phase 0: Inspect and freeze contract

Status: current alignment.

Actions:

- Run `npm run data:inspect`.
- Review collection counts and fields.
- Confirm no duplicate IDs or missing IDs.
- Confirm legacy access requests can be archived.

Rollback:

- No runtime change; no rollback needed.

### Phase 1: Add repository interface

Goal:

- Introduce a storage interface that can support JSON, S3 JSON, and future DB
  backends behind the same API.

Rule:

- Existing routes should call repository methods, not direct JSON object mutation.

Rollback:

- Keep JSON repository as default.

### Phase 2: Dual-write dry run

Goal:

- Write current JSON source and database target in parallel.
- Read from JSON only.
- Compare record counts and checksums in background.

Rollback:

- Disable database writer; JSON remains source of truth.

### Phase 3: Read shadow validation

Goal:

- Read from database in shadow mode and compare with JSON responses.
- Do not return database responses to users yet.

Rollback:

- Disable shadow reads.

### Phase 4: Controlled read switch

Goal:

- Read from database for selected low-risk admin views.
- Keep JSON backup writes temporarily.

Rollback:

- Switch reads back to JSON using a feature flag.

### Phase 5: Database primary

Goal:

- Database becomes source of truth.
- JSON export becomes backup/rollback artifact.

Rollback:

- Restore from latest database snapshot or JSON export based on timestamp.

## Data Quality Rules

Apply before any database import:

- Every record must have a stable `id`.
- Certificate IDs must be unique across CST and VAPT after adding `type`.
- Every certificate with attachments must point to an existing upload object.
- Every document must have `vesselIMO`, `fileName`, and `filePath`.
- Every user email must be lowercase-normalized and unique per tenant.
- Every `groupIds` reference must point to an existing group.
- Every `group.vesselIMOs` value must be normalized to the IMO format used by certificates.
- Legacy `doc_access_requests` should not become active authorization state.

## Recommended Database

Preferred target:

- PostgreSQL on RDS for relational integrity, reporting, and audit queries.

Acceptable serverless target:

- DynamoDB if operational simplicity and single-key lookups matter more than SQL reporting.

For this portal, PostgreSQL is the better default because certificates, users,
groups, documents, and audit history have natural relationships and reporting needs.

## Commands

Inspect current structure:

```bash
npm run data:inspect
```

Inspect a tenant-scoped deployment:

```bash
TENANT_ID=SYNCERT npm run data:inspect
```

