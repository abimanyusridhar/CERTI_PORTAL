# Synergy Certificate Portal - Testing Analysis and Test Plan

## Architecture Under Test

The application is a zero-dependency Node.js HTTP server with static public/admin portals.

- Server entrypoint: `server/index.js`
- Route modules: `server/routes/auth.js`, `server/routes/health.js`
- Services: `server/services/security.js`, `server/services/s3.js`
- Persistence: local JSON stores and optional S3-backed JSON stores in `server/repositories`
- UI: static HTML/CSS/JS under `public`, `admin`, and `public/assets`
- Runtime data: `data/*.json`, tenant-scoped data under `data/<TENANT_ID>`, uploads under `uploads`

## Automated Test Strategy

Run all automated tests:

```bash
npm test
```

Run coverage:

```bash
npm run test:coverage
```

Current verified result (2026-07-10):

- Tests: 153 passing, 0 failing (was 121; +32 from three new integration files closing route/security gaps below)
- Line coverage: 98.60% (unit-testable modules; unchanged — new tests are integration-level)
- Branch coverage: 90.91%
- Function coverage: 93.51%

Coverage note: Node's native coverage report covers modules imported by the test process. The monolithic `server/index.js` is exercised by spawning the real server in integration tests, but that child-process execution is not included in the parent process coverage table.

### 2026-07-10 gap-closing pass

Added three new integration test files (each spawns the real server on its own port to avoid collision: 3422/3423/3424, alongside the original `integration.test.js` on 3421):

- `server/tests/integration-vapt-extras.test.js` (9 tests) — VAPT/CST single-cert GET, verify-by-id, public-cert-url/cert-url/verify token round-trip + tamper rejection, VAPT CSV import, engagement endpoints, track-event, track-open pixels, attachment deletion.
- `server/tests/integration-admin-status.test.js` (15 tests) — public/admin stats and quarterly stats, cognito/s3/ses-status, vessels/names, cognito-sync, decommissioned superadmin/auth-user-login routes, auth/user/logout+me, docs/check-access, docs temp-link + open-token round trip, docs/request-status claim-token validation, docs PUT/DELETE lifecycle.
- `server/tests/integration-security-edge.test.js` (8 tests) — duplicate cert ID → 409 (CST + VAPT), SQLi/XSS-shaped field values, oversized JSON/multipart body rejection + server-stays-healthy check, **SEC-002 cross-vessel broken access control** (confirmed no bypass across `/api/supt/vessels`, `/api/supt/vessel/:imo/certs`, `/api/docs/by-vessel/:imo`, `/api/docs/download/:id`), rate-limit burst → 429.

**Two real application bugs found by these tests and fixed in `server/index.js`:**

1. **VAPT CSV import always crashed with 500.** `POST /api/vapt/import-csv`'s per-record loop reassigned a `const cert` binding inside `sanitiseCertBody(cert)`, throwing `TypeError: Assignment to constant variable` on any valid, non-duplicate record. Fixed by changing `for (const cert of records)` to `for (let cert of records)` (mirrors the CST import route, which never had this bug). Previously **completely broken in production** — every VAPT bulk import failed.
2. **Attachment-delete endpoints were unreachable dead code.** `DELETE /api/certs/:id/attachments/:idx` and the VAPT equivalent were always intercepted by the generic `DELETE /api/certs/:id` / `DELETE /api/vapt/certs/:id` handlers, which matched via a bare `route.startsWith(...)` with no segment-count guard (unlike the sibling GET-single-cert handlers, which already had one). Fixed by adding the same explicit segment-count check used elsewhere in the file, so the generic delete only matches exact `/certs/:id` (2 segments) / `/vapt/certs/:id` (3 segments) and falls through otherwise.

**Informational findings — since remediated (2026-07-10 follow-up pass):**

- **Frontend XSS audit.** Public cert fields (`certPublicFields`) are correctly not HTML-escaped at the API layer (a JSON response isn't executed as HTML), so the real question was whether the frontend escapes on render. Auditing confirmed the **CST** public page (`public/assets/smg-public/cst/index.js`) already wraps every free-text field in its `escH()` helper. The **VAPT** public page (`public/assets/smg-public/vapt/index.js`), however, had a genuine gap: `vesselName`, `frameworks`, `scopeItems` (scope tags), `notes`, and `verifierTitle` were interpolated into `innerHTML` unescaped — a real stored-XSS vector reachable by any unauthenticated visitor verifying a VAPT certificate with a maliciously-crafted field. **Fixed** — all five now go through `escH()`, matching the CST page. The same audit found the same unescaped pattern in both admin dashboards (`smg-admin/cst/dashboard.js`, `smg-admin/vapt/dashboard.js` — `recipientName`, `vesselName`, `vesselIMO`, `chiefEngineer`, `verifiedBy`, `recipientEmail` across the near-expiry widget, cert detail modal, CSV-import preview table, and main cert list); these are same-privilege (admin-to-admin) stored XSS, lower severity than the public-facing gap, but fixed for consistency using each file's existing `escHtml()` helper.
- **Shared upload rate-limit bucket.** The single `'upload'` bucket (10 requests / 5 min per IP) was shared across `POST /api/certs`, `POST /api/vapt/certs`, and `POST /api/docs/upload` combined. **Fixed** — split into `'cert-create'` (20/5min, covers CST+VAPT cert creation) and `'doc-upload'` (10/5min, unchanged, document uploads only), so an admin creating certs no longer competes with document uploads for the same budget.
- **No enforced coverage gate.** `package.json`'s `test:coverage` script didn't fail the build on a coverage regression. **Fixed** — added `--test-coverage-lines=95 --test-coverage-branches=85 --test-coverage-functions=90` (verified to actually enforce: a deliberately-impossible threshold reproducibly exits non-zero with an explicit "does not meet threshold" error; current 98.60/90.91/93.51% clears all three with headroom).

## Automated Test Inventory

| Test Case ID | Module | Feature | Preconditions | Test Steps | Expected Result | Actual Result | Priority | Severity | Automation Status | Test Type | Test Script |
|---|---|---|---|---|---|---|---|---|---|---|---|
| UT-AUTH-001 | Auth routes | Password login decommissioned | Route module loaded | POST `/auth/login` | 410 with SSO message | TBD | P0 | Critical | Automated | Unit | `server/tests/unit/authRoutes.test.js` |
| UT-AUTH-002 | Auth routes | Verify unauthenticated | No valid auth | GET `/auth/verify` | 401 access denied | TBD | P0 | Critical | Automated | Unit | `server/tests/unit/authRoutes.test.js` |
| UT-AUTH-003 | Auth routes | Verify authenticated | Mock auth true | GET `/auth/verify` | 200 `{ ok: true }` | TBD | P0 | Critical | Automated | Unit | `server/tests/unit/authRoutes.test.js` |
| UT-AUTH-004 | Auth routes | Logout token revocation | Bearer/cookie token | POST `/auth/logout` | Token revoked, cookies cleared | TBD | P0 | High | Automated | Unit | `server/tests/unit/authRoutes.test.js` |
| UT-HEALTH-001 | Health route | Public health | Server ready | GET `/health` | Operational without internal metrics | TBD | P0 | High | Automated | Unit | `server/tests/unit/healthRoute.test.js` |
| UT-HEALTH-002 | Health route | Detailed health auth | No admin token | GET `/health-detailed` | 401 | TBD | P0 | High | Automated | Unit | `server/tests/unit/healthRoute.test.js` |
| UT-HEALTH-003 | Health route | Detailed health data | Admin auth true | GET `/health-detailed` | Memory, SES, metrics returned | TBD | P1 | Medium | Automated | Unit | `server/tests/unit/healthRoute.test.js` |
| UT-SEC-001 | Security | Cert ID validation | Security module loaded | Validate valid/invalid IDs | Accepts CST/VAP, rejects malformed | TBD | P0 | High | Automated | Unit | `server/tests/unit/security.test.js` |
| UT-SEC-002 | Security | Email/password validation | Security module loaded | Validate valid/invalid inputs | Strong policy enforced | TBD | P0 | High | Automated | Unit | `server/tests/unit/security.test.js` |
| UT-SEC-003 | Security | XSS sanitization | Security module loaded | Escape HTML metacharacters | Output is HTML-escaped | TBD | P0 | High | Automated | Unit | `server/tests/unit/security.test.js` |
| UT-SEC-004 | Security | JWT issue/verify | Key fixture | Issue, verify, tamper, expire token | Valid token accepted; invalid rejected | TBD | P0 | Critical | Automated | Unit | `server/tests/unit/security.test.js` |
| UT-SEC-005 | Security | Cert URL encryption/signing | Key fixture | Encrypt/decrypt/sign/verify | Round-trip succeeds; tamper fails | TBD | P0 | Critical | Automated | Unit | `server/tests/unit/security.test.js` |
| UT-SEC-006 | Security | Circuit breaker | Breaker fixture | Fail/succeed/fallback paths | Correct state transitions | TBD | P1 | Medium | Automated | Unit | `server/tests/unit/security.test.js` |
| UT-STORE-001 | JSON store | Missing file fallback | Temp file absent | Load store | Seed or `{}` returned and persisted | TBD | P1 | Medium | Automated | Unit | `server/tests/unit/jsonStore.test.js` |
| UT-STORE-002 | JSON store | Flush and cache | Temp file | Save, flush, reload | Data persisted and cache respected | TBD | P1 | Medium | Automated | Unit | `server/tests/unit/jsonStore.test.js` |
| UT-STORE-003 | S3 JSON store | Disk/seed fallback | S3 disabled | Init/load/flush | Local behavior works without S3 | TBD | P1 | Medium | Automated | Unit | `server/tests/unit/s3JsonStore.test.js` |
| UT-S3-001 | S3 service | Disabled mode | No S3 env | Call public methods | Clear "S3 not configured" errors | TBD | P1 | Medium | Automated | Unit | `server/tests/unit/s3JsonStore.test.js` |
| UT-S3-002 | S3 service | Enabled SigV4 requests | Mock HTTPS | Upload/download/put/get/delete | Signed native HTTPS requests sent | TBD | P1 | High | Automated | Unit | `server/tests/unit/s3Service.test.js` |
| UT-ENV-001 | Env config | Runtime validation | Config fixture | Validate ports/routes/passwords | Boundary and failure cases enforced | TBD | P0 | High | Automated | Unit | `server/tests/unit/env.test.js` |
| UT-ENV-002 | Env loader | `.env` parsing | Temp `.env` | Load quoted/plain/env parent values | Values loaded, existing env preserved | TBD | P1 | Medium | Automated | Unit | `server/tests/unit/env.test.js` |
| UT-MET-001 | Metrics | Counters/routes | Metrics fixture | Begin/end requests | Counters and route buckets update | TBD | P1 | Medium | Automated | Unit | `server/tests/unit/metrics.test.js` |
| IT-API-001 | API | Critical CST flow | Test server + tenant | Create, verify, update, attach, email-gate, delete | Expected 2xx/4xx/410 statuses | TBD | P0 | Critical | Automated | Integration | `server/tests/integration.test.js` |
| IT-API-002 | API | Critical VAPT flow | Test server + tenant | Create, attach, email-gate, delete | Expected 2xx statuses | TBD | P0 | Critical | Automated | Integration | `server/tests/integration.test.js` |
| IT-DOC-001 | Documents | Upload and superintendent access | Admin token + user session | Upload training/drill docs; list/download as supt | Correct docs and MIME/disposition | TBD | P0 | High | Automated | Integration | `server/tests/integration.test.js` |
| IT-SEC-001 | API security | CORS/auth/input validation | Test server | Unknown origin, unauth admin API, invalid IDs | CORS not reflected; 401/400/404 | TBD | P0 | Critical | Automated | Integration | `server/tests/integration.test.js` |
| UI-SMOKE-001 | UI | Static pages | Files present | Scan public/admin pages | Entrypoints and viewport tags exist | TBD | P1 | Medium | Automated | Static UI | `server/tests/static-assets.test.js` |
| UI-SMOKE-002 | UI | Broken first-party links | Files present | Scan `src`/`href` references | Referenced first-party assets exist | TBD | P1 | Medium | Automated | Static UI | `server/tests/static-assets.test.js` |
| UI-SMOKE-003 | UI | Accessibility hooks | CSS present | Scan responsive/focus CSS | Media queries and focus styles exist | TBD | P1 | Medium | Automated | Static UI | `server/tests/static-assets.test.js` |
| IT-VAPT-001 | VAPT/CST extras | Single-cert GET, verify-by-id, signed URL round-trip | Admin token / public | GET `/vapt/certs/:id`, `/verify-by-id/:id`, `/public-cert-url` → `/verify/:token` | Auth gated correctly; tampered signature → 403 | Pass | P1 | High | Automated | Integration | `server/tests/integration-vapt-extras.test.js` |
| IT-VAPT-002 | VAPT | CSV bulk import | Admin token | POST `/api/vapt/import-csv` | 200 with `added` count (BUG-001 fixed) | Pass | P1 | High | Automated | Integration | `server/tests/integration-vapt-extras.test.js` |
| IT-VAPT-003 | Engagement/tracking | Engagement stats, track-event, track-open pixel | Admin token / public | GET engagement, POST `/track-event`, GET `/track-open/:token` | Auth-gated correctly; pixel served; invalid input → 400 | Pass | P2 | Low | Automated | Integration | `server/tests/integration-vapt-extras.test.js` |
| IT-VAPT-004 | Attachments | Attachment deletion (CST + VAPT) | Admin token, cert with attachment | DELETE `/certs/:id/attachments/:idx` | 200, attachments array shrinks (BUG-002 fixed — route was unreachable) | Pass | P1 | High | Automated | Integration | `server/tests/integration-vapt-extras.test.js` |
| IT-ADMIN-001 | Admin/status | Public + admin stats | None / admin token | GET `/stats`, `/vapt/stats`, `/stats/quarterly`, `/vapt/stats/quarterly` | Public stats open by design; quarterly requires admin | Pass | P1 | Medium | Automated | Integration | `server/tests/integration-admin-status.test.js` |
| IT-ADMIN-002 | Admin/status | Integration status endpoints | Admin token | GET `/cognito-status`, `/s3-status`, `/ses-status`; POST `/admin/cognito-sync` | 401 unauth; correct config-status shape when authed | Pass | P1 | Medium | Automated | Integration | `server/tests/integration-admin-status.test.js` |
| IT-ADMIN-003 | Auth/decommission | Superadmin & password-login contracts | None | POST `/superadmin/login`, `/auth/user/login`; GET `/superadmin/verify` | 410 decommissioned | Pass | P1 | Medium | Automated | Integration | `server/tests/integration-admin-status.test.js` |
| IT-ADMIN-004 | Superintendent session | `auth/user/me`, logout | Session token | GET `/auth/user/me`, POST `/auth/user/logout` | 401 without session; 200 with correct user/vessel data; cookie cleared | Pass | P1 | High | Automated | Integration | `server/tests/integration-admin-status.test.js` |
| IT-ADMIN-005 | Docs token flows | temp-link + open + request-status | Admin token / signed token | GET `/docs/temp-link/:id`, `/docs/open/:token`, `/docs/request-status` | Signed round trip works; tampered/garbage tokens rejected safely, no 500 | Pass | P0 | High | Automated | Integration | `server/tests/integration-admin-status.test.js` |
| IT-ADMIN-006 | Docs lifecycle | PUT/DELETE doc metadata | Admin token | PUT/DELETE `/api/docs/:id` | 401 unauth; 200 update; 404 on re-delete | Pass | P1 | Medium | Automated | Integration | `server/tests/integration-admin-status.test.js` |
| IT-SECEDGE-001 | Security | Duplicate cert ID | Existing cert | POST same ID (CST + VAPT) | 409, original data preserved | Pass | P0 | Critical | Automated | Security/Integration | `server/tests/integration-security-edge.test.js` |
| IT-SECEDGE-002 | Security | Injection-shaped payloads | None | SQLi/XSS/path-traversal strings in cert ID & text fields | Rejected safely or stored as inert string; never 500 or unexpected 200 | Pass | P0 | Critical | Automated | Security/Integration | `server/tests/integration-security-edge.test.js` |
| IT-SECEDGE-003 | Security | Oversized payload resilience | None | ~11MB JSON field, ~65KB multipart field | 400 or connection reset; server verified healthy immediately after | Pass | P1 | High | Automated | Security/Integration | `server/tests/integration-security-edge.test.js` |
| IT-SECEDGE-004 | Security | Cross-vessel broken access control | Two groups/users (SEC-002) | `/supt/vessel/:imo/certs`, `/docs/by-vessel/:imo`, `/docs/download/:id` for a foreign vessel | 403 on all three; no data leak | Pass — confirmed secure | P0 | Critical | Automated | Security/Integration | `server/tests/integration-security-edge.test.js` |
| IT-SECEDGE-005 | Security | Rate-limit burst | None | ~35 rapid requests to `/verify-by-id` | 429 with `Retry-After` once threshold crossed | Pass | P1 | High | Automated | Security/Integration | `server/tests/integration-security-edge.test.js` |

## Manual and Exploratory Test Matrix

| Test Case ID | Module | Feature | Preconditions | Test Steps | Expected Result | Actual Result | Priority | Severity | Automation Status | Test Type | Test Script |
|---|---|---|---|---|---|---|---|---|---|---|---|
| API-001 | API | GET health | Server running | GET `/api/health` | 200, security headers, no sensitive counts | TBD | P0 | High | Automated | API | `server/tests/integration.test.js` |
| API-002 | API | GET detailed health | Admin token | GET `/api/health-detailed` | 200 with detailed metrics | TBD | P1 | Medium | Automated | API | `server/tests/unit/healthRoute.test.js` |
| API-003 | API | POST cert duplicate | Existing cert | POST same cert ID (CST + VAPT) | 409, original data preserved | Pass | P1 | High | Automated | API | `server/tests/integration-security-edge.test.js` |
| API-004 | API | SQL-injection-shaped payloads | Server running | Submit `' OR 1=1 --` / path-traversal-shaped strings in cert ID and text fields | Rejected (400/404) or safely stored as inert string; never 200 with unexpected data, never 500 | Pass | P0 | Critical | Automated | Security/API | `server/tests/integration-security-edge.test.js` |
| API-005 | API | XSS-shaped payloads | Server running | Submit `<script>alert(1)</script>` in text fields | Accepted and stored verbatim as a JSON string value (not executed — JSON responses aren't HTML); confirmed no server-side HTML-escaping occurs, so any frontend `innerHTML` rendering of these fields would need its own escaping (frontend not audited) | Pass | P0 | Critical | Automated | Security/API | `server/tests/integration-security-edge.test.js` |
| API-006 | API | Large JSON/multipart body | Server running | POST ~11MB JSON field and ~65KB multipart text field on cert create | Rejected (400) or connection reset at the 10MB `getBody()` cap; server verified healthy immediately after via follow-up `/api/health` call | Pass | P1 | High | Automated | API | `server/tests/integration-security-edge.test.js` |
| API-007 | API | Rate limiting | Server running | Burst ~35 requests to `/api/verify-by-id` (30/min bucket) | 429 with `Retry-After` header once threshold crossed | Pass | P1 | High | Automated | API/Security | `server/tests/integration-security-edge.test.js`, `server/tests/unit/healthRoute.test.js` |
| UI-001 | Public CST | Certificate lookup | Known CST cert | Search by cert ID | Correct certificate details/empty/error states | TBD | P0 | Critical | Manual | UI/Functional | Browser test candidate |
| UI-002 | Public VAPT | Certificate lookup | Known VAPT cert | Search by cert ID | Correct VAPT details/empty/error states | TBD | P0 | Critical | Manual | UI/Functional | Browser test candidate |
| UI-003 | Admin CST | Create/edit/delete cert | Admin SSO/session | Add, edit, attach PDF, delete | CRUD reflected in tables and API | TBD | P0 | Critical | Integration covered; UI manual | UI/E2E | Browser test candidate |
| UI-004 | Admin VAPT | Create/edit/delete cert | Admin SSO/session | Add, edit, attach PDF, delete | CRUD reflected in tables and API | TBD | P0 | Critical | Integration covered; UI manual | UI/E2E | Browser test candidate |
| UI-005 | Admin hub | Users/groups/docs tabs | Admin SSO/session | Navigate tabs, search, filter, upload | Controls work, empty/loading/error states visible | TBD | P1 | High | Static smoke | UI | `server/tests/static-assets.test.js` |
| UI-006 | Superintendent portal | Vessel docs/certs | User session | Login via SSO/session, view vessels and docs | Authorized vessels only | TBD | P0 | Critical | Integration covered; UI manual | UI/E2E | Browser test candidate |
| SEC-001 | Auth | Invalid/expired JWT | Server running | Use malformed, tampered, expired token | 401; no internal error | TBD | P0 | Critical | Automated | Security | `server/tests/unit/security.test.js` |
| SEC-002 | Access control | Broken access control | User assigned one vessel (Group A), another vessel exists (Group B) | Request `/api/supt/vessel/:imo/certs`, `/api/docs/by-vessel/:imo`, `/api/docs/download/:id` for the out-of-group vessel | 403 on all three; out-of-group vessel absent from `/api/supt/vessels`; own-vessel requests still 200 | Pass — no bypass found | P0 | Critical | Automated | Security | `server/tests/integration-security-edge.test.js` |
| SEC-003 | File upload | Malicious file | Admin token | Upload wrong magic/ext, oversized file, HTML disguised as PDF | Rejected; no executable inline content | TBD | P0 | Critical | Partially automated | Security | `server/tests/integration.test.js` |
| SEC-004 | CSRF | State-changing endpoints | Browser session | Cross-site POST without allowed origin/token | Request blocked by auth/CORS/SameSite | TBD | P0 | High | Manual | Security | Browser/proxy test |
| SEC-005 | Sensitive data | Public endpoints | No token | Browse API/public pages | No admin/user/email/internal keys leaked | TBD | P0 | Critical | Partially automated | Security | Integration/static smoke |
| PERF-001 | API response time | Health/verify | Seed data | 100 sequential GET requests | p95 under agreed SLA | TBD | P1 | Medium | Manual candidate | Performance | k6/autocannon script |
| PERF-002 | Load | Concurrent users | Seed data | 50/100/250 virtual users | Stable latency, no 5xx spike | TBD | P1 | High | Manual candidate | Performance | k6/autocannon script |
| PERF-003 | Stress/spike | Upload and search | Seed data | Sudden burst uploads/searches | Rate limits and memory remain stable | TBD | P1 | High | Manual candidate | Performance | k6/autocannon script |
| DB-001 | JSON persistence | CRUD durability | Temp tenant | Create/update/delete then restart | JSON data survives restart | TBD | P0 | High | Partially automated | Database/Persistence | Integration + store tests |
| DB-002 | S3 persistence | S3 enabled | Mock or test bucket | Init, save, flush, cold start | Remote copy restored | TBD | P1 | High | Mocked unit | Database/Persistence | `server/tests/unit/s3Service.test.js` |
| A11Y-001 | Keyboard | Public/admin pages | Browser | Tab through forms, modals, menus | Logical focus order, visible focus | TBD | P1 | High | Static partial | Accessibility | Browser test candidate |
| A11Y-002 | Screen reader | Forms/errors | Browser + SR | Trigger validation/errors | Labels and live regions announced | TBD | P1 | High | Manual | Accessibility | axe/Playwright candidate |
| A11Y-003 | Contrast | All pages | Browser | Run automated contrast audit | WCAG AA for text/controls | TBD | P1 | Medium | Manual | Accessibility | axe candidate |
| XB-001 | Cross-browser | Chrome/Edge/Firefox/Safari | Browsers available | Execute smoke and key E2E flows | Same layout and behavior | TBD | P1 | High | Manual | Cross-browser | Playwright candidate |
| MOB-001 | Responsive | Desktop/tablet/mobile | Browser dev tools/devices | Test 1440, 1024, 768, 390px widths | No overlap; controls usable | TBD | P1 | High | Static partial | Mobile | Playwright screenshot candidate |

## UAT Scenarios

| Scenario | User | Flow | Acceptance Criteria |
|---|---|---|---|
| UAT-001 | First-time admin | Open admin URL, sign in with AWS SSO, land on CST dashboard | SSO succeeds, dashboard loads, logout works |
| UAT-002 | Returning admin | Existing session opens admin dashboard | Session accepted until expiry; expired session redirects to sign-in |
| UAT-003 | Certificate manager | Create CST cert, attach PDF, send/gate email verification | Public lookup works; attachment requires email/download token |
| UAT-004 | VAPT manager | Create VAPT cert and verify public page | VAPT routes and VAPT admin remain separated from CST |
| UAT-005 | Superintendent | Open portal, view authorized vessels, download docs | Only assigned vessel data appears |
| UAT-006 | Document admin | Upload training and drill reports | Correct doc type, MIME type, and disposition are preserved |
| UAT-007 | Decommissioned captain access | Attempt old captain access request | 410 response explains workflow removal |

## Security Focus Areas

- OWASP A01 Broken Access Control: verify admin, superintendent, doc-token, and public route boundaries.
- OWASP A02 Cryptographic Failures: verify JWT signatures, certificate URL signatures, AES-GCM token handling, key persistence.
- OWASP A03 Injection: fuzz cert IDs, names, emails, CSV import, document metadata, query params.
- OWASP A05 Security Misconfiguration: verify CORS allowlist, CSP, HSTS, frame deny, no credentials in logs.
- OWASP A07 Identification/Auth Failures: expired/tampered JWTs, revoked logout tokens, SSO-only login behavior.
- OWASP A08 Integrity Failures: file magic checks, attachment disposition, S3 key prefix handling.
- OWASP A09 Logging/Monitoring: audit log generation, request metrics, no PII/key leakage.

## Defect Report Template

```text
Defect ID:
Title:
Environment:
Build/Commit:
Module:
Severity:
Priority:
Preconditions:
Steps to Reproduce:
Expected Result:
Actual Result:
Evidence:
Security/Compliance Impact:
Regression Risk:
Owner:
Status:
```

## Known Fixed Defects (this pass)

| ID | Title | Root Cause | Fix | Found By |
|---|---|---|---|---|
| BUG-001 | VAPT CSV import always 500'd | `for (const cert of records)` then reassigning `cert = sanitiseCertBody(cert)` — `TypeError: Assignment to constant variable` | Changed loop binding to `let` (`server/index.js`, `/api/vapt/import-csv` handler) | `integration-vapt-extras.test.js` |
| BUG-002 | Attachment-delete endpoints unreachable | Generic `DELETE /api/certs/:id` / `/api/vapt/certs/:id` matched via bare `route.startsWith(...)` with no segment-count guard, intercepting `.../attachments/:idx` requests before they reached the dedicated handler | Added explicit segment-count check (2 segments for CST, 3 for VAPT), matching the pattern already used by the sibling GET-single-cert handlers | `integration-vapt-extras.test.js` |

## Traceability Matrix

| Requirement / Risk | Automated Coverage | Manual / Future Coverage |
|---|---|---|
| Admin SSO-only auth | `authRoutes.test.js`, `integration.test.js` | Browser SSO callback tests |
| Public certificate verification | `integration.test.js`, `integration-vapt-extras.test.js` | Browser CST/VAPT search tests |
| CST/VAPT certificate CRUD | `integration.test.js`, `integration-vapt-extras.test.js`, `integration-security-edge.test.js` | Admin UI E2E |
| CSV bulk import (CST + VAPT) | `integration.test.js`, `integration-vapt-extras.test.js` | — |
| Email gate/download tokens | `integration.test.js`, `security.test.js` | SES sandbox/live delivery test |
| Document library and superintendent access | `integration.test.js`, `integration-admin-status.test.js` | Portal UI E2E |
| Cross-vessel broken access control | `integration-security-edge.test.js` (SEC-002 — no bypass found) | — |
| Admin/status endpoints (stats, cognito/s3/ses-status, cognito-sync) | `integration-admin-status.test.js` | — |
| Decommissioned-route contracts (superadmin, password login, captain access) | `integration.test.js`, `integration-admin-status.test.js` | — |
| Injection / oversized-payload resilience | `integration-security-edge.test.js` | — |
| File upload validation | `integration.test.js` | Malicious file corpus |
| Persistence durability | `jsonStore.test.js`, `s3JsonStore.test.js`, `s3Service.test.js` | Restart and real S3 bucket test |
| Runtime health/metrics | `healthRoute.test.js`, `metrics.test.js` | Production monitor checks |
| Static UI integrity | `static-assets.test.js` | Playwright visual/a11y tests |
| Security headers/CORS | `integration.test.js` | Browser/proxy validation |
| Performance under load | Not automated yet | k6/autocannon load suite |
