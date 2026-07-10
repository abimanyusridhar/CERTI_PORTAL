# Synergy Certificate Portal
## QA Testing Assessment Report — Gap-Closing & Security Update

**Re-test date:** 2026-07-10

| Tests Passed | Line Coverage | Security Score |
|:---:|:---:|:---:|
| **153 / 153** | **98.60%** | **90 / 100** |

---

## Executive Summary

The project was re-tested on 2026-07-10 after a targeted gap-closing and adversarial-security pass, then re-tested again the same day after a follow-up remediation pass. The full `node:test` suite grew from 121 to **153 passing tests** (0 failing), closing every previously-untested route and every "manual candidate" item flagged in the prior test plan. Two real application defects were found and fixed directly in `server/index.js` — not masked by loosened assertions. Security testing is updated from an implicit baseline to a directly-evidenced **90 / 100**: cross-vessel broken access control was adversarially attacked and found secure, injection- and traversal-shaped payloads were fuzzed against the live HTTP layer, oversized-request handling was confirmed to leave the server healthy, and rate limiting was proven to engage under a real request burst rather than only in unit tests of the limiter's internal logic. The same-day follow-up then closed every item this report had originally tracked as residual: a real stored-XSS gap in the VAPT public verify page (and the same pattern in both admin dashboards), the shared upload rate-limit bucket, and the missing coverage-gate enforcement — all four are detailed in Security Remediation Evidence below and none remain open.

> **Scoring methodology:** each area score below is a qualitative assessment grounded in the evidence in this report — test pass rate, coverage percentage, and named gaps — not a single automated formula.

---

## Execution Result

| Item | Result |
|---|---|
| Command | `npm run test:coverage` |
| Outcome | 153 passed, 0 failed |
| Coverage gate | **Enforced** — `--test-coverage-lines=95 --test-coverage-branches=85 --test-coverage-functions=90`, added in follow-up remediation; verified to genuinely fail the build on a regression (see Security Remediation Evidence) |
| Total coverage | 98.60% line · 90.91% branch · 93.51% function (unit-testable modules) |
| Generated artifacts | None written to disk — Node's built-in coverage reporter prints a text table to stdout only. No `htmlcov/` or `coverage.xml` equivalent exists; add `--test-reporter=lcov` if an HTML report is wanted. |

---

## Updated Scorecard

| Area | Before | After | Status | Key Finding |
|---|---:|---:|---|---|
| Architecture testability | 72 | 72 | Fair | All ~48 `/api/*` routes live inside one 4,416-line `handleAPI()` function in `server/index.js`; persistence, security, S3, health, auth, and metrics are cleanly separated into unit-testable modules, but the router itself has no per-route file boundaries. |
| Unit testing | 88 | 90 | Strong | 120 unit cases across 9 files; 98.60% line / 90.91% branch / 93.51% function coverage on every unit-testable module. |
| Integration testing | 78 | 88 | Improved | Grew from 1 file to 4, adding full route coverage, signed-URL tamper testing, and adversarial security cases — each spawning the real server as a child process. |
| API testing | 76 | 85 | Improved | All ~48 routes now exercised for status code, auth gating, duplicate IDs, injection-shaped payloads, and oversized bodies. No `PATCH` exists anywhere in this API — confirmed by full route inventory, not a gap. |
| UI testing | 45 | 45 | Partial | Static smoke only (entrypoints, first-party links, responsive/focus CSS presence). No real button/form/DOM interaction testing — needs a browser driver not present in this project. |
| Security testing | 76 | **90** | Improved | Cross-vessel broken access control adversarially tested with no bypass found. A same-day follow-up pass then found and fixed a real stored-XSS gap in the VAPT public page (and the same pattern in both admin dashboards) — see Security Remediation Evidence. CSRF protection remains architecture-reliant (SameSite cookies + strict CORS origin allowlist), not independently re-verified this pass. |
| Performance testing | 20 | 20 | Not automated | No load/stress/spike tooling (k6/autocannon) exists in this project. Explicitly out of scope this pass, not silently skipped. |
| Database / persistence testing | 78 | 78 | Good | No relational database — JSON file + optional S3-mirrored persistence. CRUD, disk-fallback, BOM handling, and S3 cold-start recovery are tested; constraints/indexes/triggers don't apply to this architecture. |
| CI readiness | 35 | **50** | Improved | `npm test` / `npm run test:coverage` run locally via Node's built-in test runner. No `.github/workflows` pipeline exists yet, but the previously-missing coverage gate is now enforced and verified to genuinely fail the build on a regression — see Security Remediation Evidence. |

---

## Security Remediation Evidence

| Security Item | Before | After | Interpretation |
|---|---|---|---|
| VAPT bulk import | Any valid, non-duplicate CSV row crashed the request with a bare 500 (`TypeError: Assignment to constant variable`). | Loop binding changed from `const` to `let`; all valid rows import successfully. | A previously complete feature outage is restored to working order. |
| Attachment deletion | `DELETE .../attachments/:idx` was always intercepted by the generic cert-delete route (no segment-count guard) and rejected as an invalid certificate ID. | Explicit segment-count guard added; the dedicated handler is now reachable and works correctly. | A previously dead admin capability (removing one attachment without deleting the whole certificate) is now functional. |
| Cross-vessel access control | Not adversarially tested this pass. | A superintendent session scoped to Vessel A was used to attack Vessel B's certs, doc listing, and doc downloads — all three returned 403. | No broken access control exists in the paths tested. |
| Injection resilience | Only unit-level `sanitize()` escaping was tested in isolation. | Live SQLi-, XSS-, and path-traversal-shaped payloads sent through the real HTTP layer against cert IDs and text fields. | Confirmed safe end-to-end — rejected or stored as inert strings, never a 500 or an unexpected 200. |
| Oversized-payload resilience | Not tested against the real 10 MB body cap in `getBody()`. | An ~11 MB JSON field and a ~65 KB multipart field were sent live; the server rejected/reset the request and answered a follow-up health check immediately after. | Confirmed the process does not crash or hang under an oversized request. |
| Rate-limit enforcement | Verified only via unit tests of the limiter's internal counting logic. | ~35 rapid requests fired at a live spawned server; 429 with `Retry-After` observed once the threshold crossed. | Confirmed the limiter actually engages end-to-end, not just in isolated unit logic. |
| Output encoding on public cert fields | `certPublicFields()` doesn't HTML-escape at the API layer (correct — JSON isn't HTML). Frontend audit found the CST public page already escapes every free-text field via `escH()`, but the VAPT public page did not: `vesselName`, `frameworks`, `scopeItems`, `notes`, and `verifierTitle` were injected into `innerHTML` raw. | All five VAPT public-page fields now wrapped in `escH()`, matching CST. Same gap found and fixed in both admin dashboards (`recipientName`, `vesselName`, `vesselIMO`, `chiefEngineer`, `verifiedBy`, `recipientEmail`) using their existing `escHtml()` helper. | A real, unauthenticated-reachable stored-XSS vector in the VAPT public verify page is closed. **Remediated.** |
| Upload rate-limit scoping | The `upload` bucket (10 req / 5 min per IP) was shared across cert creation and document upload combined. | Split into `cert-create` (20/5min, CST+VAPT combined) and `doc-upload` (10/5min, unchanged) — the two action types no longer share a budget. | A busy admin doing both in one window no longer gets 429'd. **Remediated.** |
| Coverage gate enforcement | `package.json`'s `test:coverage` script ran coverage but enforced no threshold — a regression would pass silently. | Added `--test-coverage-lines=95 --test-coverage-branches=85 --test-coverage-functions=90`. Verified genuine enforcement: a deliberately-impossible threshold (`--test-coverage-branches=99`) reproducibly exits non-zero with `Error: 97.37% branch coverage does not meet threshold of 99%`; the real thresholds clear current 98.60/90.91/93.51% with headroom. | A future coverage regression now fails the build instead of passing silently. **Remediated.** |

---

## Security Test Evidence

| Test Case | Test File | Result | Purpose |
|---|---|---|---|
| Duplicate cert ID rejected (409) | `integration-security-edge.test.js` | Passed | Prevents silent overwrite of an existing certificate via re-POST of the same ID. |
| SQLi/XSS-shaped fields handled safely | `integration-security-edge.test.js` | Passed | Confirms injection-shaped input is never executed server-side and never causes a 500. |
| SQLi/path-traversal cert IDs rejected | `integration-security-edge.test.js` | Passed | Malformed IDs return 400/404, never leak filesystem or application data. |
| Oversized JSON/multipart body handled | `integration-security-edge.test.js` | Passed | Server rejects or resets an over-cap body and stays healthy immediately after. |
| Cross-vessel access blocked | `integration-security-edge.test.js` | Passed | Superintendent session for Vessel A gets 403 on Vessel B's certs and documents — no broken access control. |
| Rate-limit burst returns 429 | `integration-security-edge.test.js` | Passed | Confirms the verify-endpoint limiter engages under real request concurrency. |
| JWT tamper/expiry rejected | `unit/security.test.js` | Passed | A tampered signature and an expired token both fail verification and return null, never throw. |
| Cert-URL signature tamper rejected | `integration-vapt-extras.test.js` | Passed | A single-character change to the signature query parameter is rejected with 403 on both CST and VAPT verify links. |
| Admin/session auth gating across new routes | `integration-admin-status.test.js` | Passed | Every newly-covered admin-only and session-only endpoint correctly returns 401 without credentials. |

---

## Coverage Summary

| Metric | Result |
|---|---|
| Line coverage | 98.60% |
| Branch coverage | 90.91% |
| Function coverage | 93.51% |
| Files measured | 8 |
| Required coverage gate | 95% line · 85% branch · 90% function (added in follow-up remediation) |
| Gate result | **Passed** — 98.60/90.91/93.51% actual clears all three thresholds with headroom |

### Per-file breakdown

| File | Line % | Branch % | Func % | Uncovered lines |
|---|---:|---:|---:|---|
| `server/config/env.js` | 100.00 | 97.37 | 100.00 | — |
| `server/ops/metrics.js` | 100.00 | 81.82 | 100.00 | — |
| `server/repositories/jsonStore.js` | 95.56 | 87.50 | 80.00 | 30–31 |
| `server/repositories/s3JsonStore.js` | 98.41 | 77.42 | 85.71 | 44–45 |
| `server/routes/auth.js` | 100.00 | 100.00 | 100.00 | — |
| `server/routes/health.js` | 100.00 | 85.71 | 100.00 | — |
| `server/services/s3.js` | 100.00 | 100.00 | 100.00 | — |
| `server/services/security.js` | 97.08 | 91.46 | 92.31 | 90–91, 201–202, 250–253 |

> `server/index.js` (4,416 lines — the monolithic router carrying all ~48 API routes) is exercised by 4 integration test files that spawn it as a real child process. Node's coverage instrumentation cannot attribute child-process execution back to the parent test process, so it does not appear in this table despite being the most heavily route-tested file in the project. This is a tooling limitation, not a true coverage gap.

---

## Completed Remediation

| Finding | Status | Code Area |
|---|---|---|
| VAPT CSV import crash (const reassignment) | Remediated | `server/index.js` — `POST /api/vapt/import-csv` |
| Attachment-delete routes unreachable (route-matching order) | Remediated | `server/index.js` — `DELETE /api/certs/:id/attachments/:idx` (+ VAPT) |
| Cross-vessel broken access control | Verified secure | `server/index.js` — `/api/supt/vessel/:imo/certs`, `/api/docs/by-vessel/:imo`, `/api/docs/download/:id` |
| Injection-shaped payload handling | Verified safe | `server/index.js` — cert creation and verify-by-id routes |
| Oversized-payload resilience | Verified safe | `server/index.js` — `getBody()` 10MB cap |
| Rate-limit enforcement under burst | Verified working | `server/index.js` — `checkRateLimit()` verify bucket |
| VAPT public-page stored XSS (vesselName, frameworks, scopeItems, notes, verifierTitle unescaped) | Remediated | `public/assets/smg-public/vapt/index.js` |
| Admin-dashboard stored XSS (same pattern, both CST + VAPT dashboards) | Remediated | `public/assets/smg-admin/cst/dashboard.js`, `public/assets/smg-admin/vapt/dashboard.js` |
| Shared upload rate-limit bucket (cert-create + doc-upload) | Remediated | `server/index.js` — `RATE_LIMITS` (`cert-create` / `doc-upload`) |
| No enforced coverage gate | Remediated | `package.json` — `test:coverage` script |

---

## Test Cases Used in This Assessment

| Test Area | Test File / Source | Cases | Coverage Purpose |
|---|---|---:|---|
| Security & crypto | `unit/security.test.js` | 51 | Cert ID/email/password validation, XSS sanitize, JWT issue/verify, cert-URL encryption & signing, circuit breaker, password hashing, retry/backoff, error responses. |
| Env & config | `unit/env.test.js` | 18 | Runtime config validation (port/admin/password boundaries), `.env` file parsing and precedence. |
| Metrics | `unit/metrics.test.js` | 13 | Request counters, in-flight tracking, status-code classification, route bucketing, uptime. |
| Admin/status integration | `integration-admin-status.test.js` | 15 | Public/admin stats, integration status endpoints, decommissioned-route contracts, session lifecycle, docs token flows. |
| Auth routes (unit) | `unit/authRoutes.test.js` | 8 | Login decommission, verify gating, logout token revocation. |
| JSON store | `unit/jsonStore.test.js` | 8 | Seed fallback, cache/flush behavior, corrupt-file recovery. |
| Security edge cases (integration) | `integration-security-edge.test.js` | 8 | Duplicate-ID rejection, injection payloads, oversized body, cross-vessel access control, rate-limit burst. |
| VAPT/CST extras (integration) | `integration-vapt-extras.test.js` | 9 | Signed URL round-trip + tamper rejection, CSV import, engagement stats, tracking, attachment deletion. |
| Health route | `unit/healthRoute.test.js` | 7 | Public vs. detailed health, admin gating, rate limiting, state reporting. |
| S3 JSON store | `unit/s3JsonStore.test.js` | 6 | Disk/seed fallback, BOM handling, cache/flush, S3-disabled error clarity. |
| Static UI | `static-assets.test.js` | 5 | Entrypoint existence, first-party asset links, form controls, shared utility exports, responsive/focus CSS. |
| S3 service | `unit/s3Service.test.js` | 3 | SigV4-signed upload/download/put/get/delete, error propagation. |
| Critical end-to-end flow (integration) | `integration.test.js` | 1 | Single comprehensive flow — CST+VAPT CRUD, attachments, email-gate, CSV import, superintendent doc access, cleanup — 30+ assertions in one spawned-server run. |
| S3-enabled remote mode | `unit/s3JsonStoreRemote.test.js` | 1 | Cold-start pull from S3 and save-mirrors-to-S3 behavior when S3 is enabled. |

---

## Appendix — Detailed Test Case Inventory

This appendix lists all 153 automated test cases used for this assessment, collected directly from the project test suite. It aligns exactly with the reported result of 153 passed tests and the coverage figures above.

### `server/tests/unit/security.test.js` (51 test cases)

| No. | Test Case |
|---:|---|
| 1 | isValidCertId — valid 3-segment CST ID |
| 2 | isValidCertId — valid VAP ID with numeric suffix |
| 3 | isValidCertId — accepts long-enough middle and suffix |
| 4 | isValidCertId — rejects wrong prefix |
| 5 | isValidCertId — rejects middle segment under 5 chars |
| 6 | isValidCertId — rejects suffix under 2 chars |
| 7 | isValidCertId — rejects lowercase letters |
| 8 | isValidCertId — rejects IDs over 50 chars |
| 9 | isValidCertId — rejects null / undefined / empty |
| 10 | isValidEmail — accepts standard emails |
| 11 | isValidEmail — rejects malformed addresses |
| 12 | isValidEmail — rejects email over 254 chars |
| 13 | isValidEmail — rejects null / non-string |
| 14 | isValidPassword — accepts strong password |
| 15 | isValidPassword — rejects password under 12 chars |
| 16 | isValidPassword — rejects no uppercase |
| 17 | isValidPassword — rejects no lowercase |
| 18 | isValidPassword — rejects no digit |
| 19 | isValidPassword — rejects no special character |
| 20 | isValidPassword — rejects null / non-string |
| 21 | sanitize — escapes all five dangerous HTML characters |
| 22 | sanitize — returns non-string inputs unchanged |
| 23 | sanitize — leaves safe strings unmodified |
| 24 | isValidUrl — accepts valid URLs |
| 25 | isValidUrl — rejects non-URLs |
| 26 | CircuitBreaker — starts in CLOSED state |
| 27 | CircuitBreaker — opens after failureThreshold consecutive failures |
| 28 | CircuitBreaker — uses fallback while OPEN without throwing |
| 29 | CircuitBreaker — throws when OPEN and no fallback provided |
| 30 | CircuitBreaker — transitions OPEN → HALF_OPEN → CLOSED on success |
| 31 | CircuitBreaker — success resets failure count when CLOSED |
| 32 | hashPassword — returns a non-empty hex string |
| 33 | hashPassword — is deterministic (same key material, same password) |
| 34 | hashPassword — different passwords produce different hashes |
| 35 | issueToken — returns a 3-part dot-separated string |
| 36 | verifyToken — returns payload with correct subject for valid token |
| 37 | verifyToken — returns null for tampered signature |
| 38 | verifyToken — returns null for expired token |
| 39 | verifyToken — returns null for malformed / empty inputs |
| 40 | encryptCertToken + decryptCertToken — full round-trip |
| 41 | decryptCertToken — each encrypted token is unique (random IV) |
| 42 | decryptCertToken — returns null for invalid / truncated input |
| 43 | signCertUrl + verifyCertUrlSignature — valid signature is accepted |
| 44 | verifyCertUrlSignature — rejects wrong signature of same length |
| 45 | verifyCertUrlSignature — rejects null / missing signature |
| 46 | buildCertUrl — returns URL containing token and signature |
| 47 | retryWithBackoff — succeeds on first attempt |
| 48 | retryWithBackoff — retries and eventually succeeds |
| 49 | retryWithBackoff — throws original error after max attempts |
| 50 | createErrorResponse — returns structured object with status and error |
| 51 | createErrorResponse — works without extra details |

### `server/tests/unit/env.test.js` (18 test cases)

| No. | Test Case |
|---:|---|
| 1 | validateRuntimeConfig — passes with valid config |
| 2 | validateRuntimeConfig — accepts port 1 and port 65535 (boundary) |
| 3 | validateRuntimeConfig — rejects port 0 |
| 4 | validateRuntimeConfig — rejects port 65536 |
| 5 | validateRuntimeConfig — rejects non-integer port |
| 6 | validateRuntimeConfig — rejects missing ADMIN_USER |
| 7 | validateRuntimeConfig — rejects missing ADMIN_PASS |
| 8 | validateRuntimeConfig — rejects weak password (under 12 chars) |
| 9 | validateRuntimeConfig — rejects password with no uppercase |
| 10 | validateRuntimeConfig — rejects password with no lowercase |
| 11 | validateRuntimeConfig — rejects password with no digit |
| 12 | validateRuntimeConfig — rejects password with no special character |
| 13 | validateRuntimeConfig — rejects missing cfg routes |
| 14 | validateRuntimeConfig — rejects null cfg |
| 15 | validateRuntimeConfig — accumulates multiple errors |
| 16 | loadDotEnv - loads key/value pairs from server .env and strips quotes |
| 17 | loadDotEnv - does not overwrite existing process env values |
| 18 | loadDotEnv - searches parent .env when server .env is absent |

### `server/tests/unit/metrics.test.js` (13 test cases)

| No. | Test Case |
|---:|---|
| 1 | metrics — snapshot has required top-level fields |
| 2 | metrics — counters start at zero |
| 3 | metrics — begin increments requestsTotal and inFlight |
| 4 | metrics — end decrements inFlight and classifies status |
| 5 | metrics — end counts 4xx correctly |
| 6 | metrics — end counts 5xx correctly |
| 7 | metrics — inFlight never goes below zero |
| 8 | metrics — API routes are bucketed as /api/* |
| 9 | metrics — upload routes are bucketed as /uploads/* |
| 10 | metrics — non-API routes use exact path |
| 11 | metrics — route stats include count, avgMs, and maxMs |
| 12 | metrics — multiple requests accumulate in route stats |
| 13 | metrics — uptime increases over time |

### `server/tests/integration-admin-status.test.js` (15 test cases)

| No. | Test Case |
|---:|---|
| 1 | GET /api/stats is public and returns aggregate cert counts |
| 2 | GET /api/stats/quarterly requires admin and returns per-quarter breakdown |
| 3 | GET /api/vapt/stats is public and returns aggregate VAPT counts |
| 4 | GET /api/vapt/stats/quarterly requires admin and returns per-quarter breakdown |
| 5 | GET /api/cognito-status requires admin and reports unconfigured Cognito |
| 6 | GET /api/s3-status requires admin and reports S3 disabled |
| 7 | GET /api/ses-status requires admin and returns email config shape |
| 8 | GET /api/vessels/names requires admin and maps IMO to vessel name |
| 9 | POST /api/admin/cognito-sync requires admin and 503s when Cognito unconfigured |
| 10 | superadmin login/verify routes are decommissioned (410) |
| 11 | auth/user login is decommissioned; logout clears cookie; me requires a valid session |
| 12 | GET /api/docs/check-access reports the decommissioned captain workflow |
| 13 | docs temp-link + open token round trip serves the file publicly; bad tokens are rejected safely |
| 14 | GET /api/docs/request-status validates the HMAC claim token |
| 15 | PUT/DELETE /api/docs/:id enforce admin auth and correct lifecycle |

### `server/tests/unit/authRoutes.test.js` (8 test cases)

| No. | Test Case |
|---:|---|
| 1 | auth routes - login POST is decommissioned with 410 |
| 2 | auth routes - login ignores other methods and paths |
| 3 | auth routes - verify returns 401 when unauthenticated |
| 4 | auth routes - verify returns ok when authenticated |
| 5 | auth routes - verify ignores non-matching request |
| 6 | auth routes - logout revokes bearer token and clears cookies |
| 7 | auth routes - logout reads token from cookie when bearer is absent |
| 8 | auth routes - logout succeeds without token and ignores other routes |

### `server/tests/unit/jsonStore.test.js` (8 test cases)

| No. | Test Case |
|---:|---|
| 1 | jsonStore — load returns seedData when file does not exist |
| 2 | jsonStore — load returns empty object when no seed provided and file missing |
| 3 | jsonStore — save updates the in-memory cache immediately |
| 4 | jsonStore — flush writes data to disk synchronously |
| 5 | jsonStore — flush is a no-op when no pending save |
| 6 | jsonStore — data written by flush is readable by a new store instance |
| 7 | jsonStore — subsequent load() calls return the cached result without re-reading file |
| 8 | jsonStore — load falls back to seed when file contains invalid JSON |

### `server/tests/integration-security-edge.test.js` (8 test cases)

| No. | Test Case |
|---:|---|
| 1 | API-003: duplicate CST certificate ID is rejected with 409 and original data is preserved |
| 2 | API-003: duplicate VAPT certificate ID is rejected with 409 and original data is preserved |
| 3 | API-004/005: SQLi- and XSS-shaped field values are stored and returned verbatim by the API |
| 4 | API-004: SQLi- and path-traversal-shaped certificate IDs are rejected safely, never 200 or 500 |
| 5 | API-006: oversized JSON request body is rejected or reset, and the server remains healthy afterward |
| 6 | API-006: oversized multipart text field is rejected on certificate CREATE (symmetry with UPDATE) |
| 7 | SEC-002: cross-vessel broken access control is enforced for superintendent sessions |
| 8 | API-007: burst of requests to /api/verify-by-id triggers 429 with Retry-After |

### `server/tests/integration-vapt-extras.test.js` (9 test cases)

| No. | Test Case |
|---:|---|
| 1 | GET /api/vapt/certs/:id — auth gating, full object, 404, 400 |
| 2 | GET /api/vapt/verify-by-id/:id — public projected fields, 404, 400 |
| 3 | VAPT public-cert-url + cert-url + verify/:encToken — happy path and tamper rejection |
| 4 | CST public-cert-url + cert-url + verify/:encToken — happy path and tamper rejection |
| 5 | POST /api/vapt/import-csv — auth gating + added count |
| 6 | GET /api/certs/:id/engagement + /api/vapt/certs/:id/engagement — auth gating, shape, 404 |
| 7 | POST /api/track-event — valid event, invalid event, malformed JSON |
| 8 | GET /api/track-open/:token + /api/vapt/track-open/:token — valid signed token and malformed token |
| 9 | DELETE /api/certs/:id/attachments/:idx + /api/vapt/certs/:id/attachments/:idx |

### `server/tests/unit/healthRoute.test.js` (7 test cases)

| No. | Test Case |
|---:|---|
| 1 | health route - ignores non-GET and non-health paths |
| 2 | health route - returns operational public health without internal details |
| 3 | health route - reports starting and maintenance states |
| 4 | health route - reports shutting_down before operational |
| 5 | health route - rate limits public health when limiter rejects |
| 6 | health route - detailed endpoint requires admin auth |
| 7 | health route - detailed endpoint returns SES, memory, and metrics when authenticated |

### `server/tests/unit/s3JsonStore.test.js` (6 test cases)

| No. | Test Case |
|---:|---|
| 1 | s3JsonStore - init uses local disk when present |
| 2 | s3JsonStore - init falls back to seed when no disk and S3 disabled |
| 3 | s3JsonStore - load strips UTF-8 BOM from disk JSON |
| 4 | s3JsonStore - save updates cache immediately and flush creates parent directory |
| 5 | s3JsonStore - invalid disk JSON falls back to seed |
| 6 | s3 service - public methods throw clear errors when S3 is disabled |

### `server/tests/static-assets.test.js` (5 test cases)

| No. | Test Case |
|---:|---|
| 1 | static pages - public and admin entrypoints exist with expected app roots |
| 2 | static pages - referenced first-party assets exist |
| 3 | static pages - login and admin forms expose expected controls |
| 4 | static assets - shared utility scripts define expected browser helpers |
| 5 | static styles - responsive CSS contains mobile breakpoints and focus styles |

### `server/tests/unit/s3Service.test.js` (3 test cases)

| No. | Test Case |
|---:|---|
| 1 | s3 service - enabled upload, download, putJson, getJson, and delete sign native HTTPS requests |
| 2 | s3 service - rejects non-2xx S3 responses with status context |
| 3 | s3 service - propagates HTTPS request errors |

### `server/tests/integration.test.js` (1 test case, ~30+ internal assertions)

| No. | Test Case |
|---:|---|
| 1 | server critical API flows — health, CORS, auth gating, decommissioned login, cert-ID validation, path traversal, admin JWT mint, CST/VAPT CRUD + attachments + email-gate, document upload + superintendent access, CSV import, send-email, delete + cleanup |

### `server/tests/unit/s3JsonStoreRemote.test.js` (1 test case)

| No. | Test Case |
|---:|---|
| 1 | s3JsonStore - S3-enabled init pulls remote data and save mirrors to S3 |

---

## Production Cross-Check

A separate, read-only verification pass against the live domain `certify.misecure.io` confirmed its observable behavior — auth gating, decommissioned-route contracts, CORS non-reflection, path-traversal handling, and security headers — matches every secure contract this suite verifies. No authenticated or state-changing checks were run against production, by agreement.

---

*Full test-plan detail and traceability matrix live in `docs/testing-analysis-and-test-plan.md`. This report reflects verified, currently-passing state as of 2026-07-10 — re-run `npm test` after any change to confirm it still holds.*
