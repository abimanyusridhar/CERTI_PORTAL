# Stack Decision Checkpoint

## Scope

This checkpoint captures the post-modularization decision for the current certificate portal stack.

## What Was Improved

- Server responsibilities were split into modular layers:
  - `server/config/env.js`
  - `server/logger.js`
  - `server/repositories/jsonStore.js`
  - `server/services/security.js`
  - `server/routes/health.js`
  - `server/routes/auth.js`
  - `server/ops/metrics.js`
- Runtime hardening now includes:
  - config validation before server start
  - request IDs in logs
  - minimal request/error/latency metrics exposed via `/api/health`
  - safer startup and shutdown flow

## Decision

Stay on Node.js for the current stage and continue incremental modernization.

## Why This Is The Right Choice Now

- Current load profile is small and does not justify a costly platform rewrite.
- Risk is currently dominated by maintainability and release speed, not runtime limits.
- Modularization already reduced coupling while preserving API behavior.
- Spring Boot migration would duplicate business logic and increase short-term delivery risk.

## Re-Evaluate Spring Boot If

- Throughput and HA requirements grow significantly.
- Enterprise Java governance becomes a hard requirement.
- JVM ecosystem observability/integration is mandated by the platform team.

## Next Steps

- Move remaining route groups from `server/index.js` into dedicated route modules.
- Add a database-backed repository implementation behind the same repository interfaces.
- Expand integration tests to cover VAPT CRUD and attachment flows.
