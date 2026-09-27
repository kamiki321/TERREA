# Terrea Hailing Log — FINAL Vercel Single Function — LOGIN FIX v3.3.0

This package contains exactly one API Serverless Function: `api/index.js`. The complete backend is bundled inside that file.

## Required Vercel Environment Variables
- `DATABASE_URL` — Neon/PostgreSQL connection string
- `AUTH_JWT_SECRET` — recommended: random secret, minimum 32 characters. If omitted, this package derives a stable fallback from the private database URL so login still works.
- `DEFAULT_ADMIN_USERNAME` — optional, default `kujang642`
- `DEFAULT_ADMIN_PASSWORD` — optional; if omitted, the existing built-in initial password hash is used

## API routes
`/api/health`, `/api/auth-login`, `/api/auth-refresh`, `/api/auth-logout`, `/api/auth-me`, `/api/records`, `/api/records/bulk-delete`, `/api/record?id=...`, `/api/operations`, `/api/operation?id=...`, `/api/import`

## Important
If deploying from GitHub, make sure the repository also has only `api/index.js`. An old `api/` directory with the previous route files will make Vercel detect multiple functions.

## Login fix in this build
The previous build could return HTTP 500 during `/api/auth-login` when `AUTH_JWT_SECRET` was missing. This build uses `AUTH_JWT_SECRET` when available and otherwise derives a stable HMAC secret from the private PostgreSQL connection string. `DATABASE_URL` must still be configured. For production security, set your own random `AUTH_JWT_SECRET` (32+ characters).


## Login v3.2.0 fix
The login endpoint no longer calls the full application initialization/seed routine. It initializes only the authentication tables (`user` and `user_sessions`). This prevents unrelated hailing/master-data initialization errors from causing `/api/auth-login` to return HTTP 500. The login query also reads only the authentication columns it actually needs. Refresh, logout, and auth-me use the same auth-only initialization path.


## v3.3.0 login fix
- CORS headers are applied directly inside route handlers; no route depends on a `cors()` imported helper.
- Login UI now displays the actual API error returned by the server instead of masking every error as a wrong username/password.
