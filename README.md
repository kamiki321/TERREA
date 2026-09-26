# KRI KUJANG Hailing Log — FINAL Vercel Single Function

This package contains exactly one API Serverless Function: `api/index.js`. The complete backend is bundled inside that file.

## Required Vercel Environment Variables
- `DATABASE_URL` — Neon/PostgreSQL connection string
- `AUTH_JWT_SECRET` — random secret, minimum 32 characters
- `DEFAULT_ADMIN_USERNAME` — optional, default `kujang642`
- `DEFAULT_ADMIN_PASSWORD` — optional; if omitted, the existing built-in initial password hash is used

## API routes
`/api/health`, `/api/auth-login`, `/api/auth-refresh`, `/api/auth-logout`, `/api/auth-me`, `/api/records`, `/api/records/bulk-delete`, `/api/record?id=...`, `/api/operations`, `/api/operation?id=...`, `/api/import`

## Important
If deploying from GitHub, make sure the repository also has only `api/index.js`. An old `api/` directory with the previous route files will make Vercel detect multiple functions.
