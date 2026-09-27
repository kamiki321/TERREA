# TERREA Hailing v7.0.0 — Deployment Checklist

## 1. Upload the project root

The Vercel **Root Directory must be the folder containing these files**:

- `package.json`
- `vercel.json`
- `api/index.js`
- `index.html`
- `data/master.json`

Do not set Root Directory to `api/`.

## 2. Vercel Environment Variables

Set these for **Production** (and Preview if you test Preview deployments):

- `DATABASE_URL` = Neon PostgreSQL connection string
- `AUTH_JWT_SECRET` = random secret of at least 32 characters
- `DEFAULT_ADMIN_USERNAME` = `kujang642` (or your chosen username)
- `DEFAULT_ADMIN_PASSWORD` = `Kujang642Satkat1#` (or your chosen password that meets the rule)

## 3. Redeploy without cache

After uploading/deploying this version, use **Redeploy** and disable the existing build cache if that option is shown.

## 4. Expected API checks

Open these in the browser or DevTools:

- `GET /api/health` → JSON response with `database: "neon-postgresql"`
- `POST /api/auth-login` → HTTP 200 with `accessToken` and `user`
- `POST /api/auth-refresh` → HTTP 200 after a successful login
- `GET /api/auth-me` with Bearer access token → HTTP 200

## 5. Important v7 fix

The Neon driver is imported as a **top-level static dependency** in `api/index.js`:

`const { neon: __neon } = require('@neondatabase/serverless');`

This is intentional. The previous custom runtime module loader hid the Neon `require()` inside a bundled module factory, which can prevent a Vercel Node bundler from including the dependency correctly.

The dependency is pinned to `@neondatabase/serverless` **1.1.0**, not `latest`.

## 6. Login flow tested locally

The final source was syntax-checked and the authentication flow was smoke-tested with a Neon-driver mock:

- fresh database → auth tables created
- default user creation
- password verification
- access JWT creation
- refresh cookie creation
- `/auth-me`
- refresh-token rotation
- old refresh-token reuse rejected with HTTP 401

The smoke test does not replace a live Neon/Vercel test; the final live test must use your Vercel Environment Variables.
