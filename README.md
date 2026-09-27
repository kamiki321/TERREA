# TERREA Hailing Log — Vercel Single Function

Versi ini menggunakan **Neon PostgreSQL untuk seluruh data aplikasi, termasuk authentication**.

## Arsitektur

- Tepat 1 Serverless Function: `api/index.js`
- Database: Neon PostgreSQL via `@neondatabase/serverless`
- Hailing records, vessels, operations: Neon
- User login dan refresh sessions: Neon (`user`, `user_sessions`)
- Password: scrypt hash, tidak disimpan plaintext
- Access token: JWT HS256
- Refresh token: random opaque token, disimpan hanya sebagai SHA-256 hash di Neon dan dikirim melalui HttpOnly Secure cookie

## Fresh database

Tidak perlu membuat tabel auth secara manual. Saat login pertama kali, API akan:

1. membuat tabel `user` dan `user_sessions` jika belum ada;
2. membuat akun administrator dari `DEFAULT_ADMIN_USERNAME` / `DEFAULT_ADMIN_PASSWORD` jika akun tersebut belum ada;
3. memverifikasi password terhadap hash di Neon;
4. membuat session di `user_sessions`.

Endpoint data akan membuat tabel `operations`, `hailing_records`, dan `vessels` ketika pertama kali digunakan.

## Environment Variables

Production Vercel:

- `DATABASE_URL` — Neon connection string
- `AUTH_JWT_SECRET` — minimal 32 karakter
- `DEFAULT_ADMIN_USERNAME` — default `kujang642`
- `DEFAULT_ADMIN_PASSWORD` — default `Kujang642Satkat1#`

## Login default

Jika environment variables admin tidak diubah:

- Username: `kujang642`
- Password: `Kujang642Satkat1#`

## Vercel

`vercel.json` mengarahkan semua `/api/*` ke `api/index.js`, sehingga deployment tetap hanya memiliki satu Serverless Function.

## v7 deployment fix

The Neon driver is imported with a top-level static `require()` in `api/index.js` so Vercel's Node bundler can detect and include `@neondatabase/serverless`. The dependency is pinned to 1.1.0 instead of `latest`.
