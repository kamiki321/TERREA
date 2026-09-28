# TERREA Hailing Log

## Login sederhana
Login tidak lagi memakai tabel `user`, `user_sessions`, JWT, atau refresh token.
Credential dibaca langsung dari Vercel Environment Variables.

Default:
- Username: `kujang642`
- Password: `Kujang642Satkat1#`

Set these variables in Vercel:
- `DATABASE_URL`
- `DEFAULT_ADMIN_USERNAME`
- `DEFAULT_ADMIN_PASSWORD`

Set `DEFAULT_ADMIN_PASSWORD` sesuai password yang ingin digunakan. Password minimal 8 karakter, 1 huruf uppercase, 1 angka, dan 1 karakter special.

API terlindungi menggunakan HTTP Basic Authorization melalui HTTPS. Credential hanya disimpan selama tab/browser session dan dihapus saat logout.

## Deploy
Upload isi project ke GitHub lalu deploy ke Vercel. Tidak ada `now.json` dan tidak ada runtime legacy. Node.js 24.x ditentukan melalui `package.json`.
