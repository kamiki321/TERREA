# TERREA Deployment Checklist

1. Pastikan repository berisi `api/index.js`, `index.html`, `package.json`, `vercel.json`, dan `data/master.json`.
2. Pastikan tidak ada `now.json` atau `.vercel/project.json` yang ikut di-commit.
3. Vercel Environment Variables:
   - `DATABASE_URL` = URL Neon PostgreSQL
   - `DEFAULT_ADMIN_USERNAME` = `kujang642`
   - `DEFAULT_ADMIN_PASSWORD` = `Kujang642Satkat1#` atau password pilihan yang memenuhi aturan
4. Redeploy tanpa cache setelah push.
5. Login dari halaman TERREA dengan credential yang sama.

Login sekarang tidak membuat tabel user/session di Neon. Semua data hailing tetap disimpan di PostgreSQL.
