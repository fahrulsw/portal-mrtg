# Portal MRTG Pelanggan

Portal pelanggan untuk menampilkan grafik traffic (data dari LibreNMS).
Pelanggan login, lalu hanya melihat grafik port miliknya sendiri.

## Menjalankan

```bash
npm install
cp .env.example .env      # lalu isi SESSION_SECRET, LNMS_URL, LNMS_TOKEN
node seed.js admin admin 'PasswordKuat123' "Administrator"
npm start
```

Buka http://localhost:3000 dan login sebagai admin. Admin otomatis masuk ke
halaman `/admin.html`, pelanggan masuk ke `/dashboard.html`.
Login memakai **username** (huruf kecil, angka, titik, garis bawah, strip, atau @).

## Mengelola pelanggan (halaman admin)

- **Tambah pelanggan**: nama, username, password (minimal 8 karakter).
- **Tambah layanan**: isi label (judul kartu di portal) dan Port ID LibreNMS.
  Tombol "Cari port" mencari port di LibreNMS berdasarkan nama perangkat,
  interface, atau deskripsi, lalu mengisi Port ID otomatis.
- **Nonaktifkan akun**: pelanggan langsung tidak bisa masuk, sesi lamanya ikut mati.
- **Ganti password**, ubah/hapus layanan, dan hapus pelanggan juga ada di sana.

Akun admin hanya dibuat atau direset lewat terminal:
`node seed.js admin <username> <password> "<Nama>"`.

## Upgrade dari versi lama (login email)

Jalankan saja versi baru dengan `portal.db` yang sama. Tabel pelanggan
dimigrasi otomatis: email lama menjadi username, data layanan tetap utuh.
Backup `portal.db` dulu untuk berjaga-jaga.

## Tes koneksi ke LibreNMS

```bash
curl -H "X-Auth-Token: TOKEN" "https://nms.contoh.net/api/v0/ports/12/port_bits" -o tes.png
```

Endpoint `port_bits` bisa sedikit berbeda antar versi LibreNMS. Kalau gagal,
cek `https://nms.contoh.net/api-docs` dan sesuaikan URL di `server.js`.

## Produksi

- Jalankan di belakang HTTPS (Nginx/Caddy) dan set `BEHIND_PROXY=1`.
- Ganti session store bawaan dengan `connect-sqlite3` atau Redis.
- Token LibreNMS: pakai user dengan role *global read-only*.
- Backup `portal.db` secara berkala.
