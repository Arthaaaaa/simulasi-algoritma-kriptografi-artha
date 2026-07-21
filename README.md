# Web Simulasi Algoritma Kriptografi Simetris

Aplikasi web interaktif untuk menyimulasikan algoritma enkripsi dan dekripsi kriptografi simetris. Proyek ini dibangun sebagai Tugas Akhir Semester (UAS) mata kuliah Kriptografi.

## Fitur Algoritma
- **DES (Data Encryption Standard)**: 64-bit block cipher dengan 16 ronde Feistel.
- **S-DES (Simplified DES)**: Versi sederhana dari DES dengan 8-bit block dan 10-bit key.
- **AES-128 (Advanced Encryption Standard)**: 128-bit block cipher dengan state matrix 4x4.
- **S-AES (Simplified AES)**: Versi sederhana dari AES dengan 16-bit block dan state matrix 2x2.

Setiap modul dilengkapi dengan fitur **"Tampilkan Solusi Penyelesaian"** yang memperlihatkan kalkulasi enkripsi/dekripsi secara rinci *step-by-step*.

## Teknologi
- HTML5, CSS3, JavaScript (Vanilla / ES6)
- Desain UI: Dark Mode, Glassmorphism
- Server: Node.js & Express (untuk hosting di Railway)

## Cara Menjalankan Secara Lokal

1. Pastikan Node.js sudah terinstal.
2. Clone repository ini:
   ```bash
   git clone <URL_REPO_ANDA>
   cd <NAMA_FOLDER>
   ```
3. Install dependencies:
   ```bash
   npm install
   ```
4. Jalankan server lokal:
   ```bash
   npm start
   ```
5. Buka browser dan akses: `http://localhost:3000`

## Deployment di Railway
Aplikasi ini dikonfigurasi menggunakan Express JS (`server.js`) untuk melayani file statis dan siap untuk langsung di-deploy melalui GitHub terintegrasi di Railway.

1. Hubungkan repo GitHub di dashboard Railway (`Deploy from GitHub Repo`).
2. Railway otomatis mengenali environment Node.js dan mengeksekusi `npm start`.
3. Pasang custom domain (`.my.id`) melalui menu Settings > Networking di dashboard Railway.
