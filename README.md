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
- Server: Node.js & Express (lokal) / Vercel (Produksi)

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

## Deployment di Vercel
Aplikasi ini dikonfigurasi sebagai Single Page Application (SPA) murni dengan `vercel.json` dan siap untuk langsung di-deploy secara gratis melalui Vercel.

1. Buka [Vercel.com](https://vercel.com) dan login menggunakan akun GitHub kamu.
2. Klik **Add New...** -> **Project**.
3. Import repository GitHub kamu.
4. Framework Preset biarkan default (Other), lalu klik **Deploy**.
5. Pasang custom domain (`.my.id`) melalui menu Settings > Domains di dashboard Vercel.
