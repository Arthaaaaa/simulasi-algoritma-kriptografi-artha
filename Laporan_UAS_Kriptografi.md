# LAPORAN PROJECT UAS
**MATA KULIAH KRIPTOGRAFI**

**Judul Project:**
Aplikasi Web Simulasi Algoritma Kriptografi Simetris (DES, S-DES, AES-128, S-AES) Berbasis Step-by-Step

**Disusun Oleh:**
Nama: Artha  
NIM: [Isi NIM Kamu]  
Program Studi: [Isi Program Studi]  
Universitas: [Isi Nama Universitas]  
Tahun Akademik: Semester Genap 2025/2026

---

## KATA PENGANTAR

Puji syukur kehadirat Tuhan Yang Maha Esa atas segala rahmat, petunjuk, dan karunia-Nya sehingga Laporan Project Ujian Akhir Semester (UAS) mata kuliah Kriptografi ini dapat diselesaikan dengan baik dan tepat waktu. Laporan ini disusun sebagai bentuk dokumentasi komprehensif dari proses perancangan, implementasi kode, hingga tahap pengujian "Aplikasi Web Simulasi Algoritma Kriptografi Simetris" yang telah dideploy dan dapat diakses secara publik.

Penyelesaian project ini tidak lepas dari dukungan berbagai pihak. Oleh karena itu, ucapan terima kasih yang sebesar-besarnya ditujukan kepada Sir Bayu selaku dosen pengampu mata kuliah Kriptografi. Bimbingan, materi, dan arahan beliau selama perkuliahan telah memberikan landasan pemahaman yang kuat mengenai cara kerja algoritma kriptografi, yang menjadi fondasi utama dalam pembuatan simulasi ini.

Penulis menyadari sepenuhnya bahwa aplikasi dan laporan ini masih memiliki ruang untuk penyempurnaan, baik dari segi kelengkapan fitur maupun kedalaman analisis. Oleh karena itu, kritik dan saran yang bersifat membangun sangat diharapkan guna pengembangan lebih lanjut di masa mendatang. Akhir kata, semoga aplikasi simulasi ini dapat memberikan manfaat nyata, khususnya sebagai media pembelajaran interaktif bagi mahasiswa yang sedang mempelajari ilmu Kriptografi.

---

## DAFTAR ISI
1. [BAB I PENDAHULUAN](#bab-i-pendahuluan)
2. [BAB II LANDASAN TEORI](#bab-ii-landasan-teori)
3. [BAB III PERANCANGAN & IMPLEMENTASI](#bab-iii-perancangan--implementasi)
4. [BAB IV HASIL & PENGUJIAN](#bab-iv-hasil--pengujian)
5. [BAB V PENUTUP](#bab-v-penutup)
6. [DAFTAR PUSTAKA](#daftar-pustaka)
7. [LAMPIRAN](#lampiran)

---

## BAB I PENDAHULUAN

### 1.1 Latar Belakang
Di era digital yang serba terhubung ini, keamanan data dan kerahasiaan informasi menjadi prioritas mutlak dalam setiap sistem komunikasi. Kriptografi hadir sebagai ilmu dan seni untuk mengamankan pesan. Dari berbagai metode yang ada, kriptografi simetris (block cipher) seperti Data Encryption Standard (DES) dan Advanced Encryption Standard (AES) memegang peranan vital dalam sejarah dan praktik keamanan siber modern.

Mempelajari algoritma ini secara teoritis seringkali menjadi tantangan tersendiri bagi mahasiswa. Buku teks umumnya menyajikan algoritma dalam bentuk rumus matematis yang padat, tabel permutasi yang rumit, dan operasi matriks di Galois Field yang abstrak. Banyak *tool* enkripsi yang tersedia di internet hanya bertindak sebagai "kotak hitam" (black-box), di mana pengguna memasukkan teks dan langsung mendapatkan hasil tanpa mengetahui apa yang terjadi di dalamnya.

Oleh karena itu, dibutuhkan sebuah sarana visualisasi interaktif yang transparan. Project ini digagas untuk mengatasi celah tersebut dengan membangun sebuah "Aplikasi Web Simulasi Kriptografi" yang tidak hanya mengenkripsi data, tetapi juga "membedah" dan mendemonstrasikan tahapan internal dari algoritma DES, S-DES, AES-128, dan S-AES ronde demi ronde. Dengan pendekatan *step-by-step* ini, diharapkan proses pembelajaran algoritma kompleks menjadi jauh lebih intuitif dan mudah dipahami.

### 1.2 Rumusan Masalah
Berdasarkan latar belakang di atas, rumusan masalah dalam project ini adalah:
1. Bagaimana merancang arsitektur aplikasi web untuk menyimulasikan algoritma DES, S-DES, AES-128, dan S-AES secara akurat?
2. Bagaimana memvisualisasikan tahapan algoritma (seperti fungsi Feistel, S-Box, ShiftRows, dan MixColumns) secara *step-by-step* agar ramah edukasi?
3. Bagaimana mengimplementasikan antarmuka pengguna (UI) yang modern dan intuitif menggunakan teknologi web standar?
4. Bagaimana melakukan proses deployment (hosting) aplikasi ini ke *cloud* agar dapat diakses oleh publik secara stabil?

### 1.3 Tujuan
Tujuan utama dari pembuatan aplikasi dan penyusunan laporan ini meliputi:
1. Memenuhi tugas akhir (UAS) untuk mata kuliah Kriptografi dengan mengaplikasikan teori ke dalam produk perangkat lunak nyata.
2. Membangun alat bantu ajar (edukasi) interaktif yang membedah proses internal dari algoritma kriptografi simetris populer beserta versi sederhananya.
3. Mendemonstrasikan keterampilan rekayasa perangkat lunak (Software Engineering) mulai dari penulisan *core engine* algoritma, manipulasi DOM, hingga integrasi deployment modern menggunakan GitHub dan Vercel.

### 1.4 Batasan Masalah
Agar pembahasan dan implementasi lebih terarah, project ini dibatasi pada hal-hal berikut:
1. Algoritma kriptografi yang diimplementasikan berfokus pada mode dasar (ECB) untuk DES, S-DES, AES-128, dan S-AES.
2. Input dibatasi sesuai ukuran blok standar masing-masing algoritma (misal: S-DES 8-bit, S-AES 16-bit, DES 64-bit, AES 128-bit) untuk menjaga kesederhanaan visualisasi satu blok.
3. Aplikasi bersifat murni *client-side* (Single Page Application). Seluruh komputasi kriptografi dilakukan di browser pengguna tanpa pengiriman data sensitif ke server backend.
4. Deployment dilakukan menggunakan Vercel dengan metode koneksi ke repository GitHub.

### 1.5 Manfaat
Project ini diharapkan dapat memberikan manfaat sebagai berikut:
1. **Bagi Penulis:** Menguji dan memperdalam pemahaman teoritis kriptografi sekaligus mengasah kemampuan pemrograman web *full-stack* dan DevOps dasar.
2. **Bagi Mahasiswa/Akademisi:** Menjadi media pembelajaran alternatif yang interaktif untuk membedah operasi bit dan matriks yang sulit dipahami jika hanya dibaca dari buku teks.

---

## BAB II LANDASAN TEORI

### 2.1 Kriptografi Simetris (Symmetric Cryptography)
Kriptografi simetris, atau sering disebut kriptografi kunci rahasia (secret-key cryptography), adalah jenis sistem enkripsi di mana pengirim dan penerima pesan menggunakan kunci yang persis sama. Keamanan sistem ini sangat bergantung pada kerahasiaan kunci tersebut. Algoritma simetris umumnya beroperasi dalam bentuk *Block Cipher* (memproses data dalam blok-blok ukuran tetap) atau *Stream Cipher* (memproses data bit per bit). Algoritma yang dibahas dalam project ini seluruhnya adalah jenis *Block Cipher*.

### 2.2 Struktur Feistel Network
Banyak algoritma block cipher klasik, termasuk DES, dibangun menggunakan struktur Jaringan Feistel. Dalam struktur ini, blok teks dibagi menjadi dua bagian: Kiri (L) dan Kanan (R). Pada setiap ronde, bagian Kanan digabungkan dengan sub-kunci (key schedule) dan dimasukkan ke dalam sebuah fungsi kompleks (F-function). Hasilnya kemudian di-XOR-kan dengan bagian Kiri. Posisi L dan R kemudian ditukar. Keunggulan utama Feistel adalah proses dekripsinya menggunakan struktur mesin yang sama persis dengan enkripsi, hanya urutan kuncinya yang dibalik.

### 2.3 Data Encryption Standard (DES) & S-DES
**1. DES (Data Encryption Standard)**
DES adalah standar enkripsi pemerintah Amerika Serikat pada era 70-an. DES memproses blok plaintext 64-bit menggunakan kunci yang efektifnya berukuran 56-bit (berasal dari input 64-bit di mana 8 bit adalah parity). Algoritma ini berjalan melalui 16 ronde Feistel. Tahapan utamanya meliputi:
- *Initial Permutation (IP)*: Mengacak posisi bit awal.
- *Key Schedule*: Menghasilkan 16 sub-kunci 48-bit menggunakan pergeseran bit (Left Shift) dan Permuted Choice.
- *F-Function*: Melibatkan ekspansi 32-bit ke 48-bit, XOR dengan kunci, substitusi menggunakan 8 S-Boxes (menyusutkan 48-bit ke 32-bit), dan permutasi akhir (P-Box).
- *Final Permutation (IP-1)*: Kebalikan dari IP.

**2. S-DES (Simplified DES)**
S-DES dikembangkan oleh Edward Schaefer semata-mata untuk tujuan pendidikan. S-DES mensimulasikan karakteristik DES namun dalam skala sangat kecil: blok 8-bit dan kunci 10-bit. S-DES hanya menggunakan 2 ronde Feistel dan 2 S-Box (S0 dan S1), menjadikannya algoritma yang sempurna untuk dihitung secara manual menggunakan kertas dan pensil.

### 2.4 Substitution-Permutation Network (SPN)
Berbeda dengan Feistel, SPN (seperti pada AES) tidak membagi data menjadi dua bagian, melainkan memproses seluruh blok data secara bersamaan melalui serangkaian substitusi (penggantian nilai) dan permutasi (pengacakan posisi) yang dirancang untuk menciptakan sifat *Confusion* (menyembunyikan hubungan kunci dan ciphertext) dan *Diffusion* (menyebarkan pengaruh satu bit plaintext ke seluruh ciphertext).

### 2.5 Advanced Encryption Standard (AES) & S-AES
**1. AES-128 (Advanced Encryption Standard)**
Terpilih pada tahun 2001 untuk menggantikan DES, AES beroperasi pada blok 128-bit yang direpresentasikan sebagai matriks *State* berukuran 4x4 byte. AES-128 menggunakan kunci 128-bit dan beroperasi sebanyak 10 ronde. Operasi matematika di dalamnya berbasis *Galois Field* GF(2^8). Tiap ronde (kecuali ronde terakhir) terdiri dari 4 transformasi:
- *SubBytes*: Substitusi byte-per-byte non-linear menggunakan S-Box.
- *ShiftRows*: Pergeseran sirkular pada baris-baris matriks State.
- *MixColumns*: Perkalian matriks setiap kolom untuk mengacak data secara vertikal (tidak ada di ronde terakhir).
- *AddRoundKey*: Operasi bitwise XOR antara matriks State dengan sub-kunci ronde tersebut.

**2. S-AES (Simplified AES)**
Mirip dengan S-DES, S-AES diciptakan (oleh Musa dkk.) untuk membantu mahasiswa memahami struktur AES. S-AES memproses blok 16-bit (matriks State 2x2 nibble) dengan kunci 16-bit melalui 2 ronde operasi di GF(2^4). Walau skalanya kecil, ia menggunakan komposisi transformasi yang sama persis: Nibble Substitution, Shift Row, Mix Column, dan Add Key.

---

## BAB III PERANCANGAN & IMPLEMENTASI

### 3.1 Arsitektur Aplikasi (Single Page Application)
Aplikasi ini dirancang menggunakan arsitektur Single Page Application (SPA). Artinya, saat pengguna mengakses web, server hanya perlu mengirimkan satu file `index.html`. Navigasi perpindahan antar algoritma (misal dari DES ke AES) ditangani secara internal oleh JavaScript di sisi browser (Client-side Routing). Pendekatan ini dipilih karena memberikan pengalaman pengguna (User Experience) yang sangat cepat, mulus, dan tanpa proses *loading* berulang.

Struktur folder proyek:
- `css/` : Menyimpan `style.css` (Desain sistem UI).
- `js/` : Menyimpan logika kriptografi dan UI terpisah:
  - `app.js` (Router SPA dan fungsi utility bersama).
  - `des-core.js` & `des-ui.js` (Logika enkripsi dan render HTML untuk DES).
  - `sdes-core.js` & `sdes-ui.js` (Logika S-DES).
  - `aes-core.js` & `aes-ui.js` (Logika AES).
  - `saes-core.js` & `saes-ui.js` (Logika S-AES).

### 3.2 Desain Antarmuka dan Estetika
Tampilan web tidak menggunakan library eksternal (seperti Bootstrap atau Tailwind), melainkan dibangun murni menggunakan Vanilla CSS3. Estetika desain mengambil tema **Modern Glassmorphism** (elemen transparan dengan efek blur latar belakang) yang dipadukan dengan *Dark Mode*.
- **Palet Warna:** Memanfaatkan kontras antara warna gelap *Charcoal/Graphite* (latar belakang) dengan aksen warna premium *Ruby/Crimson* dan *Rose Gold/Copper* untuk elemen interaktif (tombol, link, hover state).
- **Tipografi:** Menggunakan font modern (sistem font default modern seperti Inter/Segoe UI) agar mudah dibaca.
- **Tata Letak:** Menggunakan CSS Flexbox dan Grid untuk memastikan tampilan web responsif di berbagai ukuran layar (desktop maupun mobile).

### 3.3 Implementasi Mesin Kriptografi (Core Engine)
Setiap algoritma diimplementasikan dalam bentuk *Class* atau *Module* JavaScript mandiri. Tantangan terbesar dalam implementasi ini adalah **menyimpan state di setiap ronde**. 
Pada umumnya, algoritma hanya me-return hasil akhir (ciphertext). Namun, karena web ini dirancang untuk fitur edukasi *step-by-step*, fungsi core engine dimodifikasi agar menyimpan *snapshot* atau jejak memori pada setiap tahapan (contoh: jejak nilai L0, R0, L1, R1, K1 pada DES). Objek jejak inilah yang nantinya dikirim ke modul UI untuk di-render menjadi elemen HTML yang bisa dibaca pengguna.

### 3.4 Deployment dan Konfigurasi Server
Meskipun web berjalan di sisi klien (browser), aplikasi ini tetap membutuhkan web server sederhana untuk melayani file statis dan mendukung *fallback routing* SPA.
- **Node.js & Express:** Dibuat file `server.js` yang memanfaatkan Express untuk men-*serve* file HTML/CSS/JS di port yang tersedia.
- **GitHub:** Digunakan sebagai *Version Control System* untuk menyimpan dan merekam perubahan kode.
- **Vercel:** Platform cloud *Platform-as-a-Service* (PaaS) digunakan untuk hosting. Vercel secara otomatis mendeteksi repository GitHub dan mendeploy aplikasi web sebagai Single Page Application secara otomatis setiap kali ada *commit* baru.
- **DomaiNesia (DNS):** DNS dikonfigurasi dengan mengarahkan record ke server Vercel, sehingga aplikasi dapat diakses menggunakan domain khusus `.my.id` secara profesional.

---

## BAB IV HASIL & PENGUJIAN

### 4.1 Skenario Pengujian Algoritma
Pengujian dilakukan untuk memastikan logika komputasi Vanilla JavaScript yang ditulis menghasilkan output yang 100% akurat. Pengujian divalidasi dengan membandingkan hasilnya terhadap *Test Vectors* standar internasional (seperti dokumen NIST untuk AES) dan hasil kalkulasi manual.

**1. Hasil Uji Algoritma DES**
- **Input Plaintext**: `0123456789ABCDEF` (Format Hexadecimal)
- **Input Key**: `133457799BBCDFF1` (Format Hexadecimal)
- **Proses**: Sistem berhasil menampilkan Initial Permutation, memecah blok jadi L0 dan R0, menampilkan operasi XOR dan S-Box selama 16 ronde, hingga Inverse Permutation.
- **Output Ciphertext**: `85E813540F0AB405`
- **Kesimpulan**: Berhasil. Hasil sesuai dengan referensi standar DES.

**2. Hasil Uji Algoritma S-DES**
- **Input Plaintext**: `10010111` (Format Biner)
- **Input Key**: `1010000010` (Format Biner)
- **Proses**: Sistem menjabarkan kalkulasi P10, Left Shift, dan P8 untuk Key Schedule, dilanjutkan dengan proses fungsi F pada 2 ronde.
- **Output Ciphertext**: `00111000`
- **Kesimpulan**: Berhasil. Hasil sesuai dengan perhitungan manual di kertas.

**3. Hasil Uji Algoritma AES-128**
- **Input Plaintext**: `00112233445566778899AABBCCDDEEFF` (Hex)
- **Input Key**: `000102030405060708090A0B0C0D0E0F` (Hex)
- **Proses**: Visualisasi sukses memetakan array 1-dimensi menjadi matriks 4x4 (State). Fitur step-by-step berhasil menunjukkan perubahan state yang mencolok setelah operasi S-Box (SubBytes) dan pengacakan baris/kolom.
- **Output Ciphertext**: `69C4E0D86A7B0430D8CDB78070B4C55A`
- **Kesimpulan**: Berhasil. Hasil identik dengan *NIST Standard Test Vector (FIPS-197)*.

**4. Hasil Uji Algoritma S-AES**
- **Input Plaintext**: `1101011100101000` (Biner)
- **Input Key**: `0100101011110101` (Biner)
- **Proses**: Visualisasi mengubah input menjadi 4 buah nibble. Perhitungan Galois Field GF(2^4) divisualisasikan dengan hasil XOR matriks.
- **Output Ciphertext**: `0010010011101100` (Biner) / `24EC` (Hex)
- **Kesimpulan**: Berhasil. Akurasi komputasi GF-nya telah tervalidasi.

### 4.2 Analisis UI/UX dan Responsivitas
Secara fungsionalitas visual, aplikasi mampu merender ratusan elemen HTML (khususnya pada DES yang memiliki 16 ronde) dalam waktu kurang dari satu detik berkat performa DOM JavaScript modern. Panel akordeon (fitur buka-tutup) untuk section *Step-by-Step* sangat membantu agar halaman tidak terlihat terlalu penuh. Pengujian di layar *mobile* (smartphone) menunjukkan bahwa tata letak flexbox otomatis menyesuaikan diri, meskipun tabel matriks (seperti pada AES) memunculkan scroll horizontal untuk mencegah elemen bertumpuk, sehingga keterbacaan data tetap terjamin.

---

## BAB V PENUTUP

### 5.1 Kesimpulan
Dari perancangan, implementasi, dan pengujian yang telah dilakukan, dapat ditarik kesimpulan sebagai berikut:
1. Aplikasi web simulasi Kriptografi (DES, S-DES, AES-128, S-AES) telah sukses dibangun dari nol (scratch) menggunakan Vanilla JavaScript tanpa bergantung pada library kriptografi instan.
2. Fitur inti dari aplikasi, yaitu kapabilitas "Solusi Step-by-Step", berjalan dengan sangat baik dan terbukti efektif menerjemahkan teori rumit dari Feistel Network dan SPN menjadi visualisasi data yang mudah dilacak ronde demi ronde.
3. Arsitektur Single Page Application (SPA) memberikan performa interaksi yang cepat dan mulus.
4. Integrasi ekosistem modern (GitHub, Vercel, dan DomaiNesia) berhasil meluncurkan aplikasi ini ke ranah publik dengan konfigurasi domain kustom yang aman (HTTPS) secara mulus.

### 5.2 Saran
Beberapa saran untuk pengembangan penelitian atau perbaikan project di masa mendatang meliputi:
1. **Dukungan Mode Operasi Blok**: Aplikasi saat ini menggunakan mode ECB (Electronic Codebook). Ke depannya, disarankan menambah simulasi visual untuk mode rantai blok seperti CBC (Cipher Block Chaining) atau CTR (Counter Mode).
2. **Kriptografi Asimetris**: Fitur edukasi dapat diperluas dengan menambahkan visualisasi algoritma *Public-Key* (seperti RSA atau Elliptic Curve) beserta kalkulasi matematis modulos-nya.
3. **Fitur Ekspor PDF**: Menambahkan fitur tombol yang secara otomatis mengekstrak elemen HTML "Step-by-step" menjadi dokumen PDF siap cetak bagi mahasiswa yang membutuhkannya untuk laporan tertulis.

---

## DAFTAR PUSTAKA
- Stallings, W. (2017). *Cryptography and Network Security: Principles and Practice* (7th ed.). Pearson Education.
- National Institute of Standards and Technology (NIST). (2001). *Advanced Encryption Standard (AES)* (FIPS PUB 197). Washington, D.C.: U.S. Department of Commerce.
- National Bureau of Standards (NBS). (1977). *Data Encryption Standard (DES)* (FIPS PUB 46).
- Mozilla Developer Network (MDN). (2024). *JavaScript & DOM Reference*.
- Dokumentasi resmi deployment cloud platform (Vercel) dan manajer DNS DomaiNesia.

---

## LAMPIRAN

- **Tautan Aplikasi Web Publik**: `https://simulasi-algoritma-kriptografi-artha.my.id`
- **Tautan GitHub Repository**: `https://github.com/Arthaaaaa/UAS-Semester6`
- **Tautan Video Penjelasan (YouTube)**: `[Isi Link YouTube Kamu]`
- **Dokumen Scan Perhitungan Manual**: Dilampirkan terpisah dalam format PDF sebagai kelengkapan penilaian Ujian Akhir Semester.

*(Catatan: Screenshot aplikasi web, diagram alir, atau dokumentasi visual lainnya dapat disisipkan/di-paste di halaman ini sebelum file dicetak atau dikonversi menjadi format PDF untuk pengumpulan ke dosen).*
