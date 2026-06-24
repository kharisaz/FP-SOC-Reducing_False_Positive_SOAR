# 🛡️ Panduan Proyek SOAR: Integrasi Wazuh & Shuffle

Dokumen ini berfungsi sebagai "otak cadangan" (*State Context*) untuk diunggah/dibaca oleh AI di masa depan agar dapat langsung memahami arsitektur, progres, dan tujuan proyek tanpa perlu mengulang penjelasan dari awal.

---

## 1. Tujuan Proyek
Membangun arsitektur **SOAR (Security Orchestration, Automation, and Response)** yang berfungsi penuh secara *end-to-end* menggunakan perangkat sumber terbuka (*Open Source*). 
Tujuan utamanya adalah mendeteksi ancaman keamanan secara *real-time* (dalam kasus uji coba ini: Serangan *Brute-force* SSH) dan meresponsnya secara otomatis tanpa intervensi manusia.

## 2. Konsep & Arsitektur Sistem
Proyek ini mengandalkan tulang punggung utama yang berjalan di atas Virtual Machine (VM) Microsoft Azure. Semua VM dalam arsitektur pertahanan berada dalam satu Resource Group (`rg-wazuh-lab`) agar dapat berkomunikasi via IP Private:

*   **Wazuh Manager (RAM 8GB) `20.189.117.161`:** Bertugas sebagai SIEM & otak pendeteksi utama.
*   **Shuffle SOAR Server (RAM 8GB) `40.81.18.5`:** Bertugas sebagai eksekutor otomatisasi. Menangkap *Webhook* dari Wazuh Manager dan meluncurkan *Workflow* mitigasi.
*   **Target Server (RAM 4GB) `20.24.64.56`:** Diinstal Wazuh Agent (ID: 001). Menjadi korban serangan dan bertugas melakukan pemblokiran IP saat diperintah oleh SOAR.
*   **Attacker Server (Eksternal) `20.193.149.62`:** Server di luar Azure yang bertugas meluncurkan serangan (misal: *Brute-force* Hydra) ke IP Publik *Target Server*.

**Alur Skenario (Data Pipeline):**
`Attacker (Aktivitas)` ➡️ `Wazuh Agent (Target Server)` ➡️ `Wazuh Manager (Deteksi)` ➡️ `Ollama AI (Analisis & Filter)` ➡️ `Shuffle Webhook` ➡️ `Wazuh API (Trigger Active Response)` ➡️ `Wazuh Agent (Blokir/Hapus)` ➡️ `Telegram Bot (Notifikasi Grup)`.

---

## 3. Progres Saat Ini (Tahap Selesai)
Infrastruktur inti, logika otomatisasi SOAR, klasifikasi kecerdasan buatan (Ollama AI), dan alur respons otomatis telah berhasil dibangun dan diintegrasikan 100% untuk tiga skenario utama:

### A. Skenario 1: Malware Detection (Defense in Depth)
Kami menerapkan dua lapisan pertahanan malware secara bersamaan di Target Server:
| Lapisan Pertahanan | Metode Deteksi (Wazuh) | Jalur yang Diawasi (Path) | Cara Kerja & Mekanisme |
| :--- | :--- | :--- | :--- |
| **Lapisan 1: FIM Syscheck** | `Rule 100005` (Level 12) | `/home/azureuser/malware_trap/` | Memantau pembuatan file bernama khusus `eicar.com` secara instan menggunakan modul integritas bawaan Wazuh. |
| **Lapisan 2: ClamAV Engine** | `Rule 52502` (Level 8) | `/tmp/` dan `/home/azureuser/uploads/` | Memindai isi biner dari file apa pun (tidak peduli nama filenya) menggunakan mesin antivirus ClamAV secara real-time. |

### B. Skenario 2: SSH Brute-force
Rentetan login gagal memicu deteksi brute-force (`Rule 5712` Level 10), yang diteruskan ke Shuffle untuk mengeksekusi pemblokiran IP di Target Server melalui `firewall-drop0`.

### C. Skenario 3: DDoS Mitigation
Deteksi frekuensi koneksi tinggi (`Rule 100010` Level 10) memicu auto-mitigation menggunakan `firewall-drop0` untuk memblokir IP penyerang di firewall lokal Target Server secara instan.

Semua pengujian skenario di atas telah berhasil memicu notifikasi bot Telegram secara real-time langsung ke **Grup Telegram Tim (`-5490411645`)**.

### D. Benchmark Metrics


---

## 4. Masalah Keamanan & Bug yang Telah Diselesaikan (Bug Fixes)
1.  **Bug Koneksi & Autentikasi Wazuh App di Shuffle:** Shuffle versi bawaan gagal melakukan otentikasi JWT ke Wazuh API 4.x. Diselesaikan dengan membuat **Custom Python Flask Proxy** (`wazuh_proxy.service`) pada server SOAR untuk penanganan token otomatis.
2.  **Error "Command not defined" (Active Response):** Agen Wazuh menolak perintah tak dikenal dari API. Diselesaikan dengan mendaftarkan alias perintah `remove-threat0` dan `firewall-drop0` di `ossec.conf`.
3.  **Error "Cannot read 'srcip' from data" pada Active Response:**
    *   *Masalah:* Payload dari Shuffle yang dikirim ke Wazuh API tidak memiliki struktur objek `alert` yang lengkap, melainkan hanya menyertakan parameter IP di dalam array `arguments`. Akibatnya, agen membuang error saat mencoba membaca source IP.
    *   *Solusi:* Proxy Flask di-upgrade untuk memindai array `arguments` secara dinamis menggunakan fungsi validasi IP, mengekstrak IP yang valid, dan menyuntikkannya ke objek payload `alert.data.srcip` sebelum dikirim ke Wazuh API. Ini menyelesaikan kegagalan pemblokiran firewall-drop.
4.  **Dinamika Ekstraksi File Path untuk ClamAV:**
    *   *Masalah:* Notifikasi ClamAV tidak memiliki field `$exec.syscheck.path` karena berasal dari syslog.
    *   *Solusi:* Proxy Flask diperbarui untuk memotong isi log (`full_log`) secara otomatis, mengambil path file yang terinfeksi secara dinamis, dan mengirimkannya ke perintah `remove-threat0` untuk dihapus.
5.  **IP Attacker Terblokir Permanen Selama Testing:**
    *   *Masalah:* Saat menguji ulang simulasi serangan, log tidak terbuat karena IP penyerang telah diblokir oleh aturan firewall dari tes sebelumnya.
    *   *Solusi:* Dilakukan flushing manual pada tabel INPUT firewall (`sudo iptables -F INPUT`) di Target Server sebelum memulai ulang demo/pengujian.
6.  **Daftar Integrasi Rule ID pada Wazuh Manager:**
    *   Mengupdate file `ossec.conf` pada Wazuh Manager untuk mendaftarkan rule ID DDoS (`100010, 100011, 100012`) dan ClamAV (`52502`) ke blok `<integration>` milik Shuffle.

---

## 5. Panduan Jalannya Simulasi & Demo Proyek
Ikuti panduan berikut saat mendemokan proyek di depan dosen penguji untuk membuktikan sistem bekerja sesuai ketentuan:

### A. Tahap Persiapan (Reset Environment)
Sebelum memulai demo, pastikan firewall dalam kondisi bersih:
1. Hubungkan ke **Target Server (`20.24.64.56`)** dan jalankan:
   ```bash
   sudo iptables -F INPUT
   ```
2. Pastikan grup Telegram dalam keadaan siap menerima notifikasi baru.

### B. Cara Demo Skenario 1 (Malware)
*   **Tujuan:** Membuktikan antivirus dinamis mendeteksi dan menghapus file malware apa saja di folder yang diawasi.
*   **Langkah Demo:**
    1. Di **Target Server**, buat file text tiruan virus di folder `/home/azureuser/uploads/`:
       ```bash
       echo 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > /home/azureuser/uploads/eicar_test.txt
       ```
    2. Tunggu beberapa detik, lalu ketik `ls -l /home/azureuser/uploads/`. Tunjukkan bahwa file `eicar_test.txt` **telah terhapus otomatis**.
    3. Tunjukkan notifikasi masuk di **Grup Telegram** dengan status malware berhasil dibersihkan.

### C. Cara Demo Skenario 2 (SSH Brute-force)
*   **Tujuan:** Membuktikan pertahanan memblokir IP penyerang yang mencoba tebak password massal.
*   **Langkah Demo:**
    1. Di **Attacker Server (`20.193.149.62`)**, buat file password acak:
       ```bash
       echo -e "salah1\nsalah2\nsalah3\nsalah4\nsalah5\nsalah6\nsalah7\nsalah8\nsalah9\nsalah10" > /tmp/passwords.txt
       ```
    2. Jalankan serangan brute-force menggunakan `hydra`:
       ```bash
       hydra -l fakeuser -P /tmp/passwords.txt ssh://20.24.64.56 -t 4
       ```
    3. Tunjukkan bahwa proses Hydra mendadak macet (*hang* / *timeout*) sebelum selesai karena IP penyerang diblokir.
    4. Di **Target Server**, buktikan IP penyerang masuk ke iptables dengan perintah `sudo iptables -L INPUT -n`.
    5. Tunjukkan notifikasi alert brute-force di **Grup Telegram**.

### D. Cara Demo Skenario 3 (DDoS)
*   **Tujuan:** Membuktikan auto-mitigation bekerja memblokir banjir koneksi secara instan.
*   **Langkah Demo:**
    1. Di **Attacker Server**, jalankan serangan banjir koneksi paralel:
       ```bash
       for i in {1..60}; do ssh -o StrictHostKeyChecking=no -o ConnectTimeout=1 fakeuser@20.24.64.56 & done
       ```
    2. Tunjukkan terminal Attacker langsung dipenuhi respon `Connection timed out`.
    3. Di **Target Server**, buktikan IP penyerang telah diblokir di `iptables` dengan perintah `sudo iptables -L INPUT -n`.
    4. Tunjukkan notifikasi alert DDoS di **Grup Telegram**.

## 6. Benchmark Metriks

### Deskripsi Umum

Dokumen ini menjelaskan metodologi pengukuran performa sistem SOAR dalam memilah ancaman nyata dari noise alert, serta membuktikan kontribusi filter berbasis AI terhadap pengurangan False Positive pada pipeline deteksi ancaman.

---

### 1. Sumber Data

Seluruh data diambil dari file log alert Wazuh di `/var/ossec/logs/alerts/alerts.json`. File ini merupakan akumulasi seluruh alert sejak Wazuh Manager pertama kali beroperasi, sehingga script benchmark saat ini menghitung keseluruhan histori, bukan hanya sesi pengujian terakhir. Untuk pengujian terisolasi, disarankan menambahkan filter tanggal atau membersihkan log sebelum sesi dimulai.

---

### 2. Definisi Metrik

**Total Alerts** adalah jumlah keseluruhan baris pada `alerts.json`, yang menjadi penyebut utama seluruh perhitungan persentase.

**True Positive (TP)** adalah alert yang teridentifikasi sebagai ancaman nyata berdasarkan pencocokan Rule ID spesifik dari empat skenario serangan yang telah diimplementasikan.

**False Positive (FP)** adalah selisih antara Total Alerts dan TP, merepresentasikan noise yang berhasil difilter sebelum diteruskan ke Shuffle. Persentase keduanya dihitung dengan formula berikut.

```
TP (%) = (TP / Total Alerts) × 100
FP (%) = (FP / Total Alerts) × 100
```
### 3. Pipeline Filter (Before vs After AI)

Tanpa filter AI, seluruh alert diteruskan langsung ke Shuffle termasuk yang bersifat noise. Setelah ditambahkan filter berbasis model Qwen2.5:1.5b via Ollama, setiap alert terlebih dahulu dianalisis oleh AI dan hanya alert yang terklasifikasi sebagai ancaman nyata yang diteruskan ke Shuffle untuk dieksekusi.

---

## 5. Output dan Pembaruan Otomatis

Hasil benchmark disimpan ke `/home/azureuser/benchmark_result.txt` dan dapat diperbarui otomatis menggunakan cron job berikut.

```bash
*/5 * * * * /home/azureuser/benchmark.sh
```
