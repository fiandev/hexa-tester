![2fc1fcd4-70fa-46b6-bbc4-f543a5023ca8](https://github.com/user-attachments/assets/e6eeeeb8-959e-48fc-b422-f8555643b0b2)


# 🛡️ MAK LIMAH BIADAB - PENTESTING v6.1.2
**Advanced Defensive Scan & CI Integration**

---

## 📘 Deskripsi Singkat
**MAK LIMAH BIADAB - PENTESTING** is a web security scanner designed to help developers and security testers identify vulnerabilities in web applications. This tool provides various features for **scanning** and **testing web security**, **including CORS misconfiguration**, **error page exposure**, **rate limiting**, and **others**.

---

## 🚀 Fitur Utama

### 🔍 Scanning Modules
- **Header Security Check**: Mendeteksi header keamanan yang hilang (HSTS, CSP, X-Frame-Options, dsb).
- **TLS & Cipher Scan**: Mengevaluasi sertifikat SSL/TLS, status kedaluwarsa, dan cipher suite.
- **Fingerprinting**: Mengidentifikasi teknologi dan framework (WordPress, React, ASP.NET, dsb).
- **Advanced CORS Check**: Menguji konfigurasi CORS untuk potensi mis-konfigurasi kritis.
- **Error Page Disclosure**: Mendeteksi informasi sensitif dari halaman error (stack trace, path, dsb).
- **Cookie Attributes Check**: Mengevaluasi atribut keamanan cookie (`HttpOnly`, `Secure`, `SameSite`).
- **Broken Access Control (BAC)**: Menguji akses tanpa autentikasi pada endpoint penting.
- **Rate Limit Test**: Mendeteksi brute-force vulnerability pada endpoint login.
- **Open Redirect Scan**: Menguji parameter URL yang berpotensi diarahkan ke domain eksternal.
- **Mixed Content Detector**: Mendeteksi aset `HTTP` pada situs `HTTPS`.
- **Subdomain Recon**: Memeriksa subdomain aktif dan kemungkinan cloud takeover.
- **JS Analyzer (v6.1)**: Analisis file `.js` dan `.map` untuk menemukan secret dan endpoint tersembunyi.
- **Smart IDOR Scanner (v6.0)**: Deteksi otomatis terhadap potensi *Insecure Direct Object Reference*.
- **SSRF Passive Scanner (v6.1)**: Analisis parameter URL untuk payload internal/cloud metadata.

---

## 🧩 Fitur Tambahan

### 🧱 CI/CD Workflow Integration
- Ekspor hasil scan otomatis dalam format:
  - **JSON** → untuk pipeline otomatis
  - **YAML (simulasi)** → untuk pembacaan cepat oleh manusia
- File output:
  - `mak_limah_ci_summary_<timestamp>.json`
  - `mak_limah_ci_summary_<timestamp>.yaml`

### 🧠 Intelligent Reporting
- **HTML Report Generator** dengan tampilan modern
- **Critical Findings Extractor** otomatis (High/Critical severity)

---

## 💻 Instalasi

### Persyaratan
- **Python 3.8+**
- Modul:
```bash
pip install pycryptodome rich requests
```

---

## 🧪 Cara Penggunaan

### 1. Jalankan Tools
```bash
python mak-limah.py
```

### 2. Masukkan Target URL
Ikuti prompt interaktif:
```
Enter target URL: https://example.com
```

### 3. Pilih Mode Scan
- Full Scan
- Header-only
- CORS & Cookie Audit
- Export CI Workflow

### 4. Lihat Hasil
- Hasil real-time muncul di terminal.
- Ringkasan hasil dalam tabel Rich.
- Export ke HTML, JSON, dan YAML.

---

## 📦 Output Files

| File | Deskripsi |
|------|-----------|
| `mak_limah_report_<timestamp>.html` | Laporan HTML interaktif |
| `mak_limah_ci_summary_<timestamp>.json` | Output CI/CD JSON |
| `mak_limah_ci_summary_<timestamp>.yaml` | Output CI/CD YAML (simulasi) |

---

## 🧰 Contoh Hasil CI Summary (JSON)

```json
{
  "tool_name": "MAK LIMAH BIADAB - PENTESTING",
  "tool_version": "6.1.2 (Stable - UI Fix 3)",
  "target": "https://example.com",
  "timestamp": 1730000000,
  "total_critical_findings": 3,
  "findings": [
    {
      "module": "Headers",
      "severity": "CRITICAL",
      "details": "3 critical headers missing."
    },
    {
      "module": "CORS",
      "severity": "CRITICAL",
      "details": "Origin allowed via GET (*)"
    }
  ]
}
```

---

## 🧩 Struktur Kode

- `SafeSession` → Kelas wrapper untuk `requests.Session`
- `SimpleLinkParser` → Parser HTML untuk link & JS
- `scan_*()` → Modul utama scanning
- `make_*()` → Komponen UI (Rich Panels)
- `export_ci_summary()` → Ekspor hasil CI/CD
- `generate_html_report()` → Generator laporan HTML

---

## ⚠️ Peringatan
> Tools ini dibuat **hanya untuk keperluan edukasi dan uji keamanan yang sah**.
> Penggunaan tanpa izin pada sistem pihak ketiga adalah **ilegal dan melanggar hukum**.

---

## 🧑‍💻 Pengembang
**Sardi Dev**
Follow: https://instagram.com/Otakukazzee
Lisensi: Non-Open Source — Modifikasi dan redistribusi dilarang tanpa izin tertulis.

---

## 🧩 Versi & Pembaruan
- **v6.1.2** — CI Workflow Export, UI Fix 3
- **v6.1** — SSRF Passive Scan, JS SourceMap Analyzer
- **v6.0** — Smart IDOR Scanner, HTML Report Generator

---

## 📞 Dukungan
Hubungi developer via email (sardidevs.me@gmail.com) atau media sosial resmi untuk permintaan enterprise atau integrasi pipeline.

---

**© 2025 Sardi Dev — All Rights Reserved.**
