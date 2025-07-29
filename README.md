# 🎬 VideoWhisper - Enhanced Video Steganography with RSA

<div align="center">
  <img src="https://img.shields.io/badge/python-3.7+-blue.svg" alt="Python Version">
  <img src="https://img.shields.io/badge/license-MIT-green.svg" alt="License">
  <img src="https://img.shields.io/badge/version-1.1.0-orange.svg" alt="Version">
</div>

<div align="center">
  <h3>🔐 Enhanced Security • 🤫 Whisper Secrets • 🎥 Through Video</h3>
  <p><i>Advanced video steganography with dual security modes</i></p>
</div>

---

## 🆕 What's New in v1.1.0

- **🔒 Dual Security Modes**: Embedded vs External key management
- **🔑 Enhanced Key Security**: Option to store private keys separately
- **🛡️ Interactive Key Prompts**: Automatic prompting for missing keys
- **📊 Detailed Security Info**: Enhanced reporting of security modes

## 📖 Deskripsi

**VideoWhisper** adalah aplikasi steganografi video yang memungkinkan kamu menyembunyikan pesan terenkripsi dalam file video dengan dual mode. **VideoWhisper** menggunakan enkripsi RSA 2048-bit untuk perlindungan maksimal dan tidak mudah di brute-force.

### ✨ Fitur Utama

- 🔐 **Enkripsi RSA 2048-bit** - Keamanan tingkat tinggi
- 🎥 **Multi-format Support** - MP4, AVI, MKV, MOV, dll
- 🔒 **Dual Security Modes**:
  - **Embedded Mode**: Private key tersimpan dalam video (mudah digunakan)
  - **External Mode**: Private key terpisah (keamanan maksimal)
- 🔑 **Smart Key Management** - Otomatis mendeteksi dan meminta key yang diperlukan
- ✅ **Message Integrity** - SHA-256 checksum verification
- 🎨 **Interactive CLI** - User-friendly dengan warna dan prompts
- 🛡️ **Comprehensive Error Handling** - Penanganan error yang detail

## 🚀 Instalasi

### Prerequisites

- Python 3.7 atau lebih tinggi
- pip (Python package manager)

### Langkah Instalasi

1. **Clone repository ini**
   ```bash
   git clone https://github.com/ridwansukri/VideoWhisper.git
   cd VideoWhisper
   ```

2. **Buat virtual environment dengan nama `myenv`**
   ```bash
   # Windows
   python -m venv myenv
   myenv\Scripts\activate

   # Linux/Mac
   python3 -m venv myenv
   source myenv/bin/activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Verifikasi instalasi**
   ```bash
   python videowhisper.py test
   ```

## 📚 Cara Penggunaan

### 🔒 Mode Keamanan

VideoWhisper memiliki dua mode keamanan:

#### 1. **Embedded Mode** (Default)
- Private key disimpan dalam video
- Mudah digunakan, satu file untuk semua
- Cocok untuk penggunaan pribadi

#### 2. **External Mode** 
- Private key disimpan terpisah
- Keamanan maksimal
- Cocok untuk data sensitif

### 💻 Command Line Interface

#### 1. Menyembunyikan Pesan (Whisper)

```bash
# Embedded mode (default)
python videowhisper.py whisper -v sample_video.mp4 -m "Pesan rahasia saya"

# External mode (private key terpisah)
python videowhisper.py whisper -v sample_video.mp4 -m "Pesan rahasia" -s external

# External mode dengan public key yang sudah ada
python videowhisper.py whisper -v sample_video.mp4 -m "Pesan rahasia" -s external -k public_key.pem
```

#### 2. Mengekstrak Pesan (Listen)

```bash
# Embedded mode (otomatis)
python videowhisper.py listen -v sample_video_whispered.mp4

# External mode dengan private key
python videowhisper.py listen -v sample_video_whispered.mp4 -k private_key.pem

# External mode dengan prompt interaktif
python videowhisper.py listen -v sample_video_whispered.mp4
# Program akan meminta path ke private key
```

#### 3. Membersihkan Video (Silence)

```bash
python videowhisper.py silence -v sample_video_whispered.mp4 -o sample_video_clean.mp4
```

### 🔐 Skenario Keamanan

#### Skenario 1: Keamanan Personal (Embedded)
```bash
# Whisper dengan embedded mode
python videowhisper.py whisper -v video.mp4 -m "Secret message"

# Listen tanpa perlu key eksternal
python videowhisper.py listen -v video_whispered.mp4
```

#### Skenario 2: Keamanan Maksimal (External)
```bash
# Whisper dengan external mode
python videowhisper.py whisper -v video.mp4 -m "Top secret!" -s external

# Listen dengan private key terpisah
python videowhisper.py listen -v video_whispered.mp4 -k video_whispered_private_key.pem
```

#### Skenario 3: Tanpa Private Key atau Private Key Tidak Tepat
```bash
# Jika mencoba listen tanpa private key di external mode
python videowhisper.py listen -v video_whispered.mp4

# Output:
# 🔐 External private key required!
# Enter private key file path: [user input required]
# ✗ Error: Error decrypting message: Decryption failed
```

## 🔧 API Documentation

### Menggunakan VideoWhisper sebagai Library

```python
from videowhisper import VideoWhisper

# Inisialisasi
vw = VideoWhisper()

# Embedded mode
result = vw.whisper_to_video(
    video_path="input.mp4",
    message="Secret message",
    output_path="output.mp4",
    security_mode="embedded"
)

# External mode
result = vw.whisper_to_video(
    video_path="input.mp4",
    message="Secret message",
    output_path="output.mp4",
    security_mode="external"
)

# Listen dengan private key
result = vw.listen_to_video(
    video_path="output.mp4",
    private_key_path="private_key.pem"
)

# Listen dengan prompt interaktif
result = vw.listen_to_video(
    video_path="output.mp4",
    auto_prompt=True
)
```

## 🏗️ Struktur File Output

### Embedded Mode
- sample_video_whispered.mp4 - Video dengan pesan tersembunyi
- sample_video_whispered_public_key.pem - Public key untuk sharing


### External Mode
- sample_video_whispered.mp4 - Video dengan pesan tersembunyi
- sample_video_whispered_public_key.pem - Public key untuk sharing
- sample_video_whispered_private_key.pem - Private key untuk dekripsi


## 🔐 Keamanan & Best Practices

### Keamanan RSA
- **RSA-2048** dengan OAEP padding
- **SHA-256** untuk checksum integrity
- **Secure key generation** dengan cryptography library

### Best Practices

#### Embedded Mode
- ✅ Mudah digunakan untuk personal use
- ⚠️ Private key dapat diekstrak dari video

#### External Mode
- ✅ Keamanan maksimal
- ✅ Private key terpisah dari video
- ✅ Kontrol akses yang lebih baik
- ⚠️ Private key file diperlukan saat melakukan ekstraksi pesan

### Rekomendasi Penggunaan

| Use Case | Mode | Alasan |
|----------|------|---------|
| Personal backup | Embedded | Mudah, satu file |
| Sharing dengan teman | Embedded | Praktis |
| Data sensitif | External | Keamanan maksimal |
| Corporate use | External | Audit trail yang jelas |
| Long-term storage | External | Kontrol akses jangka panjang |

## ⚠️ Limitasi

- Ukuran pesan maksimal: ~200 karakter (keterbatasan RSA-2048)
- Video output sedikit lebih besar dari input
- Tidak tahan terhadap re-encoding atau kompresi video
- External mode memerlukan manajemen file key

## 🧪 Testing

```bash
# Aktifkan virtual environment
myenv\Scripts\activate  # Windows
source myenv/bin/activate  # Linux/Mac

# Run comprehensive test
python videowhisper.py test

# Test manual dengan sample_video.mp4
python videowhisper.py whisper -v sample_video.mp4 -m "Test message" -s embedded
python videowhisper.py listen -v sample_video_whispered.mp4

python videowhisper.py whisper -v sample_video.mp4 -m "Test external" -s external
python videowhisper.py listen -v sample_video_whispered.mp4 -k sample_video_whispered_private_key.pem
```

## 🚨 Security Notices

### ⚠️ Penting untuk External Mode:
1. **Jangan kehilangan private key file** - tanpa ini pesan tidak bisa didekripsi
2. **Backup private key** dengan aman
3. **Jangan share private key** kecuali untuk dekripsi
4. **Gunakan permission yang tepat** untuk private key file (chmod 600)

### 🛡️ Deteksi Keamanan:
- VideoWhisper akan mendeteksi mode keamanan otomatis
- Peringatan jelas jika private key diperlukan
- Validasi integritas pesan dengan checksum

## 🤝 Kontribusi

Kontribusi sangat diterima! Silakan:

1. Fork repository
2. Buat feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit changes (`git commit -m 'Add some AmazingFeature'`)
4. Push ke branch (`git push origin feature/AmazingFeature`)
5. Buat Pull Request

## 📝 Changelog

### v1.1.0 (Current)
- ✨ Added dual security modes (embedded/external)
- ✨ Interactive private key prompts
- ✨ Enhanced security reporting
- 🔧 Improved error handling
- 📚 Updated documentation

### v1.0.0
- 🎉 Initial release
- 🔐 Basic RSA encryption
- 🎥 Video steganography
- 📱 CLI interface

## 📝 Lisensi

Distributed under the MIT License. See `LICENSE` for more information.

## 👨‍💻 Author

**Muh Ridwan Sukri**
- GitHub: [@ridwansukri](https://github.com/ridwansukri)
- Email: contact@ridwansukri.com

---

<div align="center">
  <p>Made with ❤️ for Enhanced Security</p>
  <p><i>VideoWhisper v1.1 - Where secrets meet security</i></p>
</div>
