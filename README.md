# 🎬 VideoWhisper v1.3.1 - Enhanced Video Steganography

<div align="center">
  <img src="https://img.shields.io/badge/python-3.7+-blue.svg" alt="Python Version">
  <img src="https://img.shields.io/badge/license-MIT-green.svg" alt="License">
  <img src="https://img.shields.io/badge/version-1.3.0-orange.svg" alt="Version">
</div>

<div align="center">
  <h3>🔐 Enhanced Security • 🤫 Whisper Secrets • 🎥 Through Video • 📁 File Upload Support</h3>
  <p><i>Advanced video steganography with hybrid encryption and interactive GUI</i></p>
</div>

---

## 🆕 What's New in v1.3.1

- Fixed various bugs
- Renamed some features

## 📖 Description

**VideoWhisper** is an advanced video steganography application that allows you to hide encrypted messages and files within video files. Version 1.3.1 introduces a modern GUI interface and support for hiding various file types using hybrid encryption for maximum compatibility and security.

### ✨ Key Features

- 🔐 **RSA-2048 + AES-256 Encryption** - Military-grade security
- 🎥 **Multi-format Video Support** - MP4, AVI, MKV, MOV, etc.
- 📁 **File Upload Support** - Hide PDF, images, documents, archives
- 🔒 **Dual Security Modes**:
  - **Embedded Mode**: Private key stored in video (convenient)
  - **External Mode**: Private key separate (maximum security)
- 🚀 **Hybrid Encryption**: Automatically handles large files
- 🖥️ **Interactive GUI**: User-friendly interface with real-time feedback
- 🎯 **Auto-Detection**: Smart method selection based on file size
- 📊 **Detailed Analytics**: File size tracking and efficiency metrics
- 🔑 **Smart Key Management**: Reuse existing keys
- ✅ **Video Integrity**: Videos remain playable after processing

### 📊 Capacity Comparison

| Video Size | RSA-Only Mode | Hybrid Mode | Improvement |
|------------|---------------|-------------|-------------|
| 1 MB | ~142 bytes | ~90 KB | **630x** |
| 10 MB | ~142 bytes | ~900 KB | **6,300x** |
| 100 MB | ~142 bytes | ~9 MB | **63,000x** |

## 🚀 Installation

### Prerequisites

- Python 3.7 or higher
- pip (Python package manager)

### Installation Steps

1. **Clone this repository**
   ```bash
   git clone https://github.com/ridwansukri/VideoWhisper.git
   cd VideoWhisper
   ```

2. **Create virtual environment**
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

4. **Verify installation**
   ```bash
   python videowhisper.py test
   ```

## 📚 Usage Guide

### 🖥️ GUI Mode (Recommended)

**Windows:**
```bash
# Launch GUI directly
python videowhisper.py

# Or explicitly specify GUI mode
python videowhisper.py gui
```

**Linux/macOS:**
```bash
# Launch GUI directly
python3 videowhisper.py

# Or explicitly specify GUI mode  
python3 videowhisper.py gui
```

**Alternative (if python3 is aliased as python):**
```bash
# Check your Python version first
python --version

# If it shows Python 3.x, you can use:
python videowhisper.py
```

If you encounter display authorization errors, Use sudo (for display access)
```bash
sudo python3 videowhisper.py gui
```

#### GUI Features:
- **📋 Tabbed Interface**: Separate tabs for Hide and Extract operations
- **📁 File Browser**: Easy file selection with drag & drop support
- **📊 Real-time Capacity**: Live capacity checking and recommendations
- **🔒 Security Options**: Visual security mode selection
- **📈 Progress Tracking**: Background processing with status updates

### 💻 Command Line Interface

#### 1. Hide Messages/Files (Whisper)

```bash
# Hide text message (RSA mode)
python videowhisper.py whisper -v video.mp4 -m "Secret message"

# Hide file (auto-detects best mode)
python videowhisper.py whisper -v video.mp4 -f document.pdf

# Force hybrid mode
python videowhisper.py whisper -v video.mp4 -f large_file.zip --hybrid

# External security mode
python videowhisper.py whisper -v video.mp4 -f file.txt -s external

# Use existing public key
python videowhisper.py whisper -v video.mp4 -f file.txt -k my_public_key.pem
```

#### 2. Extract Messages/Files (Listen)

```bash
# Extract from embedded mode
python videowhisper.py listen -v video_whispered.mp4

# Extract with external private key
python videowhisper.py listen -v video_whispered.mp4 -k private_key.pem

# Extract to specific directory
python videowhisper.py listen -v video_whispered.mp4 -d /output/folder
```

#### 3. Clean Videos (Silence)

```bash
python videowhisper.py silence -v video_whispered.mp4 -o clean_video.mp4
```

### 🔐 Security Modes

#### Embedded Mode (Default)
- ✅ Convenient: Everything in one file
- ✅ Easy sharing: No separate key files
- ⚠️ Security: Private key can be extracted from video

#### External Mode (Maximum Security)
- ✅ Maximum security: Private key separate from video
- ✅ Access control: Better key management
- ⚠️ Complexity: Requires separate key file for extraction

### 📁 Supported File Types

- **Documents**: PDF, DOC, DOCX, TXT, CSV, JSON, XML
- **Images**: JPG, JPEG, PNG, GIF, BMP
- **Audio**: MP3, WAV
- **Archives**: ZIP, RAR
- **Spreadsheets**: XLSX
- **Any file type** up to capacity limits

## 🔧 API Usage

### Using VideoWhisper as a Library

```python
from videowhisper import VideoWhisper

# Initialize
vw = VideoWhisper()

# Hide text message
result = vw.whisper_to_video(
    video_path="input.mp4",
    payload="Secret message",
    output_path="output.mp4",
    security_mode="embedded"
)

# Hide file with auto-detection
file_payload = vw.encode_file_to_payload("document.pdf")
result = vw.whisper_to_video(
    video_path="input.mp4",
    payload=file_payload,
    output_path="output.mp4",
    use_lsb=None  # Auto-detect
)

# Extract content
result = vw.listen_to_video(
    video_path="output.mp4",
    auto_prompt=True
)

# Handle file extraction
if result['payload_type'] == 'file':
    output_path = vw.decode_file_from_payload(
        result['payload'], 
        output_dir="./extracted"
    )
```

## 🏗️ Output File Structure

### Embedded Mode
- `video_whispered.mp4` - Video with hidden content
- `video_whispered_public_key.pem` - Public key for sharing

### External Mode
- `video_whispered.mp4` - Video with hidden content
- `video_whispered_public_key.pem` - Public key for sharing
- `video_whispered_private_key.pem` - Private key for decryption

### Key Reuse
When using existing keys, VideoWhisper will:
- ✅ Reuse your existing public key
- ✅ Not generate unnecessary duplicate keys
- ✅ Automatically find corresponding private keys

## 🔐 Security & Best Practices

### Encryption Details
- **RSA-2048** with OAEP padding for small data
- **AES-256-CBC** with random IV for large data
- **Hybrid approach** combines both for optimal security/performance
- **SHA-256** checksums for integrity verification

### Best Practices

#### For Personal Use
- ✅ Use **Embedded Mode** for convenience
- ✅ Keep videos in secure location
- ✅ Use strong, unique messages

#### For Sensitive Data
- ✅ Use **External Mode** for maximum security
- ✅ Store private keys separately and securely
- ✅ Use file permissions (chmod 600) on key files
- ✅ Regular key rotation for long-term use

#### For File Sharing
- ✅ Share only the whispered video and public key
- ✅ Never share private keys unless for decryption
- ✅ Use secure channels for key distribution

### Capacity Guidelines

| File Size | Recommended Mode | Video Size Needed |
|-----------|------------------|-------------------|
| < 100 bytes | RSA-Only | Any size |
| 100B - 1KB | RSA-Only or Hybrid | > 1 MB |
| 1KB - 1MB | Hybrid (Required) | > 10 MB |
| > 1MB | Hybrid (Required) | > 100 MB |

## ⚠️ Limitations & Considerations

### Technical Limitations
- **RSA-only mode**: ~142 bytes maximum
- **Hybrid mode**: Up to ~10% of video size
- **Video formats**: Best with uncompressed or lightly compressed videos
- **Re-encoding**: Hidden data lost if video is re-encoded

### Compatibility
- ✅ **Video playback**: Videos remain fully playable
- ✅ **Cross-platform**: Works on Windows, Linux, macOS
- ✅ **Python versions**: 3.7+ supported
- ⚠️ **Video editing**: Avoid editing whispered videos

## 🧪 Testing

### Comprehensive Testing
```bash
# Run all tests
python videowhisper.py test

# Test with sample video
python videowhisper.py whisper -v sample_video.mp4 -m "Test message"
python videowhisper.py listen -v sample_video_whispered.mp4
```

### Manual Testing
```bash
# Test file upload
python videowhisper.py whisper -v video.mp4 -f test_file.pdf
python videowhisper.py listen -v video_whispered.mp4 -d ./extracted

# Test external mode
python videowhisper.py whisper -v video.mp4 -f file.txt -s external
python videowhisper.py listen -v video_whispered.mp4 -k video_whispered_private_key.pem
```

## 🚨 Security Notices

### ⚠️ Important for External Mode
1. **Never lose private key files** - data becomes unrecoverable
2. **Secure key storage** - use appropriate file permissions
3. **Key backup strategy** - maintain secure backups
4. **Access control** - limit who has access to private keys

### 🛡️ Security Features
- **Automatic mode detection** - prevents user errors
- **Integrity verification** - detects tampering
- **Secure key generation** - cryptographically secure random keys
- **Error handling** - comprehensive validation

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📝 Changelog

### v1.3.1 (Current)
- Fixed various bugs
- Renamed some features

### v1.3.0
- ✨ Added interactive GUI interface
- ✨ File upload support with multiple formats
- ✨ Hybrid encryption (AES-256 + RSA-2048)
- ✨ Auto-detection of optimal encryption method
- ✨ Smart key management and reuse
- ✨ Detailed statistics and analytics
- ✨ Video compatibility improvements
- 🔧 Enhanced error handling and validation
- 📚 Comprehensive documentation updates

### v1.2.0
- ✨ LSB steganography implementation
- ✨ Enhanced capacity calculation
- 🔧 Improved file handling

### v1.1.0
- ✨ Dual security modes (embedded/external)
- ✨ Interactive private key prompts
- ✨ Enhanced security reporting
- 🔧 Improved error handling

### v1.0.0
- 🎉 Initial release
- 🔐 Basic RSA encryption
- 🎥 Video steganography
- 📱 CLI interface

## 📝 License

Distributed under the MIT License. See `LICENSE` for more information.

## 👨‍💻 Author

**Muh Ridwan Sukri**

- GitHub: [@ridwansukri](https://github.com/ridwansukri)
- Email: contact@ridwansukri.com
- Repository: [VideoWhisper](https://github.com/ridwansukri/VideoWhisper)

---

<div align="center">
  <p>Made with ❤️ for Enhanced Security</p>
  <p><i>VideoWhisper v1.3.1 - Where secrets meet innovation</i></p>
</div>
