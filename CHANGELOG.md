# VideoWhisper v1.3.1 - Changelog

- Fixed various bugs
- Renamed some features

### 🚀 Usage

#### GUI Mode (Default)
```bash
# Jalankan tanpa arguments untuk GUI
python videowhisper.py

# Atau eksplisit
python videowhisper.py gui
```

#### CLI Mode (Enhanced)
```bash
# Hide text message
python videowhisper.py whisper -v video.mp4 -m "Secret message"

# Hide file (auto-detects if LSB needed)
python videowhisper.py whisper -v video.mp4 -f document.pdf

# Force LSB mode
python videowhisper.py whisper -v video.mp4 -f document.pdf --lsb

# Extract content
python videowhisper.py listen -v video_whispered.mp4

# Extract to specific directory
python videowhisper.py listen -v video_whispered.mp4 -d /path/to/output
```

### 📊 Technical Improvements

#### Security Enhancements
- **Enhanced RSA encryption** dengan payload validation
- **Improved key management** untuk external mode
- **Better integrity checking** dengan comprehensive checksums
- **Secure file handling** dengan proper error handling

#### Performance Optimizations
- **Smart capacity calculation** untuk efisiensi storage
- **Optimized base64 encoding** untuk file handling
- **Background threading** untuk GUI responsiveness
- **Memory-efficient file processing**

#### User Experience
- **Intuitive GUI design** dengan clear visual feedback
- **Comprehensive error messages** dengan actionable suggestions
- **Auto-detection** untuk file types dan security modes
- **Progress indicators** untuk long-running operations

### 🔄 Backward Compatibility

- ✅ **Full compatibility** dengan VideoWhisper v1.1.0
- ✅ **Automatic format detection** untuk old/new whispers
- ✅ **CLI interface preserved** dengan new options
- ✅ **Existing key files** tetap dapat digunakan

### 📋 Requirements

- Python 3.7+
- cryptography>=41.0.0
- click>=8.1.0
- colorama>=0.4.6
- tkinter (included in Python standard library)

### 🐛 Bug Fixes

- Fixed payload size calculation untuk large files
- Improved error handling untuk corrupted videos
- Better file path handling untuk Windows/Linux
- Enhanced memory management untuk large files

### 🎯 Coming Soon

- Drag & drop support untuk GUI
- Batch processing untuk multiple files
- Advanced encryption options
- Cloud storage integration
- Mobile app companion

---

**Full release notes dan migration guide tersedia di dokumentasi lengkap.**
