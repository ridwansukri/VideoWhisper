#!/usr/bin/env python3
"""
VideoWhisper - Secure Video Steganography with RSA Encryption
Author: Muh Ridwan Sukri
Description: Hide encrypted messages in video files with advanced security modes
"""

import os
import sys
import json
import base64
import hashlib
import mimetypes
from typing import Tuple, Optional, Union
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.padding import PKCS7
import secrets
import click
from colorama import init, Fore, Style
import getpass
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import threading

# Initialize colorama for Windows
init()

# Constants
WHISPER_MARKER = b"VIDEOWHISPER_START_v1.3"
WHISPER_END = b"VIDEOWHISPER_END_v1.3"
LSB_MARKER = b"VIDEOWHISPER_LSB_v1.3"
LSB_END = b"VIDEOWHISPER_LSB_END_v1.3"
KEY_SIZE = 2048
VERSION = "1.3.0"
MAX_FILE_SIZE_MB = 100  # Increased for LSB mode
SUPPORTED_FILE_TYPES = [
    '.txt', '.pdf', '.doc', '.docx', '.jpg', '.jpeg', '.png', '.gif', '.bmp',
    '.mp3', '.wav', '.zip', '.rar', '.json', '.xml', '.csv', '.xlsx'
]
# LSB steganography constants
LSB_BITS_PER_BYTE = 1  # Use 1 LSB per byte for better quality
LSB_HEADER_SIZE = 32   # bytes for metadata header

class VideoWhisper:
    """Main class for VideoWhisper steganography operations"""
    
    def __init__(self):
        self.private_key = None
        self.public_key = None
        self._print_banner()
    
    def _print_banner(self):
        """Print VideoWhisper banner"""
        banner = f"""
{Fore.CYAN}╔══════════════════════════════════════╗
║        VideoWhisper v{VERSION}          ║
║   Whispering Secrets Through Video   ║
║      🔐 Enhanced Security Mode 🔐    ║
╚══════════════════════════════════════╝{Style.RESET_ALL}
        """
        print(banner)
    
    def calculate_max_capacity(self, video_size: int, use_lsb: bool = False) -> dict:
        """Calculate maximum file/message capacity based on video size and encryption method"""
        if use_lsb:
            # Hybrid append capacity calculation (much larger than RSA-only)
            # Can append significant amount of data without video corruption
            
            # Conservative estimate: up to 10% of video size for hybrid data, minimum 5KB
            max_append_size = max(int(video_size * 0.1), 5120)  # At least 5KB
            
            # Account for structure overhead
            structure_overhead = len(LSB_MARKER) + 4 + len(LSB_END) + 1024  # markers + length + padding
            metadata_overhead = 2000  # JSON metadata (conservative estimate)
            aes_overhead = 32  # AES padding overhead
            
            total_overhead = structure_overhead + metadata_overhead + aes_overhead
            
            # Available capacity for actual file data
            available_capacity = max_append_size - total_overhead
            
            # Ensure minimum capacity
            if available_capacity < 1024:  # Less than 1KB available
                available_capacity = 1024  # Minimum 1KB capacity
            
            # Leave 10% margin for safety
            safe_capacity = int(available_capacity * 0.9)
            
            return {
                'max_file_size_bytes': max(0, safe_capacity),
                'max_file_size_mb': max(0, safe_capacity) / (1024 * 1024),
                'method': 'Hybrid Append (AES+RSA)',
                'video_size_bytes': video_size,
                'max_append_size': max_append_size,
                'available_capacity': available_capacity,
                'safety_margin': max(0, available_capacity - safe_capacity)
            }
        else:
            # Original RSA-only method
            rsa_overhead = (KEY_SIZE // 8) - 2 * 32 - 2  # OAEP padding overhead
            base64_overhead_ratio = 4/3
            json_overhead = 500  # bytes
            available_space = int(video_size * 0.1)
            max_raw_size = min(rsa_overhead, available_space - json_overhead)
            max_file_size = int(max_raw_size / base64_overhead_ratio)
            
            return {
                'max_file_size_bytes': max_file_size,
                'max_file_size_mb': max_file_size / (1024 * 1024),
                'method': 'RSA Only',
                'rsa_limit_bytes': rsa_overhead,
                'available_space_bytes': available_space,
                'video_size_bytes': video_size
            }
    
    def encode_file_to_payload(self, file_path: str) -> dict:
        """Encode file to base64 with metadata"""
        try:
            if not os.path.exists(file_path):
                raise FileNotFoundError(f"File not found: {file_path}")
            
            file_size = os.path.getsize(file_path)
            file_ext = os.path.splitext(file_path)[1].lower()
            
            # Check file type
            if file_ext not in SUPPORTED_FILE_TYPES:
                raise ValueError(f"Unsupported file type: {file_ext}")
            
            # Check file size
            if file_size > MAX_FILE_SIZE_MB * 1024 * 1024:
                raise ValueError(f"File too large. Maximum size: {MAX_FILE_SIZE_MB}MB")
            
            # Read and encode file
            with open(file_path, 'rb') as f:
                file_data = f.read()
            
            encoded_data = base64.b64encode(file_data).decode('utf-8')
            
            # Get MIME type
            mime_type, _ = mimetypes.guess_type(file_path)
            
            payload = {
                'type': 'file',
                'filename': os.path.basename(file_path),
                'file_extension': file_ext,
                'mime_type': mime_type or 'application/octet-stream',
                'file_size': file_size,
                'encoded_data': encoded_data,
                'checksum': hashlib.sha256(file_data).hexdigest()
            }
            
            return payload
            
        except Exception as e:
            raise Exception(f"Error encoding file: {str(e)}")
    
    def decode_file_from_payload(self, payload: dict, output_dir: str = None) -> str:
        """Decode file from base64 payload"""
        try:
            if payload.get('type') != 'file':
                raise ValueError("Payload is not a file type")
            
            # Decode file data
            file_data = base64.b64decode(payload['encoded_data'])
            
            # Verify checksum
            calculated_checksum = hashlib.sha256(file_data).hexdigest()
            if calculated_checksum != payload['checksum']:
                raise ValueError("File integrity check failed")
            
            # Determine output path
            if not output_dir:
                output_dir = os.getcwd()
            
            filename = payload['filename']
            output_path = os.path.join(output_dir, filename)
            
            # Handle filename conflicts
            counter = 1
            base_name, ext = os.path.splitext(filename)
            while os.path.exists(output_path):
                new_filename = f"{base_name}_{counter}{ext}"
                output_path = os.path.join(output_dir, new_filename)
                counter += 1
            
            # Write file
            with open(output_path, 'wb') as f:
                f.write(file_data)
            
            return output_path
            
        except Exception as e:
            raise Exception(f"Error decoding file: {str(e)}")
    
    def generate_aes_key(self) -> bytes:
        """Generate a random AES-256 key"""
        return secrets.token_bytes(32)  # 256 bits
    
    def encrypt_with_aes(self, data: bytes, key: bytes) -> bytes:
        """Encrypt data with AES-256-CBC"""
        # Generate random IV
        iv = secrets.token_bytes(16)  # 128 bits for CBC
        
        # Pad data to block size
        padder = PKCS7(128).padder()  # AES block size is 128 bits
        padded_data = padder.update(data) + padder.finalize()
        
        # Encrypt
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        
        # Return IV + encrypted data
        return iv + encrypted_data
    
    def decrypt_with_aes(self, encrypted_data: bytes, key: bytes) -> bytes:
        """Decrypt data with AES-256-CBC"""
        # Extract IV and encrypted data
        iv = encrypted_data[:16]
        ciphertext = encrypted_data[16:]
        
        # Decrypt
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Remove padding
        unpadder = PKCS7(128).unpadder()
        data = unpadder.update(padded_data) + unpadder.finalize()
        
        return data
    
    def find_safe_embedding_zone(self, video_data: bytes) -> tuple:
        """Find safe zone in video for LSB embedding (skip headers)"""
        # Skip first 1KB to avoid video headers
        start_offset = 1024
        # Use middle 80% of video for embedding to avoid metadata at end
        usable_length = int(len(video_data) * 0.8)
        end_offset = start_offset + usable_length
        
        if end_offset > len(video_data):
            end_offset = len(video_data)
            
        return start_offset, end_offset
    
    def embed_lsb(self, video_data: bytes, secret_data: bytes) -> bytes:
        """Embed secret data into video using LSB steganography in safe zones"""
        start_offset, end_offset = self.find_safe_embedding_zone(video_data)
        available_bytes = end_offset - start_offset
        
        if len(secret_data) * 8 > available_bytes:
            raise ValueError(f"Secret data too large. Need {len(secret_data) * 8} bytes, have {available_bytes}")
        
        # Convert secret data to bits
        secret_bits = ''.join(format(byte, '08b') for byte in secret_data)
        
        # Create a copy of video data as bytearray for modification
        stego_video = bytearray(video_data)
        
        # Embed secret bits into LSBs in safe zone only
        for i, bit in enumerate(secret_bits):
            byte_index = start_offset + i
            if byte_index >= end_offset:
                break
            # Clear LSB and set to secret bit
            stego_video[byte_index] = (stego_video[byte_index] & 0xFE) | int(bit)
        
        return bytes(stego_video)
    
    def extract_lsb(self, stego_video: bytes, data_length: int, start_offset: int = None) -> bytes:
        """Extract secret data from video using LSB steganography"""
        if start_offset is None:
            start_offset, _ = self.find_safe_embedding_zone(stego_video)
        
        if start_offset + (data_length * 8) > len(stego_video):
            raise ValueError("Requested data length exceeds video size")
        
        # Extract LSBs from safe zone
        secret_bits = []
        for i in range(data_length * 8):
            byte_index = start_offset + i
            if byte_index >= len(stego_video):
                break
            secret_bits.append(str(stego_video[byte_index] & 1))
        
        # Convert bits back to bytes
        secret_data = bytearray()
        for i in range(0, len(secret_bits), 8):
            if i + 8 <= len(secret_bits):
                byte_bits = ''.join(secret_bits[i:i+8])
                secret_data.append(int(byte_bits, 2))
        
        return bytes(secret_data)
    
    def generate_keys(self) -> Tuple[bytes, bytes]:
        """Generate RSA key pair for encryption"""
        try:
            print(f"{Fore.YELLOW}🔑 Generating RSA-{KEY_SIZE} key pair...{Style.RESET_ALL}")
            
            # Generate private key
            self.private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=KEY_SIZE,
                backend=default_backend()
            )
            
            # Get public key
            self.public_key = self.private_key.public_key()
            
            # Serialize keys
            private_pem = self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            
            public_pem = self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            print(f"{Fore.GREEN}✓ Keys generated successfully!{Style.RESET_ALL}")
            return private_pem, public_pem
            
        except Exception as e:
            raise Exception(f"Error generating RSA keys: {str(e)}")
    
    def load_key_from_file(self, key_path: str, key_type: str) -> bytes:
        """Load public or private key from file"""
        try:
            if not os.path.exists(key_path):
                raise FileNotFoundError(f"{key_type} key file not found: {key_path}")
            
            with open(key_path, 'rb') as f:
                key_data = f.read()
            
            # Validate key format
            if key_type == "private":
                serialization.load_pem_private_key(key_data, password=None, backend=default_backend())
            else:
                serialization.load_pem_public_key(key_data, backend=default_backend())
            
            print(f"{Fore.GREEN}✓ {key_type.title()} key loaded successfully!{Style.RESET_ALL}")
            return key_data
            
        except Exception as e:
            raise Exception(f"Error loading {key_type} key: {str(e)}")
    
    def encrypt_payload(self, payload: Union[str, dict], public_key_pem: bytes) -> bytes:
        """Encrypt message or file payload using RSA public key"""
        try:
            # Load public key
            public_key = serialization.load_pem_public_key(
                public_key_pem,
                backend=default_backend()
            )
            
            # Handle different payload types
            if isinstance(payload, str):
                # Text message
                payload_data = {
                    'type': 'message',
                    'content': payload
                }
            else:
                # File payload
                payload_data = payload
            
            # Convert to JSON bytes
            payload_bytes = json.dumps(payload_data).encode('utf-8')
            
            # Check payload size (RSA has limitations)
            max_payload_size = (KEY_SIZE // 8) - 2 * 32 - 2  # OAEP padding overhead
            if len(payload_bytes) > max_payload_size:
                raise ValueError(f"Payload too large. Maximum size: {max_payload_size} bytes, got: {len(payload_bytes)} bytes")
            
            # Encrypt payload
            encrypted = public_key.encrypt(
                payload_bytes,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            return encrypted
            
        except Exception as e:
            raise Exception(f"Error encrypting payload: {str(e)}")
    
    def decrypt_payload(self, encrypted_payload: bytes, private_key_pem: bytes) -> dict:
        """Decrypt payload using RSA private key"""
        try:
            # Load private key
            private_key = serialization.load_pem_private_key(
                private_key_pem,
                password=None,
                backend=default_backend()
            )
            
            # Decrypt payload
            decrypted = private_key.decrypt(
                encrypted_payload,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            # Parse JSON
            payload_data = json.loads(decrypted.decode('utf-8'))
            
            return payload_data
            
        except Exception as e:
            raise Exception(f"Error decrypting payload: {str(e)}")
    
    # Backward compatibility methods
    def encrypt_message(self, message: str, public_key_pem: bytes) -> bytes:
        """Encrypt message using RSA public key (backward compatibility)"""
        return self.encrypt_payload(message, public_key_pem)
    
    def decrypt_message(self, encrypted_message: bytes, private_key_pem: bytes) -> str:
        """Decrypt message using RSA private key (backward compatibility)"""
        payload = self.decrypt_payload(encrypted_message, private_key_pem)
        if payload.get('type') == 'message':
            return payload['content']
        else:
            raise ValueError("Decrypted payload is not a text message")
    
    def whisper_to_video(self, video_path: str, payload: Union[str, dict], output_path: str, 
                        security_mode: str = "embedded", public_key_path: str = None, use_lsb: bool = None) -> dict:
        """Embed encrypted message or file in video with different security modes"""
        try:
            print(f"\n{Fore.BLUE}🎬 Starting video whisper process...{Style.RESET_ALL}")
            print(f"{Fore.CYAN}🔒 Security Mode: {security_mode.upper()}{Style.RESET_ALL}")
            
            # Check if video exists
            if not os.path.exists(video_path):
                raise FileNotFoundError(f"Video file not found: {video_path}")
            
            # Get video info
            video_size = os.path.getsize(video_path)
            print(f"📹 Input video: {os.path.basename(video_path)} ({video_size:,} bytes)")
            
            # Handle different security modes and key management
            private_key_filename = None
            
            if public_key_path and os.path.exists(public_key_path):
                # Use existing public key
                public_key_pem = self.load_key_from_file(public_key_path, "public")
                print(f"{Fore.YELLOW}🔑 Using existing public key from: {public_key_path}{Style.RESET_ALL}")
                
                if security_mode == "embedded":
                    # For embedded mode, try to find corresponding private key
                    base_name = os.path.splitext(public_key_path)[0]
                    potential_private_key = base_name.replace('_public', '_private') + '.pem'
                    
                    if os.path.exists(potential_private_key):
                        private_key_pem = self.load_key_from_file(potential_private_key, "private")
                        print(f"{Fore.GREEN}🔑 Found corresponding private key: {potential_private_key}{Style.RESET_ALL}")
                    else:
                        print(f"{Fore.RED}⚠️  Warning: Cannot find private key for embedded mode{Style.RESET_ALL}")
                        print(f"{Fore.RED}    Expected: {potential_private_key}{Style.RESET_ALL}")
                        print(f"{Fore.YELLOW}🔄 Generating new key pair instead...{Style.RESET_ALL}")
                        private_key_pem, public_key_pem = self.generate_keys()
                else:
                    # External mode - don't need private key for whisper
                    private_key_pem = None
                    
            else:
                # Generate new keys
                private_key_pem, public_key_pem = self.generate_keys()
                
                if security_mode == "external":
                    # Save private key separately for external mode
                    private_key_filename = f"{os.path.splitext(output_path)[0]}_private_key.pem"
                    with open(private_key_filename, 'wb') as f:
                        f.write(private_key_pem)
                    print(f"{Fore.RED}🔐 Private key saved separately: {private_key_filename}{Style.RESET_ALL}")
                    print(f"{Fore.RED}⚠️  IMPORTANT: Keep this private key file safe!{Style.RESET_ALL}")
                    
                    # Don't embed private key in video for external mode
                    private_key_for_embedding = None
                else:
                    # Embedded mode - keep private key for embedding
                    private_key_for_embedding = private_key_pem
            
            # Check payload size and determine method
            video_size = os.path.getsize(video_path)
            
            # Determine payload type and size
            if isinstance(payload, str):
                payload_type = "message"
                payload_size = len(payload.encode('utf-8'))
                print(f"📝 Message length: {len(payload)} characters ({payload_size} bytes)")
            else:
                payload_type = "file"
                payload_size = payload.get('file_size', len(json.dumps(payload).encode('utf-8')))
                print(f"📁 File: {payload.get('filename', 'unknown')} ({payload_size:,} bytes)")
            
            # Auto-determine method if not specified
            if use_lsb is None:
                rsa_capacity = self.calculate_max_capacity(video_size, use_lsb=False)
                lsb_capacity = self.calculate_max_capacity(video_size, use_lsb=True)
                
                if payload_size > rsa_capacity['max_file_size_bytes']:
                    if payload_size <= lsb_capacity['max_file_size_bytes']:
                        use_lsb = True
                        print(f"{Fore.YELLOW}📊 Payload too large for RSA-only mode, switching to LSB mode{Style.RESET_ALL}")
                    else:
                        raise ValueError(f"Payload too large even for LSB mode. Maximum: {lsb_capacity['max_file_size_bytes']:,} bytes")
                else:
                    use_lsb = False
                    print(f"{Fore.GREEN}📊 Using RSA-only mode for efficient small payload{Style.RESET_ALL}")
            
            # Check capacity for chosen method
            capacity = self.calculate_max_capacity(video_size, use_lsb=use_lsb)
            print(f"📊 Using {capacity['method']} - Max capacity: {capacity['max_file_size_bytes']:,} bytes")
            
            if payload_size > capacity['max_file_size_bytes']:
                raise ValueError(f"Payload too large for this video. Maximum: {capacity['max_file_size_bytes']:,} bytes, got: {payload_size:,} bytes")
            
            # Read original video
            print(f"{Fore.YELLOW}📖 Reading video data...{Style.RESET_ALL}")
            with open(video_path, 'rb') as f:
                video_data = f.read()
            
            if use_lsb:
                # Hybrid mode with safe append (no LSB to avoid video corruption)
                print(f"{Fore.YELLOW}🔐 Using hybrid encryption (AES + RSA) with safe append...{Style.RESET_ALL}")
                
                # Prepare payload data
                if isinstance(payload, str):
                    payload_data = {
                        'type': 'message',
                        'content': payload
                    }
                    checksum_data = payload.encode('utf-8')
                    original_size = len(payload)
                else:
                    payload_data = payload
                    checksum_data = json.dumps(payload).encode('utf-8')
                    original_size = payload.get('file_size', len(checksum_data))
                
                # Convert payload to JSON bytes
                payload_json = json.dumps(payload_data).encode('utf-8')
                
                # Generate AES key and encrypt payload
                aes_key = self.generate_aes_key()
                encrypted_payload_data = self.encrypt_with_aes(payload_json, aes_key)
                
                # Encrypt AES key with RSA
                encrypted_aes_key = self.encrypt_payload(base64.b64encode(aes_key).decode('utf-8'), public_key_pem)
                
                # Prepare hybrid whisper data
                hybrid_whisper_data = {
                    'version': VERSION,
                    'timestamp': datetime.now().isoformat(),
                    'security_mode': security_mode,
                    'payload_type': payload_type,
                    'method': 'RSA_AES',
                    'encrypted_aes_key': base64.b64encode(encrypted_aes_key).decode('utf-8'),
                    'checksum': hashlib.sha256(checksum_data).hexdigest(),
                    'original_size': original_size,
                    'data_length': len(encrypted_payload_data)
                }
                
                # Only embed private key in embedded mode
                if security_mode == "embedded" and private_key_for_embedding:
                    hybrid_whisper_data['private_key'] = private_key_for_embedding.decode('utf-8')
                else:
                    hybrid_whisper_data['private_key'] = None
                    hybrid_whisper_data['requires_external_key'] = True
                
                # Convert metadata to JSON
                metadata_json = json.dumps(hybrid_whisper_data, indent=2).encode('utf-8')
                
                # Create hybrid data structure (append method, no LSB)
                hybrid_data = (
                    LSB_MARKER +  # Start marker (reuse constant)
                    len(metadata_json).to_bytes(4, 'big') +  # Metadata length
                    metadata_json +  # Metadata JSON
                    encrypted_payload_data +  # Encrypted payload (no separate length needed)
                    LSB_END  # End marker
                )
                
                # Safe append method (no video corruption)
                print(f"{Fore.YELLOW}📎 Appending data safely to video...{Style.RESET_ALL}")
                print(f"📊 Hybrid data size: {len(hybrid_data):,} bytes")
                print(f"📊 Original video size: {len(video_data):,} bytes")
                
                # Add some padding to make it look like extended video data
                padding_size = 1024  # 1KB padding
                padding = secrets.token_bytes(padding_size)
                
                # Append: Original Video + Padding + Hybrid Data
                whispered_video = video_data + padding + hybrid_data
                
                print(f"{Fore.GREEN}✓ Safe append completed successfully{Style.RESET_ALL}")
                
                # Write whispered video
                print(f"{Fore.YELLOW}✍️  Writing whispered video...{Style.RESET_ALL}")
                with open(output_path, 'wb') as f:
                    f.write(whispered_video)
                
                whisper_size = len(hybrid_data)
                file_size_increase = len(whispered_video) - len(video_data)
                
            else:
                # Original RSA-only mode
                print(f"{Fore.YELLOW}🔐 Using RSA encryption...{Style.RESET_ALL}")
                encrypted_payload = self.encrypt_payload(payload, public_key_pem)
            
                # Prepare whisper data
                if isinstance(payload, str):
                    checksum_data = payload.encode('utf-8')
                    original_size = len(payload)
                else:
                    checksum_data = json.dumps(payload).encode('utf-8')
                    original_size = payload.get('file_size', len(checksum_data))
                
                whisper_data = {
                    'version': VERSION,
                    'timestamp': datetime.now().isoformat(),
                    'security_mode': security_mode,
                    'payload_type': payload_type,
                    'method': 'RSA_ONLY',
                    'encrypted_payload': base64.b64encode(encrypted_payload).decode('utf-8'),
                    'checksum': hashlib.sha256(checksum_data).hexdigest(),
                    'original_size': original_size
                }
                
                # Only embed private key in embedded mode
                if security_mode == "embedded" and private_key_for_embedding:
                    whisper_data['private_key'] = private_key_for_embedding.decode('utf-8')
                else:
                    whisper_data['private_key'] = None
                    whisper_data['requires_external_key'] = True
                
                # Convert to JSON
                json_data = json.dumps(whisper_data, indent=2).encode('utf-8')
                
                # Create whispered video (append method)
                whispered_video = video_data + WHISPER_MARKER + json_data + WHISPER_END
                
                # Write whispered video
                print(f"{Fore.YELLOW}✍️  Writing whispered video...{Style.RESET_ALL}")
                with open(output_path, 'wb') as f:
                    f.write(whispered_video)
                    
                whisper_size = len(json_data)
                file_size_increase = len(whispered_video) - len(video_data)
            
            # Save public key to file (only if not using existing key)
            if public_key_path and os.path.exists(public_key_path):
                # Use existing public key path
                public_key_filename = public_key_path
                print(f"{Fore.GREEN}✓ Using existing public key: {public_key_filename}{Style.RESET_ALL}")
            else:
                # Save new public key
                public_key_filename = f"{os.path.splitext(output_path)[0]}_public_key.pem"
                with open(public_key_filename, 'wb') as f:
                    f.write(public_key_pem)
                print(f"{Fore.GREEN}✓ New public key saved: {public_key_filename}{Style.RESET_ALL}")
            
            print(f"{Fore.GREEN}✓ Video whisper completed successfully!{Style.RESET_ALL}")
            
            # Calculate detailed statistics
            original_video_size = len(video_data)
            output_video_size = original_video_size + file_size_increase
            
            # Return results with detailed statistics
            result = {
                'status': 'success',
                'output_file': output_path,
                'public_key_file': public_key_filename,
                'public_key': public_key_pem.decode('utf-8'),
                'security_mode': security_mode,
                'payload_type': payload_type,
                'payload_size': original_size,
                'whisper_size': whisper_size,
                'file_size_increase': file_size_increase,
                'method': 'RSA_AES' if use_lsb else 'RSA_ONLY',
                # Detailed statistics
                'original_video_size': original_video_size,
                'output_video_size': output_video_size,
                'efficiency_ratio': (original_size / file_size_increase * 100) if file_size_increase > 0 else 100
            }
            
            if security_mode == "external" and private_key_filename:
                result['private_key_file'] = private_key_filename
            
            return result
            
        except Exception as e:
            return {
                'status': 'error',
                'error': str(e)
            }
    
    def listen_to_video(self, video_path: str, private_key_path: str = None, 
                       auto_prompt: bool = True) -> dict:
        """Extract and decrypt whispered message from video"""
        try:
            print(f"\n{Fore.BLUE}👂 Listening for whispers in video...{Style.RESET_ALL}")
            
            # Check if video exists
            if not os.path.exists(video_path):
                raise FileNotFoundError(f"Video file not found: {video_path}")
            
            # Read video file
            print(f"{Fore.YELLOW}📖 Reading video data...{Style.RESET_ALL}")
            with open(video_path, 'rb') as f:
                video_data = f.read()
            
            # Try to detect LSB whisper first
            print(f"{Fore.YELLOW}🔍 Detecting whisper method...{Style.RESET_ALL}")
            
            # Check for LSB markers
            is_lsb_mode = False
            encrypted_payload_data = None
            
            try:
                # Try to detect hybrid append format first (search from end)
                hybrid_marker_index = video_data.rfind(LSB_MARKER)
                hybrid_end_index = video_data.rfind(LSB_END)
                
                if hybrid_marker_index != -1 and hybrid_end_index != -1 and hybrid_end_index > hybrid_marker_index:
                    print(f"{Fore.CYAN}📡 Hybrid append whisper detected!{Style.RESET_ALL}")
                    
                    # Extract metadata length (4 bytes after marker)
                    metadata_length_start = hybrid_marker_index + len(LSB_MARKER)
                    metadata_length_bytes = video_data[metadata_length_start:metadata_length_start + 4]
                    metadata_length = int.from_bytes(metadata_length_bytes, 'big')
                    print(f"📊 Metadata length: {metadata_length} bytes")
                    
                    # Extract metadata JSON
                    metadata_start = metadata_length_start + 4
                    metadata_bytes = video_data[metadata_start:metadata_start + metadata_length]
                    whisper_data = json.loads(metadata_bytes.decode('utf-8'))
                    print(f"✓ Metadata extracted successfully")
                    
                    # Extract encrypted payload data (rest until end marker)
                    payload_start = metadata_start + metadata_length
                    encrypted_payload_data = video_data[payload_start:hybrid_end_index]
                    print(f"✓ Payload extracted successfully ({len(encrypted_payload_data)} bytes)")
                    
                    is_lsb_mode = True
                    
                else:
                    raise ValueError("Hybrid marker not found")
                    
            except Exception as e:
                print(f"🔍 Hybrid detection failed: {str(e)}")
                # Fall back to traditional append method
                print(f"{Fore.CYAN}📡 Traditional whisper format detected{Style.RESET_ALL}")
                
                # Find whisper markers for traditional format
                marker_index = video_data.rfind(WHISPER_MARKER)
                if marker_index == -1:
                    raise ValueError("No whispers found in this video")
                
                end_marker_index = video_data.rfind(WHISPER_END)
                if end_marker_index == -1:
                    raise ValueError("Corrupted whisper data")
                
                # Extract whisper data
                print(f"{Fore.YELLOW}🔍 Extracting whisper data...{Style.RESET_ALL}")
                json_data = video_data[marker_index + len(WHISPER_MARKER):end_marker_index]
                
                # Parse JSON
                whisper_data = json.loads(json_data.decode('utf-8'))
                is_lsb_mode = False
            
            # Check security mode
            security_mode = whisper_data.get('security_mode', 'embedded')
            requires_external_key = whisper_data.get('requires_external_key', False)
            
            print(f"{Fore.CYAN}🔒 Security Mode: {security_mode.upper()}{Style.RESET_ALL}")
            
            # Extract components
            checksum = whisper_data['checksum']
            timestamp = whisper_data.get('timestamp', 'Unknown')
            payload_type = whisper_data.get('payload_type', 'message')
            
            # Handle private key based on security mode
            private_key_pem = None
            
            if security_mode == "embedded" and not requires_external_key:
                # Use embedded private key
                if whisper_data.get('private_key'):
                    private_key_pem = whisper_data['private_key'].encode('utf-8')
                    print(f"{Fore.GREEN}🔑 Using embedded private key{Style.RESET_ALL}")
                else:
                    raise ValueError("No embedded private key found in embedded mode")
                    
            elif security_mode == "external" or requires_external_key:
                # Need external private key
                if private_key_path:
                    private_key_pem = self.load_key_from_file(private_key_path, "private")
                elif auto_prompt:
                    # Prompt for private key path
                    print(f"{Fore.RED}🔐 External private key required!{Style.RESET_ALL}")
                    while True:
                        key_path = input(f"{Fore.YELLOW}Enter private key file path: {Style.RESET_ALL}")
                        if key_path.strip():
                            try:
                                private_key_pem = self.load_key_from_file(key_path.strip(), "private")
                                break
                            except Exception as e:
                                print(f"{Fore.RED}Error: {str(e)}{Style.RESET_ALL}")
                                continue
                        else:
                            raise ValueError("Private key path is required for external security mode")
                else:
                    raise ValueError("Private key path required for external security mode")
            
            if not private_key_pem:
                raise ValueError("No private key available for decryption")
            
            # Decrypt payload based on method
            if is_lsb_mode and whisper_data.get('method') in ['LSB_HYBRID', 'RSA_AES']:
                # Hybrid decryption (AES + RSA)
                print(f"{Fore.YELLOW}🔓 Decrypting with hybrid method (AES + RSA)...{Style.RESET_ALL}")
                
                # Decrypt AES key with RSA
                encrypted_aes_key_b64 = whisper_data['encrypted_aes_key']
                encrypted_aes_key = base64.b64decode(encrypted_aes_key_b64)
                decrypted_aes_key_b64 = self.decrypt_payload(encrypted_aes_key, private_key_pem)
                aes_key = base64.b64decode(decrypted_aes_key_b64['content'])
                
                # Decrypt payload with AES
                decrypted_payload_json = self.decrypt_with_aes(encrypted_payload_data, aes_key)
                decrypted_payload = json.loads(decrypted_payload_json.decode('utf-8'))
                
            else:
                # Traditional RSA decryption
                print(f"{Fore.YELLOW}🔓 Decrypting with RSA...{Style.RESET_ALL}")
                encrypted_payload = base64.b64decode(whisper_data.get('encrypted_payload', whisper_data.get('encrypted_message', '')))
                decrypted_payload = self.decrypt_payload(encrypted_payload, private_key_pem)
            
            # Verify checksum based on payload type
            if payload_type == 'message' or decrypted_payload.get('type') == 'message':
                if payload_type == 'message':
                    # Old format compatibility
                    message_content = decrypted_payload.get('content', '')
                    checksum_data = message_content.encode('utf-8')
                else:
                    checksum_data = json.dumps(decrypted_payload).encode('utf-8')
            else:
                checksum_data = json.dumps(decrypted_payload).encode('utf-8')
            
            calculated_checksum = hashlib.sha256(checksum_data).hexdigest()
            if calculated_checksum != checksum:
                raise ValueError("Payload integrity check failed - whisper may be corrupted")
            
            print(f"{Fore.GREEN}✓ Whisper extracted successfully!{Style.RESET_ALL}")
            
            result = {
                'status': 'success',
                'payload': decrypted_payload,
                'payload_type': payload_type,
                'timestamp': timestamp,
                'security_mode': security_mode,
                'checksum_verified': True,
                'version': whisper_data.get('version', 'Unknown'),
                'requires_external_key': requires_external_key
            }
            
            # Add backward compatibility for message type
            if payload_type == 'message' or decrypted_payload.get('type') == 'message':
                result['message'] = decrypted_payload.get('content', '')
            
            return result
            
        except Exception as e:
            return {
                'status': 'error',
                'error': str(e)
            }
    
    def silence_video(self, video_path: str, output_path: str) -> dict:
        """Remove whispers from video (clean it)"""
        try:
            print(f"\n{Fore.BLUE}🤫 Silencing video whispers...{Style.RESET_ALL}")
            
            # Check if video exists
            if not os.path.exists(video_path):
                raise FileNotFoundError(f"Video file not found: {video_path}")
            
            # Read video file
            with open(video_path, 'rb') as f:
                video_data = f.read()
            
            # Find whisper marker
            marker_index = video_data.rfind(WHISPER_MARKER)
            if marker_index == -1:
                # No whispers found, just copy the file
                with open(output_path, 'wb') as f:
                    f.write(video_data)
                print(f"{Fore.YELLOW}ℹ️  No whispers found in video{Style.RESET_ALL}")
                return {
                    'status': 'success',
                    'message': 'No whispers found, video copied as is'
                }
            
            # Extract original video
            original_video = video_data[:marker_index]
            
            # Write silenced video
            with open(output_path, 'wb') as f:
                f.write(original_video)
            
            print(f"{Fore.GREEN}✓ Video silenced successfully!{Style.RESET_ALL}")
            
            return {
                'status': 'success',
                'message': 'Whispers removed successfully',
                'size_reduction': len(video_data) - len(original_video)
            }
            
        except Exception as e:
            return {
                'status': 'error',
                'error': str(e)
            }

class VideoWhisperGUI:
    """GUI Interface for VideoWhisper"""
    
    def __init__(self):
        self.root = tk.Tk()
        self.root.title(f"VideoWhisper v{VERSION} | Developed by Muh Ridwan Sukri")
        self.root.geometry("800x700")
        self.root.resizable(True, True)
        
        # VideoWhisper instance
        self.vw = VideoWhisper()
        
        # Variables
        self.video_path = tk.StringVar()
        self.output_path = tk.StringVar()
        self.security_mode = tk.StringVar(value="embedded")
        self.public_key_path = tk.StringVar()
        self.private_key_path = tk.StringVar()
        self.file_to_upload = tk.StringVar()
        self.use_lsb = tk.BooleanVar(value=False)
        
        self.setup_gui()
        
    def setup_gui(self):
        """Setup the GUI interface"""
        # Create notebook for tabs
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill='both', expand=True, padx=10, pady=5)
        
        # Create tabs
        self.whisper_frame = ttk.Frame(notebook)
        self.listen_frame = ttk.Frame(notebook)
        
        notebook.add(self.whisper_frame, text="🤫 Whisper (Hide)")
        notebook.add(self.listen_frame, text="👂 Listen (Extract)")
        
        self.setup_whisper_tab()
        self.setup_listen_tab()
        
        # Status bar
        self.status_var = tk.StringVar(value="Ready")
        status_bar = ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        
    def setup_whisper_tab(self):
        """Setup the whisper (hide) tab"""
        frame = self.whisper_frame
        
        # Title
        title = ttk.Label(frame, text="🤫 Hide Message or File in Video", font=("Arial", 14, "bold"))
        title.pack(pady=10)
        
        # Video selection
        video_frame = ttk.LabelFrame(frame, text="📹 Select Video File", padding=10)
        video_frame.pack(fill='x', padx=10, pady=5)
        
        video_entry_frame = ttk.Frame(video_frame)
        video_entry_frame.pack(fill='x')
        
        ttk.Entry(video_entry_frame, textvariable=self.video_path, width=60).pack(side='left', fill='x', expand=True)
        ttk.Button(video_entry_frame, text="Browse", command=self.browse_video_file).pack(side='right', padx=(5,0))
        
        # Video info label
        self.video_info_label = ttk.Label(video_frame, text="", foreground="blue")
        self.video_info_label.pack(pady=(5,0))
        
        # Content selection
        content_frame = ttk.LabelFrame(frame, text="📝 Content to Hide", padding=10)
        content_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        # Content type selection
        type_frame = ttk.Frame(content_frame)
        type_frame.pack(fill='x', pady=(0,10))
        
        self.content_type = tk.StringVar(value="message")
        ttk.Radiobutton(type_frame, text="📝 Text Message", variable=self.content_type, 
                       value="message", command=self.toggle_content_type).pack(side='left')
        ttk.Radiobutton(type_frame, text="📁 File Upload", variable=self.content_type, 
                       value="file", command=self.toggle_content_type).pack(side='left', padx=(20,0))
        
        # Message input
        self.message_frame = ttk.Frame(content_frame)
        self.message_frame.pack(fill='both', expand=True)
        
        ttk.Label(self.message_frame, text="Enter your secret message:").pack(anchor='w')
        self.message_text = scrolledtext.ScrolledText(self.message_frame, height=8, wrap=tk.WORD)
        self.message_text.pack(fill='both', expand=True, pady=(5,0))
        
        # File upload frame
        self.file_frame = ttk.Frame(content_frame)
        
        file_select_frame = ttk.Frame(self.file_frame)
        file_select_frame.pack(fill='x', pady=(0,10))
        
        ttk.Entry(file_select_frame, textvariable=self.file_to_upload, width=50).pack(side='left', fill='x', expand=True)
        ttk.Button(file_select_frame, text="Browse File", command=self.browse_file_to_upload).pack(side='right', padx=(5,0))
        
        self.file_info_label = ttk.Label(self.file_frame, text="", foreground="green")
        self.file_info_label.pack(pady=(0,5))
        
        self.capacity_label = ttk.Label(self.file_frame, text="", foreground="orange")
        self.capacity_label.pack()
        
        # Security settings
        security_frame = ttk.LabelFrame(frame, text="🔒 Security Settings", padding=10)
        security_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Label(security_frame, text="Security Mode:").pack(anchor='w')
        mode_frame = ttk.Frame(security_frame)
        mode_frame.pack(fill='x', pady=(5,10))
        
        ttk.Radiobutton(mode_frame, text="🔐 Embedded (All-in-one)", variable=self.security_mode, 
                       value="embedded").pack(side='left')
        ttk.Radiobutton(mode_frame, text="🔑 External (Separate key file)", variable=self.security_mode, 
                       value="external").pack(side='left', padx=(20,0))
        
        # LSB Mode option
        lsb_frame = ttk.Frame(security_frame)
        lsb_frame.pack(fill='x', pady=(10,0))
        
        self.hybrid_checkbox = ttk.Checkbutton(lsb_frame, text="🚀 Use Hybrid Mode (AES+RSA for larger files)", 
                       variable=self.use_lsb, command=self.update_lsb_info)
        self.hybrid_checkbox.pack(anchor='w')
        
        self.lsb_info_label = ttk.Label(lsb_frame, text="", foreground="blue")
        self.lsb_info_label.pack(anchor='w', pady=(5,0))
        
        # Public key for external mode
        key_frame = ttk.Frame(security_frame)
        key_frame.pack(fill='x')
        
        ttk.Label(key_frame, text="Public Key (Leave empty for auto-generate):").pack(anchor='w')
        key_entry_frame = ttk.Frame(key_frame)
        key_entry_frame.pack(fill='x', pady=(5,0))
        
        ttk.Entry(key_entry_frame, textvariable=self.public_key_path, width=50).pack(side='left', fill='x', expand=True)
        ttk.Button(key_entry_frame, text="Browse", command=self.browse_public_key).pack(side='right', padx=(5,0))
        
        # Output settings
        output_frame = ttk.LabelFrame(frame, text="📁 Output Settings", padding=10)
        output_frame.pack(fill='x', padx=10, pady=5)
        
        output_entry_frame = ttk.Frame(output_frame)
        output_entry_frame.pack(fill='x')
        
        ttk.Entry(output_entry_frame, textvariable=self.output_path, width=50).pack(side='left', fill='x', expand=True)
        ttk.Button(output_entry_frame, text="Browse", command=self.browse_output_file).pack(side='right', padx=(5,0))
        
        # Action buttons
        button_frame = ttk.Frame(frame)
        button_frame.pack(fill='x', padx=10, pady=10)
        
        ttk.Button(button_frame, text="🤫 Hide in Video", command=self.whisper_action, 
                  style='Accent.TButton').pack(side='right', padx=(5,0))
        ttk.Button(button_frame, text="🧪 Test Capacity", command=self.test_capacity).pack(side='right')
        
        # Initialize content type
        self.toggle_content_type()
        
    def setup_listen_tab(self):
        """Setup the listen (extract) tab"""
        frame = self.listen_frame
        
        # Title
        title = ttk.Label(frame, text="👂 Extract Hidden Content from Video", font=("Arial", 14, "bold"))
        title.pack(pady=10)
        
        # Video selection
        listen_video_frame = ttk.LabelFrame(frame, text="📹 Select Video with Hidden Content", padding=10)
        listen_video_frame.pack(fill='x', padx=10, pady=5)
        
        self.listen_video_path = tk.StringVar()
        listen_entry_frame = ttk.Frame(listen_video_frame)
        listen_entry_frame.pack(fill='x')
        
        ttk.Entry(listen_entry_frame, textvariable=self.listen_video_path, width=60).pack(side='left', fill='x', expand=True)
        ttk.Button(listen_entry_frame, text="Browse", command=self.browse_listen_video).pack(side='right', padx=(5,0))
        
        # Private key for external mode
        key_frame = ttk.LabelFrame(frame, text="🔑 Private Key (for External Mode)", padding=10)
        key_frame.pack(fill='x', padx=10, pady=5)
        
        key_entry_frame = ttk.Frame(key_frame)
        key_entry_frame.pack(fill='x')
        
        ttk.Entry(key_entry_frame, textvariable=self.private_key_path, width=50).pack(side='left', fill='x', expand=True)
        ttk.Button(key_entry_frame, text="Browse", command=self.browse_private_key).pack(side='right', padx=(5,0))
        
        ttk.Label(key_frame, text="Leave empty for embedded mode", foreground="gray").pack(anchor='w', pady=(5,0))
        
        # Results display
        result_frame = ttk.LabelFrame(frame, text="📋 Extracted Content", padding=10)
        result_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        # Info display
        self.info_text = scrolledtext.ScrolledText(result_frame, height=6, wrap=tk.WORD)
        self.info_text.pack(fill='x', pady=(0,10))
        
        # Content display
        self.result_text = scrolledtext.ScrolledText(result_frame, height=10, wrap=tk.WORD)
        self.result_text.pack(fill='both', expand=True)
        
        # Action buttons
        listen_button_frame = ttk.Frame(frame)
        listen_button_frame.pack(fill='x', padx=10, pady=10)
        
        ttk.Button(listen_button_frame, text="💾 Save File", command=self.save_extracted_file).pack(side='right', padx=(5,0))
        ttk.Button(listen_button_frame, text="👂 Extract Content", command=self.listen_action, 
                  style='Accent.TButton').pack(side='right')
        
        self.extracted_payload = None
        
    def toggle_content_type(self):
        """Toggle between message and file input"""
        if self.content_type.get() == "message":
            self.file_frame.pack_forget()
            self.message_frame.pack(fill='both', expand=True)
        else:
            self.message_frame.pack_forget()
            self.file_frame.pack(fill='both', expand=True)
            
    def browse_video_file(self):
        """Browse for video file"""
        filename = filedialog.askopenfilename(
            title="Select Video File",
            filetypes=[
                ("Video files", "*.mp4 *.avi *.mov *.mkv *.wmv *.flv *.webm"),
                ("All files", "*.*")
            ]
        )
        if filename:
            self.video_path.set(filename)
            self.update_video_info()
            
    def update_video_info(self):
        """Update video information display"""
        if self.video_path.get() and os.path.exists(self.video_path.get()):
            size = os.path.getsize(self.video_path.get())
            
            # Calculate capacity for both modes
            rsa_capacity = self.vw.calculate_max_capacity(size, use_lsb=False)
            lsb_capacity = self.vw.calculate_max_capacity(size, use_lsb=True)
            
            info_text = f"Size: {size:,} bytes | RSA: {rsa_capacity['max_file_size_bytes']:,} bytes | Hybrid: {lsb_capacity['max_file_size_bytes']:,} bytes ({lsb_capacity['max_file_size_mb']:.1f} MB)"
            self.video_info_label.config(text=info_text)
            
            # Auto-generate output path
            if not self.output_path.get():
                base, ext = os.path.splitext(self.video_path.get())
                self.output_path.set(f"{base}_whispered{ext}")
                
            # Update LSB info
            self.update_lsb_info()
                
    def browse_file_to_upload(self):
        """Browse for file to upload"""
        filename = filedialog.askopenfilename(
            title="Select File to Hide",
            filetypes=[
                ("Text files", "*.txt"),
                ("Image files", "*.jpg *.jpeg *.png *.gif *.bmp"),
                ("Document files", "*.pdf *.doc *.docx"),
                ("Audio files", "*.mp3 *.wav"),
                ("Archive files", "*.zip *.rar"),
                ("All files", "*.*")
            ]
        )
        if filename:
            self.file_to_upload.set(filename)
            self.update_file_info()
            
    def update_file_info(self):
        """Update file information display"""
        if self.file_to_upload.get() and os.path.exists(self.file_to_upload.get()):
            size = os.path.getsize(self.file_to_upload.get())
            ext = os.path.splitext(self.file_to_upload.get())[1].lower()
            
            # Check if file type is supported
            if ext in SUPPORTED_FILE_TYPES:
                self.file_info_label.config(text=f"✓ File: {os.path.basename(self.file_to_upload.get())} ({size:,} bytes)", foreground="green")
            else:
                self.file_info_label.config(text=f"⚠ Unsupported file type: {ext}", foreground="red")
                
            # Update capacity info
            if self.video_path.get() and os.path.exists(self.video_path.get()):
                video_size = os.path.getsize(self.video_path.get())
                rsa_capacity = self.vw.calculate_max_capacity(video_size, use_lsb=False)
                lsb_capacity = self.vw.calculate_max_capacity(video_size, use_lsb=True)
                
                if size <= rsa_capacity['max_file_size_bytes']:
                    self.capacity_label.config(text=f"✓ File fits in RSA mode", foreground="green")
                    # Re-enable hybrid checkbox for small files
                    self.hybrid_checkbox.config(state='normal')
                elif size <= lsb_capacity['max_file_size_bytes']:
                    self.capacity_label.config(text=f"⚠ File requires Hybrid mode (too large for RSA)", foreground="orange")
                    # Auto-enable Hybrid mode and disable checkbox
                    self.use_lsb.set(True)
                    self.update_lsb_info()
                    # Disable hybrid checkbox (force hybrid mode)
                    self.hybrid_checkbox.config(state='disabled')
                    self.lsb_info_label.config(text="Hybrid mode is required for this file size", foreground="red")
                else:
                    self.capacity_label.config(text=f"✗ File too large even for Hybrid! Max: {lsb_capacity['max_file_size_bytes']:,} bytes", foreground="red")
            else:
                self.capacity_label.config(text="Select video file first to check capacity", foreground="orange")
                
    def browse_public_key(self):
        """Browse for public key file"""
        filename = filedialog.askopenfilename(
            title="Select Public Key File",
            filetypes=[("PEM files", "*.pem"), ("All files", "*.*")]
        )
        if filename:
            self.public_key_path.set(filename)
            
    def browse_private_key(self):
        """Browse for private key file"""
        filename = filedialog.askopenfilename(
            title="Select Private Key File",
            filetypes=[("PEM files", "*.pem"), ("All files", "*.*")]
        )
        if filename:
            self.private_key_path.set(filename)
            
    def browse_output_file(self):
        """Browse for output file location"""
        filename = filedialog.asksaveasfilename(
            title="Save Whispered Video As",
            defaultextension=".mp4",
            filetypes=[
                ("Video files", "*.mp4 *.avi *.mov *.mkv"),
                ("All files", "*.*")
            ]
        )
        if filename:
            self.output_path.set(filename)
            
    def browse_listen_video(self):
        """Browse for video file to listen to"""
        filename = filedialog.askopenfilename(
            title="Select Video with Hidden Content",
            filetypes=[
                ("Video files", "*.mp4 *.avi *.mov *.mkv *.wmv *.flv *.webm"),
                ("All files", "*.*")
            ]
        )
        if filename:
            self.listen_video_path.set(filename)
    
    def update_lsb_info(self):
        """Update hybrid mode information"""
        if self.use_lsb.get():
            self.lsb_info_label.config(
                text="Hybrid mode uses AES+RSA encryption and safely appends data (no video corruption)",
                foreground="blue"
            )
        else:
            self.lsb_info_label.config(text="", foreground="blue")
            
    def test_capacity(self):
        """Test video capacity"""
        if not self.video_path.get():
            messagebox.showerror("Error", "Please select a video file first")
            return
            
        if not os.path.exists(self.video_path.get()):
            messagebox.showerror("Error", "Video file not found")
            return
            
        try:
            video_size = os.path.getsize(self.video_path.get())
            rsa_capacity = self.vw.calculate_max_capacity(video_size, use_lsb=False)
            lsb_capacity = self.vw.calculate_max_capacity(video_size, use_lsb=True)
            
            info = f"""Video Capacity Analysis:

Video Size: {video_size:,} bytes ({video_size/(1024*1024):.2f} MB)

RSA-Only Mode:
• Maximum File Size: {rsa_capacity['max_file_size_bytes']:,} bytes ({rsa_capacity['max_file_size_mb']:.3f} MB)
• Method: Traditional append to video file
• Best for: Small messages and files

Hybrid Append Mode:
• Maximum File Size: {lsb_capacity['max_file_size_bytes']:,} bytes ({lsb_capacity['max_file_size_mb']:.1f} MB)
• Method: Hybrid encryption (AES+RSA) + Safe append
• Best for: Larger files without video corruption

Recommendation: Use Hybrid mode for files larger than {rsa_capacity['max_file_size_bytes']:,} bytes."""
            
            messagebox.showinfo("Video Capacity Analysis", info)
            
        except Exception as e:
            messagebox.showerror("Error", f"Error analyzing video: {str(e)}")
            
    def whisper_action(self):
        """Perform whisper action in background thread"""
        # Validation
        if not self.video_path.get():
            messagebox.showerror("Error", "Please select a video file")
            return
            
        if not self.output_path.get():
            messagebox.showerror("Error", "Please specify output file path")
            return
            
        if self.content_type.get() == "message":
            content = self.message_text.get(1.0, tk.END).strip()
            if not content:
                messagebox.showerror("Error", "Please enter a message")
                return
        else:
            if not self.file_to_upload.get():
                messagebox.showerror("Error", "Please select a file to upload")
                return
                
        # Start background thread
        thread = threading.Thread(target=self._whisper_worker, daemon=True)
        thread.start()
        
    def _whisper_worker(self):
        """Background worker for whisper operation"""
        try:
            self.status_var.set("Processing...")
            self.root.update()
            
            # Prepare payload
            if self.content_type.get() == "message":
                payload = self.message_text.get(1.0, tk.END).strip()
            else:
                payload = self.vw.encode_file_to_payload(self.file_to_upload.get())
            
            # Perform whisper
            result = self.vw.whisper_to_video(
                self.video_path.get(),
                payload,
                self.output_path.get(),
                self.security_mode.get(),
                self.public_key_path.get() if self.public_key_path.get() else None,
                self.use_lsb.get()
            )
            
            # Update UI in main thread
            self.root.after(0, self._whisper_complete, result)
            
        except Exception as e:
            self.root.after(0, self._whisper_error, str(e))
            
    def _whisper_complete(self, result):
        """Handle whisper completion"""
        self.status_var.set("Ready")
        
        if result['status'] == 'success':
            info = f"""✅ Whisper completed successfully!

Output Files:
• Whispered video: {result['output_file']}
• Public key: {result['public_key_file']}"""

            if 'private_key_file' in result:
                info += f"\n• Private key: {result['private_key_file']}"
                
            info += f"""

Detailed Statistics:
• Security mode: {result['security_mode']}
• Encryption method: {result['method']}
• Payload type: {result['payload_type']}
• Original video: {result['original_video_size']:,} bytes
• Payload size: {result['payload_size']:,} bytes
• Output video: {result['output_video_size']:,} bytes
• Size increase: {result['file_size_increase']:,} bytes
• Efficiency: {result['efficiency_ratio']:.1f}%"""

            if result['security_mode'] == "external":
                info += "\n\n⚠️ Private key is NOT embedded in video. Keep private key file safe!"
                
            messagebox.showinfo("Success", info)
        else:
            messagebox.showerror("Error", f"Whisper failed: {result['error']}")
            
    def _whisper_error(self, error):
        """Handle whisper error"""
        self.status_var.set("Ready")
        messagebox.showerror("Error", f"Whisper failed: {error}")
        
    def listen_action(self):
        """Perform listen action in background thread"""
        if not self.listen_video_path.get():
            messagebox.showerror("Error", "Please select a video file")
            return
            
        # Start background thread
        thread = threading.Thread(target=self._listen_worker, daemon=True)
        thread.start()
        
    def _listen_worker(self):
        """Background worker for listen operation"""
        try:
            self.status_var.set("Extracting...")
            self.root.update()
            
            # Perform listen
            result = self.vw.listen_to_video(
                self.listen_video_path.get(),
                self.private_key_path.get() if self.private_key_path.get() else None,
                auto_prompt=False
            )
            
            # Update UI in main thread
            self.root.after(0, self._listen_complete, result)
            
        except Exception as e:
            self.root.after(0, self._listen_error, str(e))
            
    def _listen_complete(self, result):
        """Handle listen completion"""
        self.status_var.set("Ready")
        
        if result['status'] == 'success':
            # Clear previous results
            self.info_text.delete(1.0, tk.END)
            self.result_text.delete(1.0, tk.END)
            
            # Display info
            info = f"""✅ Content extracted successfully!

Details:
• Version: {result['version']}
• Security Mode: {result['security_mode']}
• Payload Type: {result['payload_type']}
• Timestamp: {result['timestamp']}
• External Key Required: {'Yes' if result.get('requires_external_key') else 'No'}
• Checksum: {'✓ Verified' if result['checksum_verified'] else '✗ Failed'}

"""
            self.info_text.insert(tk.END, info)
            
            # Display content
            payload = result['payload']
            if result['payload_type'] == 'message' or payload.get('type') == 'message':
                # Text message
                message = payload.get('content', result.get('message', ''))
                self.result_text.insert(tk.END, f"📝 SECRET MESSAGE:\n\n{message}")
                self.extracted_payload = None
            else:
                # File
                file_info = f"""📁 HIDDEN FILE:

Filename: {payload.get('filename', 'unknown')}
File Type: {payload.get('file_extension', 'unknown')}
MIME Type: {payload.get('mime_type', 'unknown')}
File Size: {payload.get('file_size', 0):,} bytes
Checksum: {payload.get('checksum', 'unknown')}

Click 'Save File' button to extract the file to disk."""
                
                self.result_text.insert(tk.END, file_info)
                self.extracted_payload = payload
                
        else:
            self.info_text.delete(1.0, tk.END)
            self.result_text.delete(1.0, tk.END)
            self.info_text.insert(tk.END, f"❌ Error: {result['error']}")
            self.extracted_payload = None
            
    def _listen_error(self, error):
        """Handle listen error"""
        self.status_var.set("Ready")
        self.info_text.delete(1.0, tk.END)
        self.result_text.delete(1.0, tk.END)
        self.info_text.insert(tk.END, f"❌ Error: {error}")
        self.extracted_payload = None
        
    def save_extracted_file(self):
        """Save extracted file to disk"""
        if not self.extracted_payload:
            messagebox.showwarning("Warning", "No file to save. Extract a file first.")
            return
            
        try:
            # Ask for save location
            suggested_filename = self.extracted_payload.get('filename', 'extracted_file')
            filename = filedialog.asksaveasfilename(
                title="Save Extracted File",
                initialfile=suggested_filename,
                filetypes=[("All files", "*.*")]
            )
            
            if filename:
                output_path = self.vw.decode_file_from_payload(self.extracted_payload, os.path.dirname(filename))
                
                # Rename to user's chosen filename
                if output_path != filename:
                    os.rename(output_path, filename)
                    output_path = filename
                    
                messagebox.showinfo("Success", f"File saved successfully:\n{output_path}")
                
        except Exception as e:
            messagebox.showerror("Error", f"Error saving file: {str(e)}")
            
    def run(self):
        """Run the GUI"""
        self.root.mainloop()

# CLI Interface
@click.group()
def cli():
    """VideoWhisper - Hide encrypted messages in video files with enhanced security"""
    pass

@cli.command()
def gui():
    """Launch the interactive GUI interface"""
    try:
        print(f"{Fore.CYAN}🚀 Launching VideoWhisper GUI...{Style.RESET_ALL}")
        app = VideoWhisperGUI()
        app.run()
    except Exception as e:
        print(f"{Fore.RED}✗ Error launching GUI: {str(e)}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}💡 Make sure tkinter is installed: pip install tk{Style.RESET_ALL}")

@cli.command()
@click.option('--video', '-v', required=True, help='Input video file path')
@click.option('--message', '-m', help='Secret message to whisper')
@click.option('--file', '-f', help='File to hide in video')
@click.option('--output', '-o', help='Output video file path (default: input_whispered.ext)')
@click.option('--security-mode', '-s', 
              type=click.Choice(['embedded', 'external']), 
              default='embedded',
              help='Security mode: embedded (default) or external')
@click.option('--public-key', '-k', help='Path to public key file (for external mode)')
@click.option('--hybrid', is_flag=True, help='Force Hybrid mode (AES+RSA) for larger files')
def whisper(video, message, file, output, security_mode, public_key, hybrid):
    """Whisper a secret message or file into a video"""
    if not message and not file:
        print(f"{Fore.RED}✗ Error: Please provide either --message or --file{Style.RESET_ALL}")
        return
        
    if message and file:
        print(f"{Fore.RED}✗ Error: Please provide either message OR file, not both{Style.RESET_ALL}")
        return
    
    if not output:
        base, ext = os.path.splitext(video)
        output = f"{base}_whispered{ext}"
    
    vw = VideoWhisper()
    
    try:
        # Prepare payload
        if message:
            payload = message
            payload_type = "message"
        else:
            payload = vw.encode_file_to_payload(file)
            payload_type = "file"
            
        result = vw.whisper_to_video(video, payload, output, security_mode, public_key, hybrid)
    
        if result['status'] == 'success':
            print(f"\n{Fore.GREEN}📁 Output files:{Style.RESET_ALL}")
            print(f"  - Whispered video: {result['output_file']}")
            print(f"  - Public key: {result['public_key_file']}")
            if 'private_key_file' in result:
                print(f"  - Private key: {result['private_key_file']}")
            
            print(f"\n{Fore.YELLOW}📊 Detailed Statistics:{Style.RESET_ALL}")
            print(f"  - Security mode: {result['security_mode']}")
            print(f"  - Encryption method: {result['method']}")
            print(f"  - Payload type: {result['payload_type']}")
            print(f"  - Original video size: {result['original_video_size']:,} bytes")
            print(f"  - Payload size: {result['payload_size']:,} bytes")
            print(f"  - Output video size: {result['output_video_size']:,} bytes")
            print(f"  - File size increase: {result['file_size_increase']:,} bytes")
            print(f"  - Efficiency ratio: {result['efficiency_ratio']:.1f}%")
            
            if security_mode == "external":
                print(f"\n{Fore.RED}⚠️  SECURITY NOTICE:{Style.RESET_ALL}")
                print(f"  - Private key is NOT embedded in video")
                print(f"  - Keep private key file safe for decryption")
            
            print(f"\n{Fore.CYAN}💡 Share the public key file to allow others to create whispers!{Style.RESET_ALL}")
        else:
            print(f"\n{Fore.RED}✗ Error: {result['error']}{Style.RESET_ALL}")
            
    except Exception as e:
        print(f"\n{Fore.RED}✗ Error: {str(e)}{Style.RESET_ALL}")

@cli.command()
@click.option('--video', '-v', required=True, help='Video file with whispered content')
@click.option('--private-key', '-k', help='Path to private key file (for external mode)')
@click.option('--output-dir', '-d', help='Output directory for extracted files')
@click.option('--no-prompt', is_flag=True, help='Disable interactive prompts')
def listen(video, private_key, output_dir, no_prompt):
    """Listen to whispers hidden in a video"""
    vw = VideoWhisper()
    result = vw.listen_to_video(video, private_key, not no_prompt)
    
    if result['status'] == 'success':
        print(f"\n{Fore.GREEN}📋 Whisper Details:{Style.RESET_ALL}")
        print(f"  - Version: {result['version']}")
        print(f"  - Security Mode: {result['security_mode']}")
        print(f"  - Payload Type: {result['payload_type']}")
        print(f"  - Timestamp: {result['timestamp']}")
        print(f"  - External Key Required: {'Yes' if result.get('requires_external_key') else 'No'}")
        print(f"  - Checksum: {'✓ Verified' if result['checksum_verified'] else '✗ Failed'}")
        
        payload = result['payload']
        if result['payload_type'] == 'message' or payload.get('type') == 'message':
            # Text message
            message = payload.get('content', result.get('message', ''))
            print(f"\n{Fore.CYAN}💬 SECRET MESSAGE:{Style.RESET_ALL}")
            print(f"{Fore.WHITE}{message}{Style.RESET_ALL}")
        else:
            # File
            print(f"\n{Fore.CYAN}📁 HIDDEN FILE:{Style.RESET_ALL}")
            print(f"  - Filename: {payload.get('filename', 'unknown')}")
            print(f"  - File Type: {payload.get('file_extension', 'unknown')}")
            print(f"  - MIME Type: {payload.get('mime_type', 'unknown')}")
            print(f"  - File Size: {payload.get('file_size', 0):,} bytes")
            print(f"  - Checksum: {payload.get('checksum', 'unknown')}")
            
            try:
                # Save file
                if not output_dir:
                    output_dir = os.getcwd()
                    
                output_path = vw.decode_file_from_payload(payload, output_dir)
                print(f"\n{Fore.GREEN}💾 File extracted successfully:{Style.RESET_ALL}")
                print(f"  - Location: {output_path}")
                
            except Exception as e:
                print(f"\n{Fore.RED}✗ Error extracting file: {str(e)}{Style.RESET_ALL}")
                
    else:
        print(f"\n{Fore.RED}✗ Error: {result['error']}{Style.RESET_ALL}")

@cli.command()
@click.option('--video', '-v', required=True, help='Video file to silence')
@click.option('--output', '-o', help='Output cleaned video file (default: input_silenced.ext)')
def silence(video, output):
    """Remove whispers from a video"""
    if not output:
        base, ext = os.path.splitext(video)
        output = f"{base}_silenced{ext}"
    
    vw = VideoWhisper()
    result = vw.silence_video(video, output)
    
    if result['status'] == 'success':
        print(f"\n{Fore.GREEN}✓ {result['message']}{Style.RESET_ALL}")
        if 'size_reduction' in result:
            print(f"{Fore.YELLOW}📉 Size reduced by: {result['size_reduction']:,} bytes{Style.RESET_ALL}")
        print(f"{Fore.CYAN}📁 Output: {output}{Style.RESET_ALL}")
    else:
        print(f"\n{Fore.RED}✗ Error: {result['error']}{Style.RESET_ALL}")

@cli.command()
def test():
    """Run a comprehensive test with both security modes and LSB"""
    print(f"{Fore.CYAN}🧪 Running VideoWhisper comprehensive test...{Style.RESET_ALL}")
    
    # Create a larger test video file to support LSB
    test_video = "test_video.bin"
    test_message = "This is a secret test message! 🤫"
    test_file_content = b"This is test file content for LSB testing. " * 50  # ~2KB content
    
    try:
        # Create dummy video (larger for LSB testing)
        print(f"📹 Creating test video file...")
        with open(test_video, 'wb') as f:
            # Create a larger dummy video with varied content
            for i in range(10000):  # ~100KB video
                f.write(bytes([i % 256] * 10))
        
        # Create test file
        test_file = "test_file.txt"
        with open(test_file, 'wb') as f:
            f.write(test_file_content)
        
        vw = VideoWhisper()
        
        # Test 1: RSA-only mode with message
        print(f"\n{Fore.YELLOW}Test 1: RSA-only mode (message){Style.RESET_ALL}")
        output_rsa = "test_rsa.bin"
        result1 = vw.whisper_to_video(test_video, test_message, output_rsa, "embedded", use_lsb=False)
        
        if result1['status'] == 'success':
            print(f"{Fore.GREEN}✓ RSA whisper test passed!{Style.RESET_ALL}")
            
            # Test extraction
            listen_result1 = vw.listen_to_video(output_rsa, auto_prompt=False)
            if listen_result1['status'] == 'success' and listen_result1.get('message') == test_message:
                print(f"{Fore.GREEN}✓ RSA listen test passed!{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}✗ RSA listen test failed: {listen_result1.get('error', 'Unknown error')}{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}✗ RSA whisper test failed: {result1.get('error')}{Style.RESET_ALL}")
        
        # Test 2: Hybrid mode with file
        print(f"\n{Fore.YELLOW}Test 2: Hybrid mode (file){Style.RESET_ALL}")
        output_hybrid = "test_hybrid.bin"
        
        # Encode test file
        file_payload = vw.encode_file_to_payload(test_file)
        result2 = vw.whisper_to_video(test_video, file_payload, output_hybrid, "embedded", use_lsb=True)
        
        if result2['status'] == 'success':
            print(f"{Fore.GREEN}✓ Hybrid whisper test passed!{Style.RESET_ALL}")
            
            # Test extraction
            listen_result2 = vw.listen_to_video(output_hybrid, auto_prompt=False)
            if listen_result2['status'] == 'success':
                payload = listen_result2.get('payload')
                if payload and payload.get('type') == 'file':
                    # Try to decode file
                    try:
                        extracted_file = vw.decode_file_from_payload(payload, ".")
                        with open(extracted_file, 'rb') as f:
                            extracted_content = f.read()
                        
                        if extracted_content == test_file_content:
                            print(f"{Fore.GREEN}✓ Hybrid listen test passed!{Style.RESET_ALL}")
                        else:
                            print(f"{Fore.RED}✗ Hybrid content mismatch!{Style.RESET_ALL}")
                        
                        # Cleanup extracted file
                        if os.path.exists(extracted_file):
                            os.remove(extracted_file)
                            
                    except Exception as e:
                        print(f"{Fore.RED}✗ Hybrid file extraction failed: {str(e)}{Style.RESET_ALL}")
                else:
                    print(f"{Fore.RED}✗ Hybrid payload type mismatch{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}✗ Hybrid listen test failed: {listen_result2.get('error', 'Unknown error')}{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}✗ Hybrid whisper test failed: {result2.get('error')}{Style.RESET_ALL}")
        
        # Test 3: Auto-detection mode
        print(f"\n{Fore.YELLOW}Test 3: Auto-detection mode{Style.RESET_ALL}")
        output_auto = "test_auto.bin"
        result3 = vw.whisper_to_video(test_video, file_payload, output_auto, "embedded", use_lsb=None)
        
        if result3['status'] == 'success':
            print(f"{Fore.GREEN}✓ Auto-detection test passed! Method: {result3.get('method')}{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}✗ Auto-detection test failed: {result3.get('error')}{Style.RESET_ALL}")
        
        # Cleanup
        cleanup_files = [
            test_video, test_file, output_rsa, output_hybrid, output_auto,
            "test_rsa_public_key.pem", "test_hybrid_public_key.pem", "test_auto_public_key.pem"
        ]
        
        for f in cleanup_files:
            if os.path.exists(f):
                os.remove(f)
        
        print(f"\n{Fore.GREEN}✓ All tests completed!{Style.RESET_ALL}")
                
    except Exception as e:
        print(f"{Fore.RED}✗ Test failed: {str(e)}{Style.RESET_ALL}")
        import traceback
        traceback.print_exc()

if __name__ == '__main__':
    # If no arguments provided, launch GUI
    if len(sys.argv) == 1:
        try:
            print(f"{Fore.CYAN}🚀 No arguments provided. Launching GUI...{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}💡 Use 'python videowhisper.py --help' to see CLI options{Style.RESET_ALL}")
            app = VideoWhisperGUI()
            app.run()
        except Exception as e:
            print(f"{Fore.RED}✗ Error launching GUI: {str(e)}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}💡 Using CLI instead. Use --help for options.{Style.RESET_ALL}")
            cli()
    else:
        cli()