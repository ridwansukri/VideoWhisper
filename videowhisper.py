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
from typing import Tuple, Optional
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
import click
from colorama import init, Fore, Style
import getpass

# Initialize colorama for Windows
init()

# Constants
WHISPER_MARKER = b"VIDEOWHISPER_START_v1.1"
WHISPER_END = b"VIDEOWHISPER_END_v1.1"
KEY_SIZE = 2048
VERSION = "1.1.0"

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
    
    def encrypt_message(self, message: str, public_key_pem: bytes) -> bytes:
        """Encrypt message using RSA public key"""
        try:
            # Load public key
            public_key = serialization.load_pem_public_key(
                public_key_pem,
                backend=default_backend()
            )
            
            # Convert message to bytes
            message_bytes = message.encode('utf-8')
            
            # Check message size (RSA has limitations)
            max_message_size = (KEY_SIZE // 8) - 2 * 32 - 2  # OAEP padding overhead
            if len(message_bytes) > max_message_size:
                raise ValueError(f"Message too long. Maximum size: {max_message_size} bytes")
            
            # Encrypt message
            encrypted = public_key.encrypt(
                message_bytes,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            return encrypted
            
        except Exception as e:
            raise Exception(f"Error encrypting message: {str(e)}")
    
    def decrypt_message(self, encrypted_message: bytes, private_key_pem: bytes) -> str:
        """Decrypt message using RSA private key"""
        try:
            # Load private key
            private_key = serialization.load_pem_private_key(
                private_key_pem,
                password=None,
                backend=default_backend()
            )
            
            # Decrypt message
            decrypted = private_key.decrypt(
                encrypted_message,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            return decrypted.decode('utf-8')
            
        except Exception as e:
            raise Exception(f"Error decrypting message: {str(e)}")
    
    def whisper_to_video(self, video_path: str, message: str, output_path: str, 
                        security_mode: str = "embedded", public_key_path: str = None) -> dict:
        """Embed encrypted message in video with different security modes"""
        try:
            print(f"\n{Fore.BLUE}🎬 Starting video whisper process...{Style.RESET_ALL}")
            print(f"{Fore.CYAN}🔒 Security Mode: {security_mode.upper()}{Style.RESET_ALL}")
            
            # Check if video exists
            if not os.path.exists(video_path):
                raise FileNotFoundError(f"Video file not found: {video_path}")
            
            # Get video info
            video_size = os.path.getsize(video_path)
            print(f"📹 Input video: {os.path.basename(video_path)} ({video_size:,} bytes)")
            
            # Handle different security modes
            if security_mode == "external" and public_key_path:
                # Use external public key
                public_key_pem = self.load_key_from_file(public_key_path, "public")
                private_key_pem = None  # Don't embed private key
                print(f"{Fore.YELLOW}🔑 Using external public key from: {public_key_path}{Style.RESET_ALL}")
            elif security_mode == "external":
                # Generate keys but don't embed private key
                private_key_pem, public_key_pem = self.generate_keys()
                
                # Save private key separately
                private_key_filename = f"{os.path.splitext(output_path)[0]}_private_key.pem"
                with open(private_key_filename, 'wb') as f:
                    f.write(private_key_pem)
                print(f"{Fore.RED}🔐 Private key saved separately: {private_key_filename}{Style.RESET_ALL}")
                print(f"{Fore.RED}⚠️  IMPORTANT: Keep this private key file safe!{Style.RESET_ALL}")
                
                private_key_pem = None  # Don't embed in video
            else:
                # Default embedded mode
                private_key_pem, public_key_pem = self.generate_keys()
            
            # Encrypt message
            print(f"{Fore.YELLOW}🔐 Encrypting message...{Style.RESET_ALL}")
            encrypted_message = self.encrypt_message(message, public_key_pem)
            
            # Prepare whisper data
            whisper_data = {
                'version': VERSION,
                'timestamp': datetime.now().isoformat(),
                'security_mode': security_mode,
                'encrypted_message': base64.b64encode(encrypted_message).decode('utf-8'),
                'checksum': hashlib.sha256(message.encode()).hexdigest(),
                'original_size': len(message)
            }
            
            # Only embed private key in embedded mode
            if security_mode == "embedded" and private_key_pem:
                whisper_data['private_key'] = private_key_pem.decode('utf-8')
            else:
                whisper_data['private_key'] = None
                whisper_data['requires_external_key'] = True
            
            # Convert to JSON
            json_data = json.dumps(whisper_data, indent=2).encode('utf-8')
            
            # Read original video
            print(f"{Fore.YELLOW}📖 Reading video data...{Style.RESET_ALL}")
            with open(video_path, 'rb') as f:
                video_data = f.read()
            
            # Create whispered video
            whispered_data = video_data + WHISPER_MARKER + json_data + WHISPER_END
            
            # Write whispered video
            print(f"{Fore.YELLOW}✍️  Writing whispered video...{Style.RESET_ALL}")
            with open(output_path, 'wb') as f:
                f.write(whispered_data)
            
            # Save public key to file
            public_key_filename = f"{os.path.splitext(output_path)[0]}_public_key.pem"
            with open(public_key_filename, 'wb') as f:
                f.write(public_key_pem)
            
            print(f"{Fore.GREEN}✓ Video whisper completed successfully!{Style.RESET_ALL}")
            
            # Return results
            result = {
                'status': 'success',
                'output_file': output_path,
                'public_key_file': public_key_filename,
                'public_key': public_key_pem.decode('utf-8'),
                'security_mode': security_mode,
                'message_length': len(message),
                'whisper_size': len(json_data),
                'file_size_increase': len(whispered_data) - len(video_data)
            }
            
            if security_mode == "external" and not public_key_path:
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
            
            # Find whisper markers
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
            
            # Check security mode
            security_mode = whisper_data.get('security_mode', 'embedded')
            requires_external_key = whisper_data.get('requires_external_key', False)
            
            print(f"{Fore.CYAN}🔒 Security Mode: {security_mode.upper()}{Style.RESET_ALL}")
            
            # Extract components
            encrypted_message = base64.b64decode(whisper_data['encrypted_message'])
            checksum = whisper_data['checksum']
            timestamp = whisper_data.get('timestamp', 'Unknown')
            
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
            
            # Decrypt message
            print(f"{Fore.YELLOW}🔓 Decrypting message...{Style.RESET_ALL}")
            decrypted_message = self.decrypt_message(encrypted_message, private_key_pem)
            
            # Verify checksum
            calculated_checksum = hashlib.sha256(decrypted_message.encode()).hexdigest()
            if calculated_checksum != checksum:
                raise ValueError("Message integrity check failed - whisper may be corrupted")
            
            print(f"{Fore.GREEN}✓ Whisper extracted successfully!{Style.RESET_ALL}")
            
            return {
                'status': 'success',
                'message': decrypted_message,
                'timestamp': timestamp,
                'security_mode': security_mode,
                'checksum_verified': True,
                'version': whisper_data.get('version', 'Unknown'),
                'requires_external_key': requires_external_key
            }
            
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

# CLI Interface
@click.group()
def cli():
    """VideoWhisper - Hide encrypted messages in video files with enhanced security"""
    pass

@cli.command()
@click.option('--video', '-v', required=True, help='Input video file path')
@click.option('--message', '-m', required=True, help='Secret message to whisper')
@click.option('--output', '-o', help='Output video file path (default: input_whispered.ext)')
@click.option('--security-mode', '-s', 
              type=click.Choice(['embedded', 'external']), 
              default='embedded',
              help='Security mode: embedded (default) or external')
@click.option('--public-key', '-k', help='Path to public key file (for external mode)')
def whisper(video, message, output, security_mode, public_key):
    """Whisper a secret message into a video"""
    if not output:
        base, ext = os.path.splitext(video)
        output = f"{base}_whispered{ext}"
    
    vw = VideoWhisper()
    result = vw.whisper_to_video(video, message, output, security_mode, public_key)
    
    if result['status'] == 'success':
        print(f"\n{Fore.GREEN}📁 Output files:{Style.RESET_ALL}")
        print(f"  - Whispered video: {result['output_file']}")
        print(f"  - Public key: {result['public_key_file']}")
        if 'private_key_file' in result:
            print(f"  - Private key: {result['private_key_file']}")
        
        print(f"\n{Fore.YELLOW}📊 Statistics:{Style.RESET_ALL}")
        print(f"  - Security mode: {result['security_mode']}")
        print(f"  - Message length: {result['message_length']} characters")
        print(f"  - Whisper data size: {result['whisper_size']:,} bytes")
        print(f"  - File size increase: {result['file_size_increase']:,} bytes")
        
        if security_mode == "external":
            print(f"\n{Fore.RED}⚠️  SECURITY NOTICE:{Style.RESET_ALL}")
            print(f"  - Private key is NOT embedded in video")
            print(f"  - Keep private key file safe for decryption")
        
        print(f"\n{Fore.CYAN}💡 Share the public key file to allow others to create whispers!{Style.RESET_ALL}")
    else:
        print(f"\n{Fore.RED}✗ Error: {result['error']}{Style.RESET_ALL}")

@cli.command()
@click.option('--video', '-v', required=True, help='Video file with whispered message')
@click.option('--private-key', '-k', help='Path to private key file (for external mode)')
@click.option('--no-prompt', is_flag=True, help='Disable interactive prompts')
def listen(video, private_key, no_prompt):
    """Listen to whispers hidden in a video"""
    vw = VideoWhisper()
    result = vw.listen_to_video(video, private_key, not no_prompt)
    
    if result['status'] == 'success':
        print(f"\n{Fore.GREEN}📋 Whisper Details:{Style.RESET_ALL}")
        print(f"  - Version: {result['version']}")
        print(f"  - Security Mode: {result['security_mode']}")
        print(f"  - Timestamp: {result['timestamp']}")
        print(f"  - External Key Required: {'Yes' if result.get('requires_external_key') else 'No'}")
        print(f"  - Checksum: {'✓ Verified' if result['checksum_verified'] else '✗ Failed'}")
        print(f"\n{Fore.CYAN}💬 SECRET MESSAGE:{Style.RESET_ALL}")
        print(f"{Fore.WHITE}{result['message']}{Style.RESET_ALL}")
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
    """Run a comprehensive test with both security modes"""
    print(f"{Fore.CYAN}🧪 Running VideoWhisper comprehensive test...{Style.RESET_ALL}")
    
    # Create a small test video file
    test_video = "test_video.bin"
    test_message = "This is a secret test message! 🤫"
    
    try:
        # Create dummy video
        with open(test_video, 'wb') as f:
            f.write(b"DUMMY_VIDEO_DATA" * 100)
        
        vw = VideoWhisper()
        
        # Test 1: Embedded mode
        print(f"\n{Fore.YELLOW}Test 1: Embedded Security Mode{Style.RESET_ALL}")
        output_embedded = "test_embedded.bin"
        result1 = vw.whisper_to_video(test_video, test_message, output_embedded, "embedded")
        
        if result1['status'] == 'success':
            print(f"{Fore.GREEN}✓ Embedded whisper test passed!{Style.RESET_ALL}")
            
            # Test extraction (embedded)
            listen_result1 = vw.listen_to_video(output_embedded, auto_prompt=False)
            if listen_result1['status'] == 'success' and listen_result1['message'] == test_message:
                print(f"{Fore.GREEN}✓ Embedded listen test passed!{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}✗ Embedded listen test failed!{Style.RESET_ALL}")
        
        # Test 2: External mode
        print(f"\n{Fore.YELLOW}Test 2: External Security Mode{Style.RESET_ALL}")
        output_external = "test_external.bin"
        result2 = vw.whisper_to_video(test_video, test_message, output_external, "external")
        
        if result2['status'] == 'success':
            print(f"{Fore.GREEN}✓ External whisper test passed!{Style.RESET_ALL}")
            
            # Test extraction (external) with private key
            private_key_file = result2.get('private_key_file')
            if private_key_file:
                listen_result2 = vw.listen_to_video(output_external, private_key_file, auto_prompt=False)
                if listen_result2['status'] == 'success' and listen_result2['message'] == test_message:
                    print(f"{Fore.GREEN}✓ External listen test passed!{Style.RESET_ALL}")
                else:
                    print(f"{Fore.RED}✗ External listen test failed!{Style.RESET_ALL}")
        
        # Cleanup
        cleanup_files = [
            test_video, output_embedded, output_external,
            "test_embedded_public_key.pem", "test_external_public_key.pem",
            "test_external_private_key.pem"
        ]
        
        for f in cleanup_files:
            if os.path.exists(f):
                os.remove(f)
        
        print(f"\n{Fore.GREEN}✓ All tests completed!{Style.RESET_ALL}")
                
    except Exception as e:
        print(f"{Fore.RED}✗ Test failed: {str(e)}{Style.RESET_ALL}")

if __name__ == '__main__':
    cli()