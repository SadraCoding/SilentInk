"""
Silent Ink - Hide encrypted ZIP files inside PNG images using steganography
Repo: https://github.com/SadraCoding/SilentInk
Made by SadraCoding
"""

import os
import sys
import getpass
import time
from pathlib import Path
from typing import Optional
from PIL import Image
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ────────────────────────────────────────────────
# Constants
# ────────────────────────────────────────────────
APP_NAME = "Silent Ink"
VERSION = "v1.0"

MAGIC_HEADER = b'SILENTINK\x00'   # Unique app signature
KDF_ITERATIONS = 800_000
SALT_SIZE = 16                    # 128-bit random salt
NONCE_SIZE = 12                   # AES-GCM standard

# ────────────────────────────────────────────────
# Helper Animations
# ────────────────────────────────────────────────
def typewrite(text: str, delay: float = 0.02):
    """Print text like a typewriter animation."""
    for char in text:
        print(char, end='', flush=True)
        time.sleep(delay)
    print()

def loading_dots(message: str, seconds: float = 1.5, interval: float = 0.3):
    """Show a loading animation with dots."""
    print(message, end='', flush=True)
    end_time = time.time() + seconds
    while time.time() < end_time:
        for dot in '.  ..  ...  ':
            print(f'\r{message}{dot}', end='', flush=True)
            time.sleep(interval)
    print(f'\r{message} ✓')

# ────────────────────────────────────────────────
# Crypto Functions
# ────────────────────────────────────────────────
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA512(),
        length=32,
        salt=salt,
        iterations=KDF_ITERATIONS
    )
    return kdf.derive(password.encode())

def encrypt_payload(data: bytes, password: str) -> bytes:
    salt = os.urandom(SALT_SIZE)
    key = derive_key(password, salt)

    aesgcm = AESGCM(key)
    nonce = os.urandom(NONCE_SIZE)
    ciphertext = aesgcm.encrypt(nonce, data, None)

    return MAGIC_HEADER + salt + nonce + ciphertext

def decrypt_payload(encrypted: bytes, password: str) -> bytes:
    if not encrypted.startswith(MAGIC_HEADER):
        raise ValueError("Invalid Silent Ink payload")

    offset = len(MAGIC_HEADER)

    salt = encrypted[offset:offset + SALT_SIZE]
    offset += SALT_SIZE

    nonce = encrypted[offset:offset + NONCE_SIZE]
    offset += NONCE_SIZE

    ciphertext = encrypted[offset:]

    key = derive_key(password, salt)
    aesgcm = AESGCM(key)

    try:
        return aesgcm.decrypt(nonce, ciphertext, None)
    except Exception:
        raise ValueError("Decryption failed: wrong password or corrupted data")

# ────────────────────────────────────────────────
# Steganography Functions
# ────────────────────────────────────────────────
def calculate_required_pixels(payload: bytes) -> int:
    full = MAGIC_HEADER + len(payload).to_bytes(8, 'big') + payload
    return (len(full) * 8 + 2) // 3 + 1

def hide_data_in_image(carrier_path: str, payload: bytes, output_path: str) -> None:
    img = Image.open(carrier_path).convert('RGB')
    pixels = img.load()
    w, h = img.size

    required = calculate_required_pixels(payload)
    if required > w * h:
        raise ValueError(f"Image too small! Need {required} pixels but only {w * h} available.")

    full_payload = MAGIC_HEADER + len(payload).to_bytes(8, 'big') + payload
    bits = ''.join(f'{byte:08b}' for byte in full_payload)
    bit_idx = 0

    typewrite(f"  [•] Embedding {len(payload):,} bytes into image ({w}x{h})...")
    for y in range(h):
        for x in range(w):
            if bit_idx >= len(bits): break
            r, g, b = pixels[x, y]
            r = (r & ~1) | int(bits[bit_idx]); bit_idx += 1
            if bit_idx < len(bits): g = (g & ~1) | int(bits[bit_idx]); bit_idx += 1
            if bit_idx < len(bits): b = (b & ~1) | int(bits[bit_idx]); bit_idx += 1
            pixels[x, y] = (r, g, b)
        if bit_idx >= len(bits): break

    img.save(output_path, 'PNG', optimize=True)
    typewrite(f"  [✓] Saved stego image: {output_path}")

def extract_data_from_image(stego_path: str) -> bytes:
    img = Image.open(stego_path).convert('RGB')
    pixels = img.load()
    byte_buffer = bytearray()
    bit_buffer = bit_count = 0
    payload_length: Optional[int] = None

    typewrite(f"  [•] Scanning image for hidden data ({img.width}x{img.height})...")
    for y in range(img.height):
        for x in range(img.width):
            for val in pixels[x, y]:
                bit_buffer = (bit_buffer << 1) | (val & 1)
                bit_count += 1
                if bit_count == 8:
                    byte_buffer.append(bit_buffer)
                    bit_buffer = bit_count = 0
                    if len(byte_buffer) >= len(MAGIC_HEADER) + 8 and payload_length is None:
                        if byte_buffer[:len(MAGIC_HEADER)] == MAGIC_HEADER:
                            payload_length = int.from_bytes(
                                byte_buffer[len(MAGIC_HEADER):len(MAGIC_HEADER)+8], 'big'
                            )
                            typewrite(f"  [•] Found payload header ({payload_length} bytes)")
                    if payload_length is not None:
                        header_size = len(MAGIC_HEADER) + 8
                        if len(byte_buffer) >= header_size + payload_length:
                            return bytes(byte_buffer[header_size:header_size + payload_length])
    raise ValueError("No valid hidden data found in image")

# ────────────────────────────────────────────────
# CLI Helpers
# ────────────────────────────────────────────────
def print_banner() -> None:
    banner = f"""
  /$$$$$$  /$$$$$$ /$$       /$$$$$$$$ /$$   /$$ /$$$$$$$$       /$$$$$$ /$$   /$$ /$$   /$$    {VERSION} 
 /$$__  $$|_  $$_/| $$      | $$_____/| $$$ | $$|__  $$__/      |_  $$_/| $$$ | $$| $$  /$$/
| $$  \__/  | $$  | $$      | $$      | $$$$| $$   | $$           | $$  | $$$$| $$| $$ /$$/ 
|  $$$$$$   | $$  | $$      | $$$$$   | $$ $$ $$   | $$           | $$  | $$ $$ $$| $$$$$/  
 \____  $$  | $$  | $$      | $$__/   | $$  $$$$   | $$           | $$  | $$  $$$$| $$  $$  
 /$$  \ $$  | $$  | $$      | $$      | $$\  $$$   | $$           | $$  | $$\  $$$| $$\  $$ 
|  $$$$$$/ /$$$$$$| $$$$$$$$| $$$$$$$$| $$ \  $$   | $$          /$$$$$$| $$ \  $$| $$ \  $$
 \______/ |______/|________/|________/|__/  \__/   |__/         |______/|__/  \__/|__/  \__/
             
Hide encrypted ZIP files inside PNG images          
Made by SadraCoding | https://github.com/SadraCoding/SilentInk 

"""
    typewrite(banner, delay=0.001)

def get_valid_path(prompt: str, expected_type: str = "file", extensions: list = None) -> Path:
    while True:
        path = input(prompt).strip().strip('"').strip("'")
        if not path:
            typewrite("  ✗ Path cannot be empty.")
            continue
        p = Path(path)
        if expected_type == "file" and not p.is_file():
            typewrite(f"  ✗ File not found: {p}")
            continue
        elif expected_type == "dir" and not p.is_dir():
            typewrite(f"  ✗ Directory not found: {p}")
            continue
        if extensions and p.suffix.lower() not in extensions:
            typewrite(f"  ✗ Invalid file type. Expected: {', '.join(extensions)}")
            continue
        return p

def prompt_password(confirm: bool = True) -> str:
    while True:
        password = getpass.getpass("  [?] Enter password: ")
        if len(password) < 8:
            typewrite("  ✗ Password too short (min 8 characters).")
            continue
        if confirm:
            password2 = getpass.getpass("  [?] Confirm password: ")
            if password != password2:
                typewrite("  ✗ Passwords don't match.")
                continue
        return password

# ────────────────────────────────────────────────
# Workflows
# ────────────────────────────────────────────────
def hide_workflow() -> None:
    typewrite("\n─── Hide ZIP in PNG Image ────────────────────────────────")
    zip_path = get_valid_path("  [?] Path to ZIP file: ", extensions=['.zip'])
    img_path = get_valid_path("  [?] Path to carrier image (PNG/JPG): ", extensions=['.png', '.jpg', '.jpeg'])
    password = prompt_password()

    with open(zip_path, 'rb') as f:
        zip_data = f.read()
    loading_dots(f"  [•] Encrypting {len(zip_data):,} bytes...")
    encrypted = encrypt_payload(zip_data, password)

    default_output = img_path.with_name(f"{img_path.stem}_stego.png")
    output_path = input(f"  [?] Output path [default: {default_output}]: ").strip() or default_output
    output_path = Path(output_path).with_suffix('.png')

    try:
        hide_data_in_image(str(img_path), encrypted, str(output_path))
        typewrite(f"\n✓ Stego image created successfully!\n  Original: {img_path.stat().st_size:,} bytes\n  Stego: {output_path.stat().st_size:,} bytes")
    except Exception as e:
        typewrite(f"\n✗ Failed: {e}")

def extract_workflow() -> None:
    typewrite("\n─── Extract ZIP from Stego Image ──────────────────────────")
    stego_path = get_valid_path("  [?] Path to stego PNG: ", extensions=['.png'])
    password = prompt_password(confirm=False)

    try:
        encrypted_data = extract_data_from_image(str(stego_path))
        loading_dots(f"  [•] Decrypting payload ({len(encrypted_data):,} bytes)...")
        zip_data = decrypt_payload(encrypted_data, password)
    except Exception as e:
        typewrite(f"\n✗ Failed: {e}")
        return

    default_output = stego_path.with_name(f"{stego_path.stem}_extracted.zip")
    output_path = input(f"  [?] Output path [default: {default_output}]: ").strip() or default_output
    output_path = Path(output_path).with_suffix('.zip')

    with open(output_path, 'wb') as f:
        f.write(zip_data)
    typewrite(f"\n✓ ZIP extracted successfully! Saved to {output_path} ({len(zip_data):,} bytes)")

def capacity_check() -> None:
    typewrite("\n─── Image Capacity Check ──────────────────────────────────")
    img_path = get_valid_path("  [?] Path to PNG/JPG image: ", extensions=['.png', '.jpg', '.jpeg'])
    img = Image.open(img_path).convert('RGB')

    total_pixels = img.width * img.height
    max_bytes = (total_pixels * 3) // 8
    usable_bytes = max_bytes - (len(MAGIC_HEADER) + 8)

    typewrite(f"\nImage: {img.width}x{img.height} ({total_pixels:,} pixels)")
    typewrite(f"Total capacity: {max_bytes:,} bytes")
    typewrite(f"Usable payload: {usable_bytes:,} bytes (after header)")

# ────────────────────────────────────────────────
# Main
# ────────────────────────────────────────────────
def main() -> None:
    print_banner()
    while True:
        choice = input("Main Menu:\n[1] Hide ZIP\n[2] Extract ZIP\n[3] Check capacity\n[0] Exit\n\nSelect [0-3]: ").strip()
        if choice == '1': hide_workflow()
        elif choice == '2': extract_workflow()
        elif choice == '3': capacity_check()
        elif choice == '0':
            typewrite("\nExiting Silent Ink. Secrets stay safe!\n")
            break
        else:
            typewrite("\n✗ Invalid option.")
        input("\nPress Enter to continue...")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        typewrite("\n\nUser interrupted. Silent Ink session terminated gracefully.")
        sys.exit(0)
    except Exception as e:
        typewrite(f"\n✗ Critical error: {e}")
        sys.exit(1)
