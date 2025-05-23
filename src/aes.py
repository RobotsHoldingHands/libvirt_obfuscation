from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import sys

def handle_errors():
    """Error handling function similar to the C version"""
    import traceback
    traceback.print_exc()
    exit(1)

def aes_init(keydata: str, keydata_len: int) -> tuple[bytes, bytes]:
    """Initialize 256 bit key and IV for cipher using PBKDF2 instead of EVP_BytesToKey
    since the latter is deprecated. This achieves the same goal of deriving key material
    from a password."""
    salt = b'1234554321'  # Same salt as C version
    
    # Using PBKDF2 with SHA1 (to match the C version's use of EVP_sha1)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA1(),
        length=48,  # 32 bytes for key + 16 bytes for IV
        salt=salt,
        iterations=5,  # Same as C version
        backend=default_backend()
    )
    
    key_iv = kdf.derive(keydata.encode())
    key = key_iv[:32]  # First 32 bytes for key
    iv = key_iv[32:48]  # Next 16 bytes for IV
    
    return key, iv

def encrypt(plaintext: bytes, plaintext_len: int, key: bytes, iv: bytes) -> bytes:
    """Encrypt data using AES-256-CBC"""
    try:
        # Create cipher context
        cipher = Cipher(
            algorithms.AES256(key),
            modes.CBC(iv),
            backend=default_backend()
        )
        
        # Create encryptor
        encryptor = cipher.encryptor()
        
        # Add padding to match block size (16 bytes for AES)
        padded_data = add_pkcs7_padding(plaintext)
        
        # Encrypt the data
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        
        return ciphertext
    except Exception:
        handle_errors()
        return b''

def decrypt(ciphertext: bytes, ciphertext_len: int, key: bytes, iv: bytes) -> bytes:
    """Decrypt data using AES-256-CBC"""
    try:
        # Create cipher context
        cipher = Cipher(
            algorithms.AES256(key),
            modes.CBC(iv),
            backend=default_backend()
        )
        
        # Create decryptor
        decryptor = cipher.decryptor()
        
        # Decrypt the data
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Remove padding
        plaintext = remove_pkcs7_padding(padded_plaintext)
        
        return plaintext
    except Exception:
        handle_errors()
        return b''

def add_pkcs7_padding(data: bytes) -> bytes:
    """Add PKCS7 padding to the data"""
    block_size = 16
    padding_length = block_size - (len(data) % block_size)
    padding = bytes([padding_length] * padding_length)
    return data + padding

def remove_pkcs7_padding(padded_data: bytes) -> bytes:
    """Remove PKCS7 padding from the data"""
    padding_length = padded_data[-1]
    return padded_data[:-padding_length]

def main(packet: bytes) -> str:
    # Initialize parameters
    password = "password"
    plaintext = b"Kunal Baweja"
    
    # Generate key and IV
    key, iv = aes_init(password, len(password))
    
    # Encrypt
    ciphertext = encrypt(plaintext, len(plaintext), key, iv)
    return ciphertext.hex()

if __name__ == "__main__":
    main(sys.argv[1])
