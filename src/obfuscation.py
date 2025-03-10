import os
import random
import time
try:
    from Crypto.Cipher import AES
except ImportError:
    AES = None

class EncryptionObfuscator:
    """Encrypt data at the network layer using AES (simulated IPsec)."""
    def __init__(self, key: bytes = None):
        # Default 16-byte key, assuming secure way to distribute key to all VMs
        if key is None:
            key = b'\x01' * 16
        if len(key) not in (16, 24, 32):
            raise ValueError("Key must be 16, 24, or 32 bytes long for AES.")
        self.key = key

    def encrypt(self, data: bytes) -> bytes:
        """
        Encrypt the given data using AES (EAX mode).
        Returns ciphertext with nonce and tag prepended (for completeness).
        """
        if AES is None:
            raise RuntimeError("PyCrypto (PyCryptodome) is not installed for encryption.")
        cipher = AES.new(self.key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        # Prepend nonce and tag so the data can be decrypted if needed
        return cipher.nonce + tag + ciphertext

class PaddingObfuscator:
    """Obfuscation via randomized padding of packets."""
    def __init__(self, min_pad: int = 0, max_pad: int = 50):
        """
        min_pad: minimum padding bytes to add.
        max_pad: maximum padding bytes to add.
        """
        self.min_pad = min_pad
        self.max_pad = max_pad

    def pad(self, data: bytes) -> bytes:
        """
        Append a random number of padding bytes (between min_pad and max_pad) to the data.
        """
        pad_length = random.randint(self.min_pad, self.max_pad) if self.max_pad > 0 else 0
        if pad_length <= 0:
            return data
        padding = os.urandom(pad_length)  # random padding bytes
        return data + padding

class TrafficShaper:
    """Obfuscation via traffic shaping (introducing delays)."""
    def __init__(self, mode: str = "random", min_delay: float = 0.01,
                 max_delay: float = 0.1, rate_bps: float = None):
        """
        mode: 'random' (random delays) or 'constant' (constant rate shaping).
        min_delay: minimum delay (sec) for random mode, or fixed delay if constant and rate_bps not given.
        max_delay: maximum delay (sec) for random mode.
        rate_bps: target constant bitrate in bits/sec (for constant mode, optional).
        """
        self.mode = mode
        self.min_delay = min_delay
        self.max_delay = max_delay
        self.rate_bps = rate_bps

    def shape(self, packet_size: int = None):
        """
        Introduce delay according to shaping mode. Call before sending each packet.
        - Random mode: sleep for a random time between min_delay and max_delay.
        - Constant mode: if rate_bps is given, sleep to maintain that bitrate; otherwise use min_delay as fixed interval.
        """
        if self.mode == "random":
            time.sleep(random.uniform(self.min_delay, self.max_delay))
        elif self.mode == "constant":
            if self.rate_bps and packet_size:
                delay = (packet_size * 8) / float(self.rate_bps)  # time to send this packet at target rate
                if delay > 0:
                    time.sleep(delay)
            else:
                time.sleep(self.min_delay)
        # If mode is unrecognized or no shaping needed, do nothing
