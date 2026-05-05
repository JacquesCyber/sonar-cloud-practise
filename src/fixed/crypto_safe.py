"""
Secure Cryptography Implementations
=====================================
These are the corrected versions of the vulnerable examples in insecure_crypto.py.

Core Principles of Correct Cryptographic Usage:
------------------------------------------------
1. Use established libraries — don't implement your own crypto algorithms
2. Use current algorithms:
   - Symmetric encryption: AES-256-GCM or AES-256-CBC with random IV
   - Asymmetric encryption: RSA-4096, ECC (P-256/P-384/Ed25519)
   - Password hashing: bcrypt, Argon2id, scrypt (NOT MD5/SHA-1/SHA-256)
   - General hashing: SHA-256 or SHA-3 (for non-password use: data integrity)
   - Random tokens: secrets module (os.urandom)
3. Use authenticated encryption (GCM mode) to detect tampering
4. Never reuse IVs/nonces with the same key
5. Use appropriate key sizes

Algorithm Quick Reference:
---------------------------
| Use Case          | Use This           | Not This                    |
|-------------------|--------------------|-----------------------------|
| Password storage  | bcrypt / Argon2id  | MD5, SHA-1, SHA-256         |
| Symmetric encrypt | AES-256-GCM        | DES, RC4, AES-ECB           |
| Key exchange      | ECDH (P-256/X25519)| RSA < 2048-bit              |
| Digital signature | RSA-4096, Ed25519  | RSA-1024, MD5withRSA        |
| Secure random     | secrets module     | random, random.random()     |
| TLS              | TLS 1.2+, TLS 1.3  | SSL 2/3, TLS 1.0/1.1        |
"""

import os
import hmac
import hashlib
import secrets
import ssl
from typing import Tuple


# =============================================================================
# FIX 1 & 2: Password hashing with bcrypt (strong, slow, salted)
# =============================================================================
# bcrypt is purpose-built for password hashing. Key properties:
# - Built-in salt: Each hash includes a random salt, so identical passwords
#   produce different hashes. Rainbow tables are useless.
# - Work factor: The 'rounds' parameter controls cost. As hardware gets faster,
#   increase the rounds. Common recommendation: 12-14 in 2024.
# - Slow by design: bcrypt computes ~100 hashes/second at rounds=12, versus
#   billions/second for MD5. This makes brute-force attacks computationally infeasible.
#
# Install: pip install bcrypt
import bcrypt

def hash_password_safe(password: str) -> str:
    """
    Safe: bcrypt with cost factor 12.
    - Automatically generates and embeds a random salt
    - Returns the hash string including the algorithm, cost, and salt
    - Safe to store directly in a database

    Returns: String like "$2b$12$salt_embedded_in_hash_string"
    """
    # SAFE: bcrypt handles salting automatically, cost factor 12 is appropriate
    password_bytes = password.encode('utf-8')
    hashed = bcrypt.hashpw(password_bytes, bcrypt.gensalt(rounds=12))
    return hashed.decode('utf-8')


def verify_password_safe(password: str, stored_hash: str) -> bool:
    """
    Safe: Constant-time comparison prevents timing attacks.
    bcrypt.checkpw() uses hmac.compare_digest internally.
    """
    password_bytes = password.encode('utf-8')
    hash_bytes = stored_hash.encode('utf-8')
    # SAFE: bcrypt.checkpw uses constant-time comparison
    return bcrypt.checkpw(password_bytes, hash_bytes)


# =============================================================================
# FIX 3 & 4: AES-256-GCM (Authenticated Encryption)
# =============================================================================
# AES-GCM provides:
# - Confidentiality: AES-256 encryption (unbreakable with current technology)
# - Authenticity: GCM authentication tag detects tampering
# - Integrity: Modification of ciphertext causes decryption failure
#
# This replaces both DES (broken algorithm) and AES-ECB (insecure mode).
#
# Structure of encrypted output:
# [12-byte nonce][16-byte auth tag][ciphertext]
# The nonce can be stored with the ciphertext — it's not secret.

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def encrypt_data_safe(plaintext: bytes, key: bytes) -> bytes:
    """
    Safe: AES-256-GCM with random nonce per encryption.

    Key must be exactly 32 bytes (256 bits).
    Generate a key with: key = secrets.token_bytes(32)
    Store the key securely (secrets manager, environment variable — not in code).
    """
    if len(key) != 32:
        raise ValueError("Key must be exactly 32 bytes for AES-256")

    # SAFE: Random 12-byte nonce — unique per encryption operation
    # Nonce does not need to be secret, just unique for each call with the same key
    nonce = get_random_bytes(12)

    # SAFE: GCM mode provides authenticated encryption
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

    # Optional: add associated data (e.g., user_id, file_id) to authenticate
    # context without encrypting it. Prevents "cut and paste" attacks.
    # cipher.update(b"associated_data")

    ciphertext, tag = cipher.encrypt_and_digest(plaintext)

    # Pack: nonce (12) + tag (16) + ciphertext
    return nonce + tag + ciphertext


def decrypt_data_safe(encrypted_data: bytes, key: bytes) -> bytes:
    """
    Safe: AES-256-GCM decryption with authentication tag verification.
    If the ciphertext has been tampered with, raises ValueError (MAC check failed).
    """
    if len(key) != 32:
        raise ValueError("Key must be exactly 32 bytes for AES-256")
    if len(encrypted_data) < 28:  # 12 (nonce) + 16 (tag) minimum
        raise ValueError("Encrypted data is too short to be valid")

    # Unpack the nonce, tag, and ciphertext
    nonce = encrypted_data[:12]
    tag = encrypted_data[12:28]
    ciphertext = encrypted_data[28:]

    # SAFE: GCM mode verifies the authentication tag — detects tampering
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

    try:
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext
    except ValueError as e:
        # Authentication tag mismatch — data was tampered with or key is wrong
        raise ValueError("Decryption failed: data may have been tampered with") from e


# =============================================================================
# FIX 5: Replace RC4 — use AES-GCM (see above) or ChaCha20-Poly1305
# =============================================================================
# ChaCha20-Poly1305 is an alternative to AES-GCM:
# - Faster than AES on systems without AES hardware acceleration
# - No known timing side-channels
# - Used in TLS 1.3
from Crypto.Cipher import ChaCha20_Poly1305

def encrypt_chacha20_safe(data: bytes, key: bytes) -> bytes:
    """
    Safe: ChaCha20-Poly1305 authenticated encryption.
    Alternative to AES-GCM, particularly good for mobile/embedded systems.
    Key must be exactly 32 bytes.
    """
    if len(key) != 32:
        raise ValueError("Key must be exactly 32 bytes")

    # SAFE: Random 12-byte nonce
    nonce = get_random_bytes(12)
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(data)

    # Pack: nonce + tag + ciphertext
    return nonce + tag + ciphertext


# =============================================================================
# FIX 6: RSA key generation with adequate key size
# =============================================================================
# Use RSA-4096 for new systems, or preferably switch to ECC (smaller keys,
# same security level, faster operations).
#
# ECC alternatives:
#   P-256 (secp256r1): 128-bit security, equivalent to RSA-3072
#   P-384 (secp384r1): 192-bit security
#   Ed25519: Fast, simple API, widely supported for signatures

from Crypto.PublicKey import RSA, ECC

def generate_rsa_keypair_safe() -> Tuple[bytes, bytes]:
    """
    Safe: RSA-4096 keypair.
    Use 4096 bits for long-term security (certificates, signing keys).
    """
    # SAFE: 4096-bit key — adequate for long-term security
    key = RSA.generate(4096)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key


def generate_ecc_keypair_safe() -> Tuple[str, str]:
    """
    Safe: P-256 ECC keypair — preferred over RSA for new systems.
    Provides equivalent security to RSA-3072 with much smaller keys.
    Ed25519 is recommended for signatures (not encryption).
    """
    # SAFE: P-256 is NIST-approved, widely supported, strong security
    key = ECC.generate(curve='P-256')
    private_key = key.export_key(format='PEM')
    public_key = key.public_key().export_key(format='PEM')
    return private_key, public_key


# =============================================================================
# FIX 7: Cryptographically secure random number generation
# =============================================================================
# The secrets module (Python 3.6+) uses os.urandom(), which reads from
# /dev/urandom (Linux/macOS) or BCryptGenRandom (Windows) — CSPRNGs.
# These are seeded from hardware entropy sources.
#
# NEVER use random.random(), random.randint(), or random.choice() for security.

def generate_session_token_safe() -> str:
    """
    Safe: secrets.token_urlsafe generates a URL-safe base64 string
    from os.urandom (CSPRNG). 32 bytes = 256 bits of entropy.
    """
    # SAFE: secrets module uses CSPRNG (os.urandom)
    return secrets.token_urlsafe(32)  # 43 URL-safe characters


def generate_password_reset_token_safe() -> str:
    """
    Safe: Cryptographically random token for password resets.
    Store the hash (SHA-256) of this token in the database, not the token itself.
    Send the raw token to the user's email.
    """
    # SAFE: 32 bytes of CSPRNG output = 256 bits entropy
    raw_token = secrets.token_urlsafe(32)

    # Store only the hash in the database (defense in depth against DB breach)
    # Compare with: hmac.compare_digest(stored_hash, hashlib.sha256(submitted_token.encode()).hexdigest())
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()

    return raw_token, token_hash  # Return raw to send to user, hash to store


def generate_csrf_token_safe() -> str:
    """Safe: CSRF token using CSPRNG."""
    # SAFE: 32 bytes hex = 64 hex characters, 256 bits entropy
    return secrets.token_hex(32)


def generate_api_key_safe() -> str:
    """Safe: Generate a prefixed API key for easy identification."""
    # Using a prefix makes it easy to identify API keys in logs/code
    return 'ak_' + secrets.token_urlsafe(40)


# =============================================================================
# FIX 8: TLS certificate verification — always enabled
# =============================================================================

def fetch_data_safe(url: str) -> bytes:
    """
    Safe: Certificate verification enabled (default behavior).
    Just use the default SSL context — verification is on by default.
    """
    import urllib.request

    # SAFE: Default context has verification enabled
    # Do NOT create a custom context unless you specifically need to add certs
    with urllib.request.urlopen(url) as response:
        return response.read()


def post_data_safe(url: str, data: dict) -> dict:
    """
    Safe: requests library with certificate verification (default).
    Never pass verify=False.
    """
    import requests

    # SAFE: verify=True is the default — certificates are verified
    # In corporate environments with custom CAs, pass the CA bundle path:
    # response = requests.post(url, json=data, verify='/path/to/ca-bundle.pem')
    response = requests.post(url, json=data)  # verify=True by default
    response.raise_for_status()
    return response.json()


# =============================================================================
# FIX 9: AES-CBC with random IV (when GCM is not available)
# =============================================================================
# If you must use CBC mode (e.g., for compatibility with a legacy system),
# always generate a random IV for each encryption.
# Note: CBC does NOT provide authentication — you must add an HMAC separately.
# Prefer AES-GCM which provides both encryption and authentication.

def encrypt_aes_cbc_safe(plaintext: bytes, key: bytes) -> bytes:
    """
    Safe (acceptable): AES-256-CBC with random IV.
    Add HMAC-SHA256 for authentication (encrypt-then-MAC pattern).
    Prefer AES-GCM which handles authentication automatically.
    """
    if len(key) != 32:
        raise ValueError("Key must be 32 bytes for AES-256")

    # SAFE: Random IV generated freshly for each encryption
    iv = get_random_bytes(16)  # AES block size is always 16 bytes

    from Crypto.Util.Padding import pad
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))

    # Prepend IV to ciphertext (IV is not secret, just needs to be stored)
    encrypted = iv + ciphertext

    # Add authentication: HMAC-SHA256 over IV + ciphertext
    # Use a separate MAC key (not the same as the encryption key)
    mac_key = hashlib.sha256(b'mac:' + key).digest()
    mac = hmac.new(mac_key, encrypted, hashlib.sha256).digest()

    return encrypted + mac  # IV + ciphertext + MAC


def decrypt_aes_cbc_safe(encrypted_data: bytes, key: bytes) -> bytes:
    """Safe: AES-256-CBC decryption with HMAC verification."""
    if len(encrypted_data) < 64:  # 16 (IV) + 16 (min ciphertext) + 32 (MAC)
        raise ValueError("Encrypted data too short")

    # Split: MAC is the last 32 bytes
    mac_received = encrypted_data[-32:]
    iv_and_ciphertext = encrypted_data[:-32]

    # Verify MAC first (prevents padding oracle attacks)
    mac_key = hashlib.sha256(b'mac:' + key).digest()
    mac_expected = hmac.new(mac_key, iv_and_ciphertext, hashlib.sha256).digest()

    # Constant-time comparison prevents timing attacks on the MAC check
    if not hmac.compare_digest(mac_received, mac_expected):
        raise ValueError("Decryption failed: authentication tag mismatch")

    # Decrypt
    iv = iv_and_ciphertext[:16]
    ciphertext = iv_and_ciphertext[16:]

    from Crypto.Util.Padding import unpad
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext
