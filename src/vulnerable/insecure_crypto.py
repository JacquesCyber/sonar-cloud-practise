"""
Insecure Cryptography Examples
================================
OWASP Category: A02:2021 - Cryptographic Failures
CWE References:
  - CWE-327: Use of a Broken or Risky Cryptographic Algorithm
  - CWE-328: Use of Weak Hash
  - CWE-326: Inadequate Encryption Strength
  - CWE-330: Use of Insufficiently Random Values
  - CWE-916: Use of Password Hash With Insufficient Computational Effort
SonarCloud Rules:
  - python:S5547 - Cipher algorithms should be robust
  - python:S4426 - Cryptographic keys should be robust
  - python:S5542 - Encryption algorithms should be used with secure mode and padding
  - python:S4790 - Using weak hashing algorithms is security-sensitive
  - python:S2245 - Using pseudorandom number generators (PRNGs) is security-sensitive
  - python:S5344 - Passwords should not be stored in plaintext or with a fast hash
Severity in SonarCloud: CRITICAL to MAJOR

Why Weak Cryptography Matters:
-------------------------------
Cryptography is the foundation of data security. Weak crypto means:
- "Encrypted" data can be decrypted by attackers
- Password hashes can be cracked with GPU-accelerated tools in hours/days
- "Signed" data can be forged
- "Random" tokens can be predicted (session fixation, CSRF bypass)

Key Principle: Don't roll your own crypto. Use established libraries correctly.
"""

import hashlib
import hmac
import random
import os
from Crypto.Cipher import DES, ARC4, DES3, AES
from Crypto.PublicKey import RSA
import ssl


# =============================================================================
# VULNERABLE EXAMPLE 1: MD5 for password hashing
# =============================================================================
# MD5 produces a 128-bit hash. Problems:
# - Designed for speed (processes ~10 billion MD5s/second on modern GPUs)
# - No salt by default → identical passwords produce identical hashes
# - Rainbow table databases exist for common passwords
# - Completely broken for collision resistance (CWE-328)
#
# SonarCloud Rule: python:S4790 (weak hashing), python:S5344 (passwords)
#
# Real impact: A database breach exposes all passwords.
# With MD5, attackers crack most passwords in hours using hashcat + wordlists.
def hash_password_md5(password: str) -> str:
    # VULNERABLE: MD5 is cryptographically broken for passwords
    # SonarCloud Rule: python:S4790
    return hashlib.md5(password.encode()).hexdigest()


def verify_password_md5(password: str, stored_hash: str) -> bool:
    # VULNERABLE: Comparing MD5 hashes
    return hashlib.md5(password.encode()).hexdigest() == stored_hash


# =============================================================================
# VULNERABLE EXAMPLE 2: SHA-1 for password hashing
# =============================================================================
# SHA-1 is slightly better than MD5 but still broken for passwords:
# - Collision attacks demonstrated (SHAttered attack, 2017)
# - Still very fast — GPUs can compute billions per second
# - No work factor — can't be tuned to remain slow as hardware improves
# - NIST deprecated SHA-1 for digital signatures in 2011
#
# SonarCloud Rule: python:S4790
def hash_password_sha1(password: str, salt: str = "") -> str:
    # VULNERABLE: SHA-1 is broken for cryptographic use
    # SonarCloud Rule: python:S4790
    return hashlib.sha1((password + salt).encode()).hexdigest()


# =============================================================================
# VULNERABLE EXAMPLE 3: DES encryption
# =============================================================================
# DES (Data Encryption Standard) was deprecated in 2005.
# Key size: 56 bits → brute-forceable in hours with modern hardware.
# The EFF's Deep Crack machine cracked DES in 22 hours in 1998.
# Today it takes seconds with cloud computing.
#
# SonarCloud Rule: python:S5547
def encrypt_data_des(plaintext: bytes, key: bytes) -> bytes:
    # VULNERABLE: DES is considered broken (56-bit key)
    # SonarCloud Rule: python:S5547
    cipher = DES.new(key, DES.MODE_ECB)  # ECB mode also flagged (S5542)
    # Pad to 8-byte boundary
    padded = plaintext + b'\x00' * (8 - len(plaintext) % 8)
    return cipher.encrypt(padded)


# =============================================================================
# VULNERABLE EXAMPLE 4: AES-ECB mode (cipher is strong, mode is weak)
# =============================================================================
# AES is secure, but ECB (Electronic Code Book) mode is NOT.
# ECB encrypts each block independently with the same key.
# Identical plaintext blocks produce identical ciphertext blocks.
# This leaks structural information about the plaintext.
# The famous "ECB penguin" image demonstrates this visually.
#
# SonarCloud Rule: python:S5542 - Insecure block cipher mode
def encrypt_aes_ecb(plaintext: bytes, key: bytes) -> bytes:
    # VULNERABLE: ECB mode leaks data patterns
    # SonarCloud Rule: python:S5542
    cipher = AES.new(key, AES.MODE_ECB)  # MODE_ECB is the problem
    # ECB with a 256-bit key still has the pattern-leaking weakness
    padded = plaintext + b'\x00' * (16 - len(plaintext) % 16)
    return cipher.encrypt(padded)


# =============================================================================
# VULNERABLE EXAMPLE 5: RC4 stream cipher
# =============================================================================
# RC4 was used in WEP WiFi encryption (broken in 2001) and early TLS.
# Multiple biases in the keystream make it statistically predictable.
# RFC 7465 prohibits RC4 in TLS. NIST prohibits it for government use.
#
# SonarCloud Rule: python:S5547
def encrypt_rc4(data: bytes, key: bytes) -> bytes:
    # VULNERABLE: RC4 is cryptographically broken
    # SonarCloud Rule: python:S5547
    cipher = ARC4.new(key)
    return cipher.encrypt(data)


# =============================================================================
# VULNERABLE EXAMPLE 6: Weak RSA key size
# =============================================================================
# RSA security depends on key size. Recommendations:
# - 1024-bit: Broken (factorable with public tools)
# - 2048-bit: Minimum acceptable (NIST recommends through 2030)
# - 3072-bit: Recommended for long-term security
# - 4096-bit: Strong, suitable for certificates
#
# SonarCloud Rule: python:S4426
def generate_rsa_keypair_weak():
    # VULNERABLE: 1024-bit RSA key is too small
    # SonarCloud Rule: python:S4426
    key = RSA.generate(1024)  # 1024 bits is breakable with academic resources
    return key.export_key(), key.publickey().export_key()


def generate_rsa_keypair_borderline():
    # BORDERLINE: 2048-bit is the minimum, but flagged as a security hotspot
    # by some configurations. Use 3072+ for new systems.
    key = RSA.generate(2048)  # SonarCloud may flag this as a hotspot
    return key.export_key(), key.publickey().export_key()


# =============================================================================
# VULNERABLE EXAMPLE 7: Insecure random number generation
# =============================================================================
# Python's random module uses Mersenne Twister — a PRNG, not a CSPRNG.
# It is NOT suitable for security-sensitive use cases:
# - Token generation
# - Session IDs
# - Password reset links
# - Nonces for cryptographic protocols
# - CSRF tokens
#
# The Mersenne Twister state can be recovered after observing 624 outputs.
# An attacker can predict all future "random" values.
#
# SonarCloud Rule: python:S2245
def generate_session_token_weak() -> str:
    # VULNERABLE: random.random() is not cryptographically secure
    # SonarCloud Rule: python:S2245
    token = ''.join([str(random.randint(0, 9)) for _ in range(32)])
    return token


def generate_password_reset_token_weak(user_id: int) -> str:
    # VULNERABLE: Using random with a time-based seed is predictable
    random.seed(user_id)  # Using user_id as seed makes it deterministic
    chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
    return ''.join(random.choice(chars) for _ in range(32))  # python:S2245


def generate_csrf_token_weak() -> str:
    # VULNERABLE: random.getrandbits is still Mersenne Twister
    return hex(random.getrandbits(128))[2:]  # python:S2245


# =============================================================================
# VULNERABLE EXAMPLE 8: Disabled certificate verification
# =============================================================================
# Disabling SSL/TLS certificate verification removes protection against
# man-in-the-middle attacks. An attacker between client and server can
# intercept and modify all "encrypted" traffic.
#
# SonarCloud Rule: python:S4830 - Server certificates should be verified
import urllib.request
import ssl

def fetch_data_insecure(url: str) -> bytes:
    # VULNERABLE: Certificate verification disabled
    # SonarCloud Rule: python:S4830
    ctx = ssl.create_default_context()
    ctx.check_hostname = False   # SonarCloud flags this
    ctx.verify_mode = ssl.CERT_NONE  # SonarCloud flags this — never do this

    with urllib.request.urlopen(url, context=ctx) as response:
        return response.read()


# Also commonly seen with requests library:
import requests as req

def post_data_insecure(url: str, data: dict) -> dict:
    # VULNERABLE: verify=False disables certificate verification
    # SonarCloud Rule: python:S4830
    response = req.post(url, json=data, verify=False)  # Never use verify=False
    return response.json()


# =============================================================================
# VULNERABLE EXAMPLE 9: Hardcoded IV (Initialization Vector)
# =============================================================================
# IVs must be unique and unpredictable for each encryption operation.
# A hardcoded IV means the same key + same IV encrypts the same data
# to the same ciphertext every time → leaks information.
# For CBC mode, a predictable IV enables the BEAST attack.
#
# SonarCloud Rule: python:S3329 - Cipher algorithms should use unpredictable IVs
HARDCODED_IV = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

def encrypt_with_fixed_iv(plaintext: bytes, key: bytes) -> bytes:
    # VULNERABLE: Fixed IV used for every encryption
    # SonarCloud Rule: python:S3329
    cipher = AES.new(key, AES.MODE_CBC, HARDCODED_IV)  # IV should be random
    padded = plaintext + b'\x00' * (16 - len(plaintext) % 16)
    return cipher.encrypt(padded)
