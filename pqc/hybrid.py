"""Hybrid encryption: Kyber768 agrees on a key, AES-256-GCM encrypts the data.

Kyber is a key encapsulation mechanism (KEM). It does not encrypt a message
directly; it lets a sender and receiver share a fresh 32-byte secret. That
secret is used as the AES-256-GCM key for the actual message.
"""
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import kyber

NONCE_BYTES = 12


def encrypt(public_key, plaintext: bytes):
    """Sender side. Returns everything the receiver needs, plus the key used."""
    kem_ciphertext, shared_secret = kyber.encapsulate(public_key)
    nonce = os.urandom(NONCE_BYTES)
    ciphertext = AESGCM(shared_secret).encrypt(nonce, plaintext, None)
    return {
        "kem_ciphertext": kem_ciphertext,
        "nonce": nonce,
        "ciphertext": ciphertext,
        "shared_secret": shared_secret,
    }


def decrypt(secret_key, kem_ciphertext, nonce, ciphertext):
    """Receiver side. Returns (plaintext, shared_secret)."""
    shared_secret = kyber.decapsulate(kem_ciphertext, secret_key)
    plaintext = AESGCM(shared_secret).decrypt(nonce, ciphertext, None)
    return plaintext, shared_secret
