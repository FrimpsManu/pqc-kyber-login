"""Python binding for the official Kyber768 reference implementation.

The C code in kyber/ref (github.com/pq-crystals/kyber) is compiled into
pqc/lib/libkyber768.so by build.sh. This module calls its three API functions:

    keypair()          -> (public_key, secret_key)
    encapsulate(pk)    -> (ciphertext, shared_secret)
    decapsulate(ct, sk) -> shared_secret
"""
import ctypes
import os

PUBLICKEYBYTES = 1184
SECRETKEYBYTES = 2400
CIPHERTEXTBYTES = 1088
SHAREDSECRETBYTES = 32

_LIB_PATH = os.path.join(os.path.dirname(__file__), "lib", "libkyber768.so")

try:
    _lib = ctypes.CDLL(_LIB_PATH)
except OSError as exc:
    raise ImportError(f"{_LIB_PATH} not found - run ./build.sh first") from exc

_buf = ctypes.c_char_p
for _name in ("keypair", "enc", "dec"):
    fn = getattr(_lib, f"pqcrystals_kyber768_ref_{_name}")
    fn.argtypes = [_buf, _buf, _buf][: 2 if _name == "keypair" else 3]
    fn.restype = ctypes.c_int


def keypair():
    pk = ctypes.create_string_buffer(PUBLICKEYBYTES)
    sk = ctypes.create_string_buffer(SECRETKEYBYTES)
    if _lib.pqcrystals_kyber768_ref_keypair(pk, sk) != 0:
        raise RuntimeError("Kyber key generation failed")
    return pk.raw, sk.raw


def encapsulate(public_key):
    if len(public_key) != PUBLICKEYBYTES:
        raise ValueError(f"public key must be {PUBLICKEYBYTES} bytes")
    ct = ctypes.create_string_buffer(CIPHERTEXTBYTES)
    ss = ctypes.create_string_buffer(SHAREDSECRETBYTES)
    if _lib.pqcrystals_kyber768_ref_enc(ct, ss, public_key) != 0:
        raise RuntimeError("Kyber encapsulation failed")
    return ct.raw, ss.raw


def decapsulate(ciphertext, secret_key):
    if len(ciphertext) != CIPHERTEXTBYTES:
        raise ValueError(f"ciphertext must be {CIPHERTEXTBYTES} bytes")
    if len(secret_key) != SECRETKEYBYTES:
        raise ValueError(f"secret key must be {SECRETKEYBYTES} bytes")
    ss = ctypes.create_string_buffer(SHAREDSECRETBYTES)
    if _lib.pqcrystals_kyber768_ref_dec(ss, ciphertext, secret_key) != 0:
        raise RuntimeError("Kyber decapsulation failed")
    return ss.raw
