"""Assignment run: encrypt and decrypt a message with Kyber768 + AES-256-GCM.

    python encrypt_message.py                      # encrypt, decrypt, save evidence
    python encrypt_message.py --brief              # same, keys shortened on screen
    python encrypt_message.py --verify FILE.json   # decrypt a saved result again
"""
import argparse
import base64
import datetime
import json
import platform
import sys
import textwrap

from pqc import hybrid, kyber

MESSAGE = "Dear All Good luck with your Job interview with Bloomberg"
ORIGINAL_WORDING = "Dear All Good luck with your Job interview with Blommberg"
KYBER_SOURCE = "github.com/pq-crystals/kyber @ 3edd5af5991927164edd4aacebfcbee00b8064e7 (ref/)"

TXT_PATH = "evidence/assignment_output.txt"
JSON_PATH = "evidence/assignment_output.json"


def wrap(hex_string, width=64):
    return "\n".join("    " + line for line in textwrap.wrap(hex_string, width))


def run(brief=False):
    lines = []    # full report, saved to TXT_PATH
    screen = []   # what is printed; long keys shortened with --brief

    def out(text):
        lines.append(text)
        screen.append(text)

    def out_hex(hex_string):
        lines.append(wrap(hex_string))
        screen.append(f"    {hex_string[:48]}... ({len(hex_string) // 2} bytes, full value in {TXT_PATH})"
                      if brief else wrap(hex_string))

    out("=" * 72)
    out("POST-QUANTUM ENCRYPTION - Kyber768 (ML-KEM-768) + AES-256-GCM")
    out("=" * 72)
    out(f"Date (UTC):   {datetime.datetime.now(datetime.timezone.utc):%Y-%m-%d %H:%M:%S}")
    out(f"Machine:      {platform.system()} {platform.release()} ({platform.machine()})")
    out(f"Python:       {platform.python_version()}")
    out(f"PQC software: {KYBER_SOURCE}")
    out("")
    out("Kyber is a key encapsulation mechanism: it lets two parties agree on a")
    out("secret key that is safe against quantum computers. That 32-byte key is")
    out("then used with AES-256-GCM to encrypt the message itself.")
    out("")
    out("MESSAGE (plaintext)")
    out(f"    {MESSAGE}")
    out(f'    (assignment text had "Blommberg"; spelling corrected to "Bloomberg")')
    out("")

    # Receiver: generate a Kyber key pair.
    public_key, secret_key = kyber.keypair()
    out("STEP 1 - Receiver generates a Kyber768 key pair")
    out(f"    public key: {len(public_key)} bytes, secret key: {len(secret_key)} bytes")
    out("    public key (hex):")
    out_hex(public_key.hex())
    out("")

    # Sender: encapsulate a shared secret and encrypt the message with it.
    sent = hybrid.encrypt(public_key, MESSAGE.encode())
    out("STEP 2 - Sender encapsulates a shared secret with the public key")
    out(f"    Kyber ciphertext: {len(sent['kem_ciphertext'])} bytes (hex):")
    out_hex(sent["kem_ciphertext"].hex())
    out(f"    sender's shared secret: {sent['shared_secret'].hex()}")
    out("")
    out("STEP 3 - Sender encrypts the message with AES-256-GCM (key = shared secret)")
    out(f"    nonce:              {sent['nonce'].hex()}")
    out(f"    CIPHERTEXT (hex):   {len(sent['ciphertext'])} bytes (message + 16-byte tag)")
    out(wrap(sent["ciphertext"].hex()))
    out(f"    CIPHERTEXT (base64):")
    out(wrap(base64.b64encode(sent["ciphertext"]).decode()))
    out("")

    # Receiver: decapsulate and decrypt.
    plaintext, receiver_secret = hybrid.decrypt(
        secret_key, sent["kem_ciphertext"], sent["nonce"], sent["ciphertext"])
    decrypted = plaintext.decode()
    out("STEP 4 - Receiver decapsulates with the secret key and decrypts")
    out(f"    receiver's shared secret: {receiver_secret.hex()}")
    out(f"    DECRYPTED TEXT:           {decrypted}")
    out("")

    # Tamper check: a single flipped bit must make decryption fail.
    tampered = bytearray(sent["ciphertext"])
    tampered[0] ^= 0x01
    try:
        hybrid.decrypt(secret_key, sent["kem_ciphertext"], sent["nonce"], bytes(tampered))
        tamper_rejected = False
    except Exception:
        tamper_rejected = True

    secrets_match = receiver_secret == sent["shared_secret"]
    text_matches = decrypted == MESSAGE
    out("CHECKS")
    out(f"    shared secrets match:            {'YES' if secrets_match else 'NO'}")
    out(f"    decrypted text == original:      {'YES' if text_matches else 'NO'}")
    out(f"    tampered ciphertext rejected:    {'YES' if tamper_rejected else 'NO'}")
    out("=" * 72)

    print("\n".join(screen))
    with open(TXT_PATH, "w") as f:
        f.write("\n".join(lines) + "\n")

    # Everything needed to decrypt again later (this is a demo key pair).
    with open(JSON_PATH, "w") as f:
        json.dump({
            "algorithm": "Kyber768 (ML-KEM-768) + AES-256-GCM",
            "pqc_software": KYBER_SOURCE,
            "message": MESSAGE,
            "original_assignment_wording": ORIGINAL_WORDING,
            "public_key_hex": public_key.hex(),
            "secret_key_hex": secret_key.hex(),
            "kyber_ciphertext_hex": sent["kem_ciphertext"].hex(),
            "nonce_hex": sent["nonce"].hex(),
            "ciphertext_hex": sent["ciphertext"].hex(),
            "ciphertext_base64": base64.b64encode(sent["ciphertext"]).decode(),
            "decrypted_text": decrypted,
        }, f, indent=2)
    print(f"\nSaved {TXT_PATH} and {JSON_PATH}")

    return 0 if (secrets_match and text_matches and tamper_rejected) else 1


def verify(path):
    with open(path) as f:
        saved = json.load(f)
    plaintext, _ = hybrid.decrypt(
        bytes.fromhex(saved["secret_key_hex"]),
        bytes.fromhex(saved["kyber_ciphertext_hex"]),
        bytes.fromhex(saved["nonce_hex"]),
        bytes.fromhex(saved["ciphertext_hex"]),
    )
    print(f"Decrypted from {path}: {plaintext.decode()}")
    return 0 if plaintext.decode() == saved["message"] else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--brief", action="store_true",
                        help="shorten the public key and Kyber ciphertext on screen")
    parser.add_argument("--verify", metavar="FILE.json",
                        help="decrypt a previously saved result")
    args = parser.parse_args()
    sys.exit(verify(args.verify) if args.verify else run(args.brief))
