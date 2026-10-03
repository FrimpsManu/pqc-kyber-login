import base64
import json
import os

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from pqc import hybrid, kyber

MESSAGE = "Dear All Good luck with your Job interview with Bloomberg"


# --- Kyber (official C reference code) --------------------------------------

def test_key_and_ciphertext_sizes():
    pk, sk = kyber.keypair()
    ct, ss = kyber.encapsulate(pk)
    assert (len(pk), len(sk), len(ct), len(ss)) == (1184, 2400, 1088, 32)


def test_shared_secret_round_trip():
    for _ in range(20):
        pk, sk = kyber.keypair()
        ct, ss = kyber.encapsulate(pk)
        assert kyber.decapsulate(ct, sk) == ss


def test_wrong_secret_key_gives_different_secret():
    pk, _ = kyber.keypair()
    _, other_sk = kyber.keypair()
    ct, ss = kyber.encapsulate(pk)
    assert kyber.decapsulate(ct, other_sk) != ss


def test_tampered_kyber_ciphertext_gives_different_secret():
    pk, sk = kyber.keypair()
    ct, ss = kyber.encapsulate(pk)
    bad = bytearray(ct)
    bad[100] ^= 0x01
    assert kyber.decapsulate(bytes(bad), sk) != ss


def test_rejects_wrong_lengths():
    with pytest.raises(ValueError):
        kyber.encapsulate(b"short")


# --- Hybrid encryption of the assignment message ----------------------------

def test_assignment_message_round_trip():
    pk, sk = kyber.keypair()
    sent = hybrid.encrypt(pk, MESSAGE.encode())
    assert MESSAGE.encode() not in sent["ciphertext"]
    plaintext, _ = hybrid.decrypt(sk, sent["kem_ciphertext"], sent["nonce"], sent["ciphertext"])
    assert plaintext.decode() == MESSAGE


def test_tampered_message_is_rejected():
    pk, sk = kyber.keypair()
    sent = hybrid.encrypt(pk, MESSAGE.encode())
    bad = bytearray(sent["ciphertext"])
    bad[0] ^= 0x01
    with pytest.raises(Exception):
        hybrid.decrypt(sk, sent["kem_ciphertext"], sent["nonce"], bytes(bad))


# --- Website login protocol -------------------------------------------------

@pytest.fixture
def client(tmp_path):
    os.environ["DATABASE_PATH"] = str(tmp_path / "users.db")
    import app as webapp
    webapp.app.config.update(TESTING=True, DATABASE=str(tmp_path / "users.db"))
    with webapp.app.test_client() as c:
        yield c


def secure_post(client, purpose, username, password, tamper=False):
    """Do what static/js/auth.js does in the browser, using the C Kyber code."""
    hs = client.post("/api/handshake").get_json()
    kem_ct, ss = kyber.encapsulate(base64.b64decode(hs["public_key"]))
    nonce = os.urandom(12)
    payload = json.dumps({"username": username, "password": password}).encode()
    ct = AESGCM(ss).encrypt(nonce, payload, f"{purpose}:{hs['kid']}".encode())
    if tamper:
        ct = bytes([ct[0] ^ 1]) + ct[1:]
    body = {"kid": hs["kid"], "kem_ciphertext": base64.b64encode(kem_ct).decode(),
            "nonce": base64.b64encode(nonce).decode(),
            "ciphertext": base64.b64encode(ct).decode()}
    return client.post(f"/api/{purpose}", json=body), body


def test_signup_then_login(client):
    res, _ = secure_post(client, "signup", "alice", "correct horse")
    assert res.status_code == 200
    client.get("/logout")
    res, _ = secure_post(client, "login", "alice", "correct horse")
    assert res.status_code == 200
    page = client.get("/dashboard").get_data(as_text=True)
    assert "Welcome, alice" in page and "How your login was protected" in page


def test_wrong_password(client):
    secure_post(client, "signup", "bob", "password123")
    client.get("/logout")
    res, _ = secure_post(client, "login", "bob", "nope-nope")
    assert res.status_code == 401


def test_password_never_sent_in_clear(client):
    _, body = secure_post(client, "signup", "carol", "SuperSecret-42")
    assert "SuperSecret-42" not in json.dumps(body)


def test_tampered_login_rejected(client):
    secure_post(client, "signup", "dave", "password123")
    client.get("/logout")
    res, _ = secure_post(client, "login", "dave", "password123", tamper=True)
    assert res.status_code == 400


def test_handshake_key_is_single_use(client):
    secure_post(client, "signup", "erin", "password123")
    client.get("/logout")
    res, body = secure_post(client, "login", "erin", "password123")
    assert res.status_code == 200
    client.get("/logout")
    replay = client.post("/api/login", json=body)
    assert replay.status_code == 400


def test_dashboard_requires_login(client):
    assert client.get("/dashboard").status_code == 302


def test_dashboard_encrypts_message(client):
    secure_post(client, "signup", "frank", "password123")
    page = client.post("/dashboard", data={"message": MESSAGE}).get_data(as_text=True)
    assert "Decrypted text" in page and MESSAGE in page
    assert "Shared secrets match</th><td>Yes" in page
