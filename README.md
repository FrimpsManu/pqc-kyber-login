# PQC Kyber Login

Post-quantum encryption with **Kyber768 (ML-KEM-768)**, built on the official
reference implementation from [pq-crystals/kyber](https://github.com/pq-crystals/kyber).

The project has two parts:

1. **Assignment run** (`encrypt_message.py`). Encrypts and decrypts the message
   *"Dear All Good luck with your Job interview with Bloomberg"* and saves the
   ciphertext, decrypted text and checks.
2. **Website** (`app.py`). A sign-up and login site where the username and
   password are encrypted in the browser with Kyber before they are sent. After
   login, a page encrypts and decrypts the same message.

**Live site:** https://web-production-0c4f4e.up.railway.app

---

## Assignment result

Full output: [`evidence/assignment_output.txt`](evidence/assignment_output.txt).
Machine-readable copy with the keys: [`evidence/assignment_output.json`](evidence/assignment_output.json).

| | |
|---|---|
| **Message** | `Dear All Good luck with your Job interview with Bloomberg` |
| **Algorithm** | Kyber768 (ML-KEM-768) key encapsulation + AES-256-GCM |
| **Ciphertext (hex, 73 bytes)** | `52dd096948c9860b6a80c6a347deb6e4e611c3a86122fdf5a3c85f944fae647fc07cbf89ff1a838ce65764ac2a15bfce2bbd97718057b36f708d1a9c892026e4dd9bf2482c6e8175c5` |
| **Ciphertext (base64)** | `Ut0JaUjJhgtqgMajR9625OYRw6hhIv31o8hflE+uZH/AfL+J/xqDjOZXZKwqFb/OK72XcYBXs29wjRqciSAm5N2b8kgsboF1xQ==` |
| **Decrypted text** | `Dear All Good luck with your Job interview with Bloomberg` |
| **Checks** | shared secrets match ✔ · decrypted text equals original ✔ · tampered ciphertext rejected ✔ |

The assignment text spells it "Blommberg". The message was corrected to
"Bloomberg" before encryption.

You can decrypt the saved result again yourself:

```sh
python encrypt_message.py --verify evidence/assignment_output.json
```

### Why Kyber + AES?

Kyber is a **key encapsulation mechanism (KEM)**. It does not encrypt a sentence
directly; it lets a sender and a receiver agree on a 32-byte secret key, in a
way that stays secure even against quantum computers. That key is then used
with AES-256-GCM to encrypt the actual message. This is the standard way to
use Kyber/ML-KEM.

```
Receiver                                   Sender
--------                                   ------
keypair() -> public key, secret key
                 ---- public key ---->
                                           encapsulate(pk) -> Kyber ciphertext, shared secret
                                           AES-256-GCM(shared secret, message) -> ciphertext
                 <--- Kyber ct + ciphertext ---
decapsulate(Kyber ct, sk) -> shared secret
AES-256-GCM decrypt -> message
```

---

## How the website protects the login

1. The browser asks the server for a handshake. The server creates a **fresh
   Kyber768 key pair for that one login** and sends back the public key.
2. The browser runs ML-KEM-768 encapsulation
   ([`@noble/post-quantum`](https://github.com/paulmillr/noble-post-quantum),
   bundled in `static/vendor/`), which gives a shared secret. It encrypts
   `{username, password}` with AES-256-GCM using that secret.
3. Only the Kyber ciphertext and the encrypted credentials are sent.
4. The server decapsulates with the **official C reference code**, decrypts,
   and checks the password against a salted PBKDF2 hash. Each handshake key
   works once and expires after 2 minutes.

After logging in, the dashboard shows exactly what the browser sent for that
login.

The browser library and the C reference code are different implementations of
the same standard (FIPS 203). The login only works because they agree on the
shared secret, which shows the two are compatible.

---

## Evidence

| File | What it shows |
|---|---|
| `evidence/assignment_output.txt` | The assignment run: keys, Kyber ciphertext, ciphertext, decrypted text, checks |
| `evidence/official_kyber_tests.txt` | Official Kyber self-tests pass for 512/768/1024, and the test-vector hashes match the published `SHA256SUMS` |
| `evidence/test_results.txt` | 14 automated tests: Kyber, encryption, sign-up/login protocol, tamper and replay rejection |
| `evidence/local_browser_test.txt` | Real Chrome run against the local site, which confirms the password never appears in any request |
| `evidence/deployed_browser_test.txt` | The same browser test against the live Railway site |
| `evidence/screenshots/` | Sign-up, dashboard, encrypted message, wrong password and login, both local and deployed |

---

## Run it locally

Requires a C compiler, Python 3.9+, and (for the browser test only) Node.js and Google Chrome.

```sh
git clone https://github.com/FrimpsManu/pqc-kyber-login.git
cd pqc-kyber-login
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
./build.sh                         # compile kyber/ref into pqc/lib/libkyber768.so

.venv/bin/python encrypt_message.py   # assignment run -> evidence/
./run_tests.sh                        # official Kyber tests + pytest -> evidence/
.venv/bin/python app.py               # website on http://127.0.0.1:8000
```

Browser test (with the site running):

```sh
cd tests/browser && npm install && npm test
```

## Deploy

The `Dockerfile` builds the Kyber library, runs the tests, and starts gunicorn.
It is deployed on [Railway](https://railway.app) with one environment variable,
`SECRET_KEY`.

## Project layout

```
kyber/                 official pq-crystals/kyber source (unmodified, see kyber/UPSTREAM.md)
pqc/kyber.py           Python binding to the C library (keypair / encapsulate / decapsulate)
pqc/hybrid.py          Kyber + AES-256-GCM encrypt / decrypt
encrypt_message.py     assignment run
app.py                 Flask website
static/js/auth.js      browser-side Kyber encryption of the login form
templates/             HTML pages
tests/                 pytest suite and Chrome browser test
evidence/              outputs, test logs, screenshots
```

## Limitations

This is a demonstration, not a production login system.

- The server's Kyber public key is not signed, so the browser cannot prove it
  came from the real server. On the live site, HTTPS provides that proof; the
  Kyber layer adds post-quantum protection for the credentials themselves.
- The upstream authors note that the reference code is no longer actively
  maintained for production use. For production they recommend
  [mlkem-native](https://github.com/pq-code-package/mlkem-native).
- On Railway, accounts are stored in SQLite inside the container, so they are
  reset whenever the site is redeployed.

## Credits

- Kyber reference implementation: the CRYSTALS-Kyber team ([pq-crystals/kyber](https://github.com/pq-crystals/kyber)), CC0 / Apache 2.0
- Browser ML-KEM: [`@noble/post-quantum`](https://github.com/paulmillr/noble-post-quantum) by Paul Miller, MIT
