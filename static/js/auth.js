// Sends the login/sign-up form protected with ML-KEM-768 (Kyber) + AES-256-GCM.
// The password is encrypted in the browser before anything is posted.
(function () {
  const form = document.getElementById("auth-form");
  if (!form) return;
  const purpose = form.dataset.purpose; // "login" or "signup"
  const status = document.getElementById("status");
  const button = form.querySelector("button[type=submit]");

  const toB64 = (bytes) => btoa(String.fromCharCode(...bytes));
  const fromB64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

  function show(text, isError) {
    status.textContent = text;
    status.className = isError ? "status error" : "status";
  }

  async function post(url, body) {
    const res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: body ? JSON.stringify(body) : undefined,
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || "Request failed (" + res.status + ")");
    return data;
  }

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (purpose === "signup" && form.password.value !== form.confirm.value) {
      show("Passwords do not match.", true);
      return;
    }
    button.disabled = true;
    try {
      show("Getting the server's Kyber public key…");
      const { kid, public_key } = await post("/api/handshake");

      show("Encrypting your credentials…");
      const { cipherText, sharedSecret } = PQ.ml_kem768.encapsulate(fromB64(public_key));
      const key = await crypto.subtle.importKey("raw", sharedSecret, "AES-GCM", false, ["encrypt"]);
      const nonce = crypto.getRandomValues(new Uint8Array(12));
      const plaintext = new TextEncoder().encode(JSON.stringify({
        username: form.username.value.trim(),
        password: form.password.value,
      }));
      const ciphertext = new Uint8Array(await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: nonce, additionalData: new TextEncoder().encode(purpose + ":" + kid) },
        key, plaintext));

      show("Sending…");
      const result = await post("/api/" + purpose, {
        kid,
        kem_ciphertext: toB64(cipherText),
        nonce: toB64(nonce),
        ciphertext: toB64(ciphertext),
      });
      window.location.href = result.redirect;
    } catch (err) {
      show(err.message, true);
      button.disabled = false;
    }
  });
})();
