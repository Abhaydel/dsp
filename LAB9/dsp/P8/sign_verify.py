from flask import Flask, render_template, request, send_file, redirect, url_for, flash, Response
import base64
import os
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.exceptions import InvalidSignature

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET", "supersecretkey_change_me")   # for flash messages

# --------------------------
# RSA helpers
def generate_rsa_keypair(key_size=2048):
    priv = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    pub = priv.public_key()
    return priv, pub

def private_key_to_pem(private_key, password: bytes = None):
    enc = serialization.BestAvailableEncryption(password) if password else serialization.NoEncryption()
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=enc
    )

def public_key_to_pem(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def sign_bytes(private_key, data: bytes, hash_algo=hashes.SHA256()):
    return private_key.sign(
        data,
        padding.PSS(mgf=padding.MGF1(hash_algo), salt_length=padding.PSS.MAX_LENGTH),
        hash_algo
    )

def verify_bytes(public_key, signature: bytes, data: bytes, hash_algo=hashes.SHA256()):
    public_key.verify(
        signature,
        data,
        padding.PSS(mgf=padding.MGF1(hash_algo), salt_length=padding.PSS.MAX_LENGTH),
        hash_algo
    )

# --------------------------
# In-memory storage (demo only)
PRIVATE_KEY = None
PUBLIC_KEY = None

# --------------------------
# Helper to get PEM strings for display
def get_pem_strings():
    priv_pem = public_pem = None
    try:
        if PRIVATE_KEY:
            priv_pem = private_key_to_pem(PRIVATE_KEY).decode("utf-8")
        if PUBLIC_KEY:
            public_pem = public_key_to_pem(PUBLIC_KEY).decode("utf-8")
    except Exception:
        priv_pem = public_pem = None
    return priv_pem, public_pem

# --------------------------
# Routes
@app.route("/")
def index():
    priv_pem, public_pem = get_pem_strings()
    return render_template("index.html", priv_pem=priv_pem, public_pem=public_pem)

@app.route("/generate_keys", methods=["POST"])
def generate_keys():
    global PRIVATE_KEY, PUBLIC_KEY
    keysize = int(request.form.get("keysize", 2048))
    PRIVATE_KEY, PUBLIC_KEY = generate_rsa_keypair(keysize)
    flash(f"✅ Generated RSA {keysize}-bit key pair.")
    return redirect(url_for("index"))

@app.route("/download_public")
def download_public():
    global PUBLIC_KEY
    if not PUBLIC_KEY:
        flash("No public key available. Generate keys first.")
        return redirect(url_for("index"))
    pem = public_key_to_pem(PUBLIC_KEY)
    return Response(pem, mimetype="application/x-pem-file",
                    headers={"Content-Disposition": "attachment;filename=public.pem"})

@app.route("/download_private")
def download_private():
    global PRIVATE_KEY
    if not PRIVATE_KEY:
        flash("No private key available. Generate keys first.")
        return redirect(url_for("index"))
    pem = private_key_to_pem(PRIVATE_KEY)
    return Response(pem, mimetype="application/x-pem-file",
                    headers={"Content-Disposition": "attachment;filename=private.pem"})

@app.route("/sign", methods=["POST"])
def sign():
    global PRIVATE_KEY
    if not PRIVATE_KEY:
        flash("No private key loaded. Generate one first.")
        return redirect(url_for("index"))

    data = request.form.get("sign_text", "").encode("utf-8")
    if not data.strip():
        flash("No text provided to sign.")
        return redirect(url_for("index"))

    sig = sign_bytes(PRIVATE_KEY, data)
    sig_b64 = base64.b64encode(sig).decode("utf-8")
    priv_pem, public_pem = get_pem_strings()
    flash("Text signed (signature shown below).")
    return render_template("index.html", signature=sig_b64, signed_text=data.decode("utf-8"),
                           priv_pem=priv_pem, public_pem=public_pem)

@app.route("/verify", methods=["POST"])
def verify():
    global PUBLIC_KEY
    user_pub_pem = request.form.get("use_pub_pem", "").strip()
    pubkey_to_use = None
    if user_pub_pem:
        try:
            pubkey_to_use = serialization.load_pem_public_key(user_pub_pem.encode("utf-8"))
        except Exception as e:
            flash(f"Provided public key is invalid: {e}")
            return redirect(url_for("index"))
    else:
        pubkey_to_use = PUBLIC_KEY

    if not pubkey_to_use:
        flash("No public key available. Generate or paste one.")
        return redirect(url_for("index"))

    text = request.form.get("verify_text", "").encode("utf-8")
    sig_b64 = request.form.get("verify_sig", "").strip()
    if not text.strip() or not sig_b64:
        flash("Both text and signature required for verification.")
        return redirect(url_for("index"))

    try:
        sig_bytes = base64.b64decode(sig_b64)
        verify_bytes(pubkey_to_use, sig_bytes, text)
        result = "✅ Signature is VALID"
        color = "green"
    except InvalidSignature:
        result = "❌ Signature is INVALID"
        color = "red"
    except Exception as e:
        result = f"❌ Error: {e}"
        color = "red"

    priv_pem, public_pem = get_pem_strings()
    return render_template("index.html", verify_result=result, verify_color=color,
                           verify_text=text.decode("utf-8"), verify_sig=sig_b64,
                           priv_pem=priv_pem, public_pem=public_pem)

# --------------------------
# Run (development)
if __name__ == "__main__":
    app.run(debug=True)
