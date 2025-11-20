from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
import base64

# generate keys
priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
pub = priv.public_key()

message = b"hello world"
# sign
sig = priv.sign(
    message,
    padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
    hashes.SHA256()
)
print('Signature (base64):', base64.b64encode(sig).decode())

# verify
try:
    pub.verify(sig, message, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
    print('Verification: SUCCESS')
except Exception as e:
    print('Verification: FAILED', e)
