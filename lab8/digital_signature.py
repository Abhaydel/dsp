"""
Digital Signature Implementation using RSA
This module provides RSA key generation, digital signature creation and verification
"""

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
import base64
import os

class RSADigitalSignature:
    def __init__(self):
        self.private_key = None
        self.public_key = None
    
    def generate_key_pair(self, key_size=2048):
        """
        Generate RSA key pair for digital signatures
        """
        print(f"Generating RSA key pair with {key_size} bits...")
        
        # Generate private key
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
        )
        
        # Get public key
        self.public_key = self.private_key.public_key()
        
        print("RSA key pair generated successfully!")
        return self.private_key, self.public_key
    
    def save_keys(self, private_key_path="private_key.pem", public_key_path="public_key.pem"):
        """
        Save keys to files
        """
        if not self.private_key or not self.public_key:
            raise ValueError("Keys not generated yet!")
        
        # Save private key
        private_pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        # Save public key
        public_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        with open(private_key_path, 'wb') as f:
            f.write(private_pem)
        
        with open(public_key_path, 'wb') as f:
            f.write(public_pem)
        
        print(f"Keys saved to {private_key_path} and {public_key_path}")
    
    def load_keys(self, private_key_path="private_key.pem", public_key_path="public_key.pem"):
        """
        Load keys from files
        """
        if os.path.exists(private_key_path):
            with open(private_key_path, 'rb') as f:
                self.private_key = load_pem_private_key(f.read(), password=None)
        
        if os.path.exists(public_key_path):
            with open(public_key_path, 'rb') as f:
                self.public_key = load_pem_public_key(f.read())
        
        print("Keys loaded successfully!")
    
    def sign_message(self, message):
        """
        Create digital signature for a message
        """
        if not self.private_key:
            raise ValueError("Private key not available!")
        
        # Convert message to bytes if it's a string
        if isinstance(message, str):
            message = message.encode('utf-8')
        
        # Create signature
        signature = self.private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        # Encode signature to base64 for easy transmission
        signature_b64 = base64.b64encode(signature).decode('utf-8')
        
        print(f"Message signed successfully!")
        print(f"Signature (base64): {signature_b64[:50]}...")
        
        return signature_b64
    
    def verify_signature(self, message, signature_b64, public_key=None):
        """
        Verify digital signature
        """
        if public_key is None:
            public_key = self.public_key
        
        if not public_key:
            raise ValueError("Public key not available!")
        
        try:
            # Convert message to bytes if it's a string
            if isinstance(message, str):
                message = message.encode('utf-8')
            
            # Decode signature from base64
            signature = base64.b64decode(signature_b64)
            
            # Verify signature
            public_key.verify(
                signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            print("✓ Signature verification successful!")
            return True
            
        except Exception as e:
            print(f"✗ Signature verification failed: {str(e)}")
            return False
    
    def get_public_key_pem(self):
        """
        Get public key in PEM format as string
        """
        if not self.public_key:
            raise ValueError("Public key not available!")
        
        public_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        return public_pem.decode('utf-8')

# Demonstration functions
def demonstrate_digital_signatures():
    """
    Demonstrate RSA digital signature functionality
    """
    print("=" * 60)
    print("RSA DIGITAL SIGNATURE DEMONSTRATION")
    print("=" * 60)
    
    # Initialize RSA digital signature
    rsa_ds = RSADigitalSignature()
    
    # Generate key pair
    rsa_ds.generate_key_pair()
    
    # Save keys
    rsa_ds.save_keys()
    
    # Test message
    message = "This is a confidential e-commerce transaction worth $1000.00"
    print(f"\nOriginal message: {message}")
    
    # Sign the message
    print("\n1. SIGNING THE MESSAGE:")
    signature = rsa_ds.sign_message(message)
    
    # Verify the signature
    print("\n2. VERIFYING THE SIGNATURE:")
    is_valid = rsa_ds.verify_signature(message, signature)
    
    # Test with tampered message
    print("\n3. TESTING WITH TAMPERED MESSAGE:")
    tampered_message = "This is a confidential e-commerce transaction worth $9999.00"
    print(f"Tampered message: {tampered_message}")
    is_valid_tampered = rsa_ds.verify_signature(tampered_message, signature)
    
    # Test loading keys from file
    print("\n4. TESTING KEY LOADING FROM FILES:")
    new_rsa_ds = RSADigitalSignature()
    new_rsa_ds.load_keys()
    is_valid_loaded = new_rsa_ds.verify_signature(message, signature)
    
    return rsa_ds

if __name__ == "__main__":
    demonstrate_digital_signatures()
