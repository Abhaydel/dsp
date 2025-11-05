import hashlib
import time
import threading
from cryptography.fernet import Fernet

# -----------------------
# Confidentiality
# -----------------------
def confidentiality_demo():
    print("\n=== Confidentiality ===")
    key = Fernet.generate_key()
    cipher = Fernet(key)

    message = "Top Secret: AI is amazing!"
    print(f"Message: {message}")

    encrypted = cipher.encrypt(message.encode())
    print(f"Encrypted: {encrypted.decode()}")

    decrypted = cipher.decrypt(encrypted).decode()
    print(f"Decrypted: {decrypted}")

# -----------------------
# Integrity
# -----------------------
def integrity_demo():
    print("\n=== Integrity ===")
    message = "Data must stay the same"
    hash1 = hashlib.sha256(message.encode()).hexdigest()

    tampered_message = "Data must stay different"
    hash2 = hashlib.sha256(tampered_message.encode()).hexdigest()

    print(f"Original Message: {message}")
    print(f"Tampered Message: {tampered_message}")
    print(f"Original Hash: {hash1[:16]}...")
    print(f"Tampered Hash: {hash2[:16]}...")

    if hash1 == hash2:
        print("Result: ✅ Data is intact")
    else:
        print("Result: ❌ Data has been altered")

# -----------------------
# Availability
# -----------------------
def availability_demo():
    print("\n=== Availability ===")
    data_store = {"file1": "important data", "file2": "student records"}

    def server():
        while True:
            print(f"✅ Server running. Available files: {', '.join(data_store.keys())}")
            time.sleep(2)

    def ddos_attack():
        time.sleep(3)
        print("⚠️  DDoS attack simulated... server overloaded!")
        time.sleep(5)
        print("⚠️  Server down temporarily...")
        time.sleep(3)
        print("✅ Server restored and running again")

    threading.Thread(target=server, daemon=True).start()
    ddos_attack()

# -----------------------
# Run all demos
# -----------------------
if __name__ == "__main__":
    confidentiality_demo()
    integrity_demo()
    availability_demo()