import hashlib

class HashGenerator:
    """Utility class for generating hashes"""

    def hash_string(self, text: str, algorithm: str = "sha256") -> str:
        """Hash a string"""
        h = hashlib.new(algorithm)
        h.update(text.encode("utf-8"))
        return h.hexdigest()

    def hash_file(self, file_path: str, algorithm: str = "sha256") -> str:
        """Hash a file"""
        h = hashlib.new(algorithm)
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                h.update(chunk)
        return h.hexdigest()


def demonstrate_hash_functions():
    """Simple demonstration of hash functions"""
    hasher = HashGenerator()
    text = "HelloWorld123"

    print("=" * 50)
    print("HASH FUNCTIONS DEMONSTRATION")
    print("=" * 50)

    for algo in ["md5", "sha1", "sha256", "sha512"]:
        h = hasher.hash_string(text, algo)
        print(f"{algo.upper():<8} -> {h}")
