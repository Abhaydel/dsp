"""
Practical Examples: Hash Functions and Obfuscation
Real-world applications demonstrating the use of hash functions and obfuscation
"""

import hashlib
import base64
import os
import json
import time
from hash_functions import HashGenerator
from obfuscation_techniques import CodeObfuscator


class PasswordManager:
    """Simple password manager demonstrating hash function usage"""

    def __init__(self):
        self.users_file = "users.json"
        self.hasher = HashGenerator()
        self.load_users()

    def load_users(self):
        """Load users from file or create empty database"""
        try:
            with open(self.users_file, 'r') as f:
                self.users = json.load(f)
        except FileNotFoundError:
            self.users = {}

    def save_users(self):
        """Save users to file"""
        with open(self.users_file, 'w') as f:
            json.dump(self.users, f, indent=2)

    def hash_password(self, password: str, salt: str = None) -> tuple:
        """
        Hash a password with salt

        Args:
            password (str): Plain text password
            salt (str): Salt value (generated if None)

        Returns:
            tuple: (hashed_password, salt)
        """
        if salt is None:
            salt = os.urandom(32).hex()

        # Combine password and salt
        salted_password = password + salt

        # Hash the salted password
        password_hash = self.hasher.hash_string(salted_password, 'sha256')

        return password_hash, salt

    def register_user(self, username: str, password: str) -> bool:
        """
        Register a new user

        Args:
            username (str): Username
            password (str): Plain text password

        Returns:
            bool: True if successful, False if user exists
        """
        if username in self.users:
            return False

        password_hash, salt = self.hash_password(password)

        self.users[username] = {
            'password_hash': password_hash,
            'salt': salt,
            'created_at': time.time()
        }

        self.save_users()
        return True

    def authenticate_user(self, username: str, password: str) -> bool:
        """
        Authenticate a user

        Args:
            username (str): Username
            password (str): Plain text password

        Returns:
            bool: True if authentication successful
        """
        if username not in self.users:
            return False

        user_data = self.users[username]
        salt = user_data['salt']
        stored_hash = user_data['password_hash']

        # Hash the provided password with stored salt
        provided_hash, _ = self.hash_password(password, salt)

        return provided_hash == stored_hash


class FileIntegrityChecker:
    """File integrity checker using hash functions"""

    def __init__(self):
        self.hasher = HashGenerator()
        self.integrity_file = "file_hashes.json"
        self.load_hashes()

    def load_hashes(self):
        """Load stored file hashes"""
        try:
            with open(self.integrity_file, 'r') as f:
                self.file_hashes = json.load(f)
        except FileNotFoundError:
            self.file_hashes = {}

    def save_hashes(self):
        """Save file hashes"""
        with open(self.integrity_file, 'w') as f:
            json.dump(self.file_hashes, f, indent=2)

    def add_file(self, file_path: str) -> str:
        """
        Add a file to integrity monitoring

        Args:
            file_path (str): Path to the file

        Returns:
            str: Hash value of the file
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")

        file_hash = self.hasher.hash_file(file_path, 'sha256')
        file_size = os.path.getsize(file_path)

        self.file_hashes[file_path] = {
            'hash': file_hash,
            'size': file_size,
            'added_at': time.time(),
            'last_checked': time.time()
        }

        self.save_hashes()
        return file_hash

    def check_file(self, file_path: str) -> dict:
        """
        Check if a file has been modified

        Args:
            file_path (str): Path to the file

        Returns:
            dict: Status information
        """
        if file_path not in self.file_hashes:
            return {'status': 'not_monitored', 'message': 'File is not being monitored'}

        if not os.path.exists(file_path):
            return {'status': 'missing', 'message': 'File is missing'}

        stored_data = self.file_hashes[file_path]
        current_hash = self.hasher.hash_file(file_path, 'sha256')
        current_size = os.path.getsize(file_path)

        # Update last checked time
        stored_data['last_checked'] = time.time()
        self.save_hashes()

        if current_hash == stored_data['hash'] and current_size == stored_data['size']:
            return {'status': 'unchanged', 'message': 'File is unchanged'}
        else:
            return {
                'status': 'modified',
                'message': 'File has been modified',
                'original_hash': stored_data['hash'],
                'current_hash': current_hash,
                'original_size': stored_data['size'],
                'current_size': current_size
            }

    def check_all_files(self) -> dict:
        """Check all monitored files"""
        results = {}
        for file_path in self.file_hashes.keys():
            results[file_path] = self.check_file(file_path)
        return results


class LicenseKeyGenerator:
    """Obfuscated license key generator"""

    def __init__(self):
        self.obfuscator = CodeObfuscator()
        self.hasher = HashGenerator()

        # Obfuscated algorithm components
        self._key_parts = self._get_obfuscated_parts()

    def _get_obfuscated_parts(self) -> dict:
        """Get obfuscated key generation components"""
        # These would normally be heavily obfuscated
        return {
            'prefix': base64.b64encode(b'LIC').decode(),
            'separator': base64.b64encode(b'-').decode(),
            'suffix': base64.b64encode(b'2024').decode()
        }

    def generate_license_key(self, user_id: str, product_code: str) -> str:
        """
        Generate an obfuscated license key

        Args:
            user_id (str): User identifier
            product_code (str): Product code

        Returns:
            str: Generated license key
        """
        # Create a unique string
        unique_string = f"{user_id}:{product_code}:{time.time()}"

        # Hash it
        hash_value = self.hasher.hash_string(unique_string, 'sha256')

        # Take first 16 characters
        key_core = hash_value[:16].upper()

        # Decode obfuscated parts
        prefix = base64.b64decode(self._key_parts['prefix']).decode()
        separator = base64.b64decode(self._key_parts['separator']).decode()
        suffix = base64.b64decode(self._key_parts['suffix']).decode()

        # Format license key
        formatted_key = f"{prefix}{separator}{key_core[:4]}{separator}{key_core[4:8]}{separator}{key_core[8:12]}{separator}{key_core[12:16]}{separator}{suffix}"

        return formatted_key

    def validate_license_key(self, license_key: str, user_id: str, product_code: str) -> bool:
        """
        Validate a license key (simplified validation)

        Args:
            license_key (str): License key to validate
            user_id (str): User identifier
            product_code (str): Product code

        Returns:
            bool: True if valid (simplified check)
        """
        # This is a simplified validation - real implementation would be more complex
        if not license_key.startswith('LIC-') or not license_key.endswith('-2024'):
            return False

        # Extract the core part
        parts = license_key.split('-')
        if len(parts) != 6:
            return False

        key_core = ''.join(parts[1:5])

        # Check if it's a valid hex string of correct length
        try:
            int(key_core, 16)
            return len(key_core) == 16
        except ValueError:
            return False


def demonstrate_practical_applications():
    """Demonstrate practical applications"""
    print("=" * 80)
    print("PRACTICAL APPLICATIONS DEMONSTRATION")
    print("=" * 80)

    # Password Manager Demo
    print("\n1. PASSWORD MANAGER DEMONSTRATION")
    print("-" * 50)

    pm = PasswordManager()

    # Register users
    print("Registering users...")
    success1 = pm.register_user("alice", "mypassword123")
    success2 = pm.register_user("bob", "securepwd456")
    success3 = pm.register_user("alice", "duplicate")  # Should fail

    print(f"Alice registration: {'Success' if success1 else 'Failed'}")
    print(f"Bob registration: {'Success' if success2 else 'Failed'}")
    print(f"Alice duplicate: {'Success' if success3 else 'Failed (expected)'}")

    # Authenticate users
    print("\nAuthenticating users...")
    auth1 = pm.authenticate_user("alice", "mypassword123")
    auth2 = pm.authenticate_user("alice", "wrongpassword")
    auth3 = pm.authenticate_user("bob", "securepwd456")

    print(f"Alice correct password: {'Success' if auth1 else 'Failed'}")
    print(
        f"Alice wrong password: {'Success' if auth2 else 'Failed (expected)'}")
    print(f"Bob correct password: {'Success' if auth3 else 'Failed'}")

    # File Integrity Checker Demo
    print("\n2. FILE INTEGRITY CHECKER DEMONSTRATION")
    print("-" * 50)

    fic = FileIntegrityChecker()

    # Create a test file
    test_file = "integrity_test.txt"
    with open(test_file, 'w') as f:
        f.write("This is a test file for integrity checking.")

    # Add file to monitoring
    print(f"Adding {test_file} to integrity monitoring...")
    file_hash = fic.add_file(test_file)
    print(f"File hash: {file_hash}")

    # Check file (should be unchanged)
    result1 = fic.check_file(test_file)
    print(f"First check: {result1['status']} - {result1['message']}")

    # Modify the file
    with open(test_file, 'a') as f:
        f.write(" Modified content!")

    # Check file again (should be modified)
    result2 = fic.check_file(test_file)
    print(f"After modification: {result2['status']} - {result2['message']}")
    if result2['status'] == 'modified':
        print(f"Original hash: {result2['original_hash']}")
        print(f"Current hash: {result2['current_hash']}")

    # License Key Generator Demo
    print("\n3. OBFUSCATED LICENSE KEY GENERATOR DEMONSTRATION")
    print("-" * 50)

    lkg = LicenseKeyGenerator()

    # Generate license keys
    key1 = lkg.generate_license_key("user123", "PROD001")
    key2 = lkg.generate_license_key("user456", "PROD002")

    print(f"License key for user123/PROD001: {key1}")
    print(f"License key for user456/PROD002: {key2}")

    # Validate license keys
    valid1 = lkg.validate_license_key(key1, "user123", "PROD001")
    valid2 = lkg.validate_license_key("INVALID-KEY", "user123", "PROD001")

    print(f"Key1 validation: {'Valid' if valid1 else 'Invalid'}")
    print(
        f"Invalid key validation: {'Valid' if valid2 else 'Invalid (expected)'}")

    # Clean up
    print("\n4. CLEANUP")
    print("-" * 50)

    files_to_clean = [test_file, "users.json", "file_hashes.json"]
    for file_path in files_to_clean:
        if os.path.exists(file_path):
            os.remove(file_path)
            print(f"Removed: {file_path}")

    print("\nDemonstration completed!")


if __name__ == "__main__":
    demonstrate_practical_applications()
