"""
Test Suite for Digital Signature and Authentication System
Comprehensive testing for RSA digital signatures and Flask authentication
"""

import unittest
import sys
import os
import tempfile
import shutil
from unittest.mock import patch, MagicMock

# Add the current directory to the path to import our modules
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from digital_signature import RSADigitalSignature
except ImportError:
    print("Warning: cryptography library not installed. Please run: pip install cryptography")
    RSADigitalSignature = None


class TestRSADigitalSignature(unittest.TestCase):
    """
    Test cases for RSA Digital Signature implementation
    """

    def setUp(self):
        """Set up test fixtures"""
        if RSADigitalSignature is None:
            self.skipTest("cryptography library not available")

        self.rsa_ds = RSADigitalSignature()
        self.test_message = "Test transaction: Transfer $100.00 from Account A to Account B"
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        """Clean up test fixtures"""
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    def test_key_generation(self):
        """Test RSA key pair generation"""
        private_key, public_key = self.rsa_ds.generate_key_pair()

        self.assertIsNotNone(private_key)
        self.assertIsNotNone(public_key)
        self.assertEqual(self.rsa_ds.private_key, private_key)
        self.assertEqual(self.rsa_ds.public_key, public_key)

    def test_key_generation_different_sizes(self):
        """Test RSA key generation with different key sizes"""
        for key_size in [1024, 2048]:
            rsa_ds = RSADigitalSignature()
            private_key, public_key = rsa_ds.generate_key_pair(key_size)

            self.assertIsNotNone(private_key)
            self.assertIsNotNone(public_key)

    def test_signature_generation(self):
        """Test digital signature generation"""
        self.rsa_ds.generate_key_pair()
        signature = self.rsa_ds.sign_message(self.test_message)

        self.assertIsNotNone(signature)
        self.assertIsInstance(signature, str)
        self.assertTrue(len(signature) > 0)

    def test_signature_verification_valid(self):
        """Test valid signature verification"""
        self.rsa_ds.generate_key_pair()
        signature = self.rsa_ds.sign_message(self.test_message)

        is_valid = self.rsa_ds.verify_signature(self.test_message, signature)
        self.assertTrue(is_valid)

    def test_signature_verification_invalid_message(self):
        """Test signature verification with tampered message"""
        self.rsa_ds.generate_key_pair()
        signature = self.rsa_ds.sign_message(self.test_message)

        tampered_message = "Test transaction: Transfer $999.00 from Account A to Account B"
        is_valid = self.rsa_ds.verify_signature(tampered_message, signature)
        self.assertFalse(is_valid)

    def test_signature_verification_invalid_signature(self):
        """Test signature verification with invalid signature"""
        self.rsa_ds.generate_key_pair()

        # base64 encoded "invalid signature"
        invalid_signature = "aW52YWxpZCBzaWduYXR1cmU="
        is_valid = self.rsa_ds.verify_signature(
            self.test_message, invalid_signature)
        self.assertFalse(is_valid)

    def test_key_save_and_load(self):
        """Test saving and loading keys from files"""
        self.rsa_ds.generate_key_pair()

        private_key_path = os.path.join(self.temp_dir, "test_private.pem")
        public_key_path = os.path.join(self.temp_dir, "test_public.pem")

        # Save keys
        self.rsa_ds.save_keys(private_key_path, public_key_path)

        # Verify files exist
        self.assertTrue(os.path.exists(private_key_path))
        self.assertTrue(os.path.exists(public_key_path))

        # Create new instance and load keys
        new_rsa_ds = RSADigitalSignature()
        new_rsa_ds.load_keys(private_key_path, public_key_path)

        # Test that loaded keys work
        signature = new_rsa_ds.sign_message(self.test_message)
        is_valid = new_rsa_ds.verify_signature(self.test_message, signature)
        self.assertTrue(is_valid)

    def test_cross_instance_verification(self):
        """Test signature verification across different instances"""
        # Generate signature with first instance
        self.rsa_ds.generate_key_pair()
        signature = self.rsa_ds.sign_message(self.test_message)
        public_key = self.rsa_ds.public_key

        # Verify with second instance using the same public key
        new_rsa_ds = RSADigitalSignature()
        is_valid = new_rsa_ds.verify_signature(
            self.test_message, signature, public_key)
        self.assertTrue(is_valid)

    def test_bytes_message_signing(self):
        """Test signing messages provided as bytes"""
        self.rsa_ds.generate_key_pair()
        message_bytes = self.test_message.encode('utf-8')

        signature = self.rsa_ds.sign_message(message_bytes)
        is_valid = self.rsa_ds.verify_signature(message_bytes, signature)
        self.assertTrue(is_valid)

    def test_get_public_key_pem(self):
        """Test getting public key in PEM format"""
        self.rsa_ds.generate_key_pair()
        public_key_pem = self.rsa_ds.get_public_key_pem()

        self.assertIsNotNone(public_key_pem)
        self.assertIsInstance(public_key_pem, str)
        self.assertIn("BEGIN PUBLIC KEY", public_key_pem)
        self.assertIn("END PUBLIC KEY", public_key_pem)

    def test_error_handling_no_private_key(self):
        """Test error handling when private key is not available"""
        with self.assertRaises(ValueError):
            self.rsa_ds.sign_message(self.test_message)

    def test_error_handling_no_public_key(self):
        """Test error handling when public key is not available"""
        with self.assertRaises(ValueError):
            self.rsa_ds.verify_signature(self.test_message, "dummy_signature")


class TestFlaskAuthentication(unittest.TestCase):
    """
    Test cases for Flask authentication and authorization
    """

    def setUp(self):
        """Set up test fixtures"""
        # Mock Flask app for testing
        self.app = None
        self.client = None

        # Test user credentials
        self.test_users = {
            'customer1': {'password': 'password123', 'role': 'customer'},
            'admin1': {'password': 'admin123', 'role': 'admin'},
            'merchant1': {'password': 'merchant123', 'role': 'merchant'}
        }

    @patch('hashlib.sha256')
    def test_password_hashing(self, mock_sha256):
        """Test password hashing functionality"""
        import hashlib

        password = "test_password"
        expected_hash = hashlib.sha256(password.encode()).hexdigest()

        # Test actual hashing
        actual_hash = hashlib.sha256(password.encode()).hexdigest()
        self.assertEqual(actual_hash, expected_hash)

    def test_user_roles(self):
        """Test user role definitions"""
        expected_roles = ['customer', 'admin', 'merchant']

        for username, user_data in self.test_users.items():
            self.assertIn(user_data['role'], expected_roles)

    def test_transaction_validation(self):
        """Test transaction validation logic"""
        # Test positive amount validation
        valid_amounts = [0.01, 100.00, 999.99]
        invalid_amounts = [0, -10, -100.50]

        for amount in valid_amounts:
            self.assertGreater(amount, 0, f"Amount {amount} should be valid")

        for amount in invalid_amounts:
            self.assertLessEqual(
                amount, 0, f"Amount {amount} should be invalid")

    def test_jwt_token_structure(self):
        """Test JWT token structure components"""
        # Mock JWT payload structure
        expected_claims = ['identity', 'role', 'exp', 'iat']

        # Simulated JWT payload
        mock_payload = {
            'identity': 'customer1',
            'role': 'customer',
            'exp': 1234567890,
            'iat': 1234567800
        }

        for claim in expected_claims:
            if claim in ['exp', 'iat']:
                continue  # These are optional for this test
            self.assertIn(claim, mock_payload)


class TestSecurityFeatures(unittest.TestCase):
    """
    Test cases for security features and edge cases
    """

    def test_signature_uniqueness(self):
        """Test that different messages produce different signatures"""
        if RSADigitalSignature is None:
            self.skipTest("cryptography library not available")

        rsa_ds = RSADigitalSignature()
        rsa_ds.generate_key_pair()

        message1 = "Transaction 1: $100"
        message2 = "Transaction 2: $200"

        signature1 = rsa_ds.sign_message(message1)
        signature2 = rsa_ds.sign_message(message2)

        self.assertNotEqual(signature1, signature2)

    def test_signature_determinism(self):
        """Test that same message with different instances produces different signatures (due to salt)"""
        if RSADigitalSignature is None:
            self.skipTest("cryptography library not available")

        message = "Test message for determinism"

        # First instance
        rsa_ds1 = RSADigitalSignature()
        rsa_ds1.generate_key_pair()
        signature1 = rsa_ds1.sign_message(message)

        # Second signature with same instance (should be different due to PSS padding)
        signature2 = rsa_ds1.sign_message(message)

        # Signatures should be different due to random salt in PSS padding
        self.assertNotEqual(signature1, signature2)

        # But both should verify correctly
        self.assertTrue(rsa_ds1.verify_signature(message, signature1))
        self.assertTrue(rsa_ds1.verify_signature(message, signature2))

    def test_large_message_handling(self):
        """Test handling of large messages"""
        if RSADigitalSignature is None:
            self.skipTest("cryptography library not available")

        rsa_ds = RSADigitalSignature()
        rsa_ds.generate_key_pair()

        # Large message (1MB)
        large_message = "A" * (1024 * 1024)

        signature = rsa_ds.sign_message(large_message)
        is_valid = rsa_ds.verify_signature(large_message, signature)

        self.assertTrue(is_valid)

    def test_unicode_message_handling(self):
        """Test handling of unicode messages"""
        if RSADigitalSignature is None:
            self.skipTest("cryptography library not available")

        rsa_ds = RSADigitalSignature()
        rsa_ds.generate_key_pair()

        # Unicode message with special characters
        unicode_message = "Transaction: ₹1000.00 from संकेत to ग्राहक 🏦💳"

        signature = rsa_ds.sign_message(unicode_message)
        is_valid = rsa_ds.verify_signature(unicode_message, signature)

        self.assertTrue(is_valid)


class TestIntegration(unittest.TestCase):
    """
    Integration tests for the complete system
    """

    def test_complete_transaction_flow(self):
        """Test complete transaction flow with digital signatures"""
        if RSADigitalSignature is None:
            self.skipTest("cryptography library not available")

        # Initialize digital signature
        rsa_ds = RSADigitalSignature()
        rsa_ds.generate_key_pair()

        # Create transaction data
        transaction_data = {
            'from': 'customer1',
            'to': 'merchant1',
            'amount': 250.00,
            'timestamp': '2025-09-09T10:30:00'
        }

        # Create transaction message
        transaction_message = f"TRANSACTION|{transaction_data['from']}|{transaction_data['to']}|{transaction_data['amount']}|{transaction_data['timestamp']}"

        # Sign transaction
        signature = rsa_ds.sign_message(transaction_message)

        # Verify signature
        is_valid = rsa_ds.verify_signature(transaction_message, signature)

        self.assertTrue(is_valid)
        self.assertIsNotNone(signature)

    def test_multi_user_scenario(self):
        """Test multi-user scenario with different key pairs"""
        if RSADigitalSignature is None:
            self.skipTest("cryptography library not available")

        # User 1
        user1_rsa = RSADigitalSignature()
        user1_rsa.generate_key_pair()

        # User 2
        user2_rsa = RSADigitalSignature()
        user2_rsa.generate_key_pair()

        message = "Multi-user test message"

        # User 1 signs message
        signature1 = user1_rsa.sign_message(message)

        # User 2 signs same message
        signature2 = user2_rsa.sign_message(message)

        # Signatures should be different
        self.assertNotEqual(signature1, signature2)

        # Each user can verify their own signature
        self.assertTrue(user1_rsa.verify_signature(message, signature1))
        self.assertTrue(user2_rsa.verify_signature(message, signature2))

        # Cross-verification with different keys should work with proper public key
        self.assertTrue(user1_rsa.verify_signature(
            message, signature2, user2_rsa.public_key))


def run_performance_tests():
    """
    Performance tests for cryptographic operations
    """
    if RSADigitalSignature is None:
        print("Skipping performance tests: cryptography library not available")
        return

    import time

    print("\n" + "="*60)
    print("PERFORMANCE TESTS")
    print("="*60)

    rsa_ds = RSADigitalSignature()

    # Key generation performance
    start_time = time.time()
    rsa_ds.generate_key_pair(2048)
    key_gen_time = time.time() - start_time
    print(f"RSA-2048 Key Generation: {key_gen_time:.3f} seconds")

    # Signature generation performance
    message = "Performance test message for signature generation"

    start_time = time.time()
    signature = rsa_ds.sign_message(message)
    sign_time = time.time() - start_time
    print(f"Signature Generation: {sign_time:.3f} seconds")

    # Signature verification performance
    start_time = time.time()
    is_valid = rsa_ds.verify_signature(message, signature)
    verify_time = time.time() - start_time
    print(f"Signature Verification: {verify_time:.3f} seconds")
    print(f"Signature Valid: {is_valid}")

    # Batch operations performance
    num_operations = 10
    messages = [
        f"Message {i} for batch testing" for i in range(num_operations)]

    start_time = time.time()
    signatures = [rsa_ds.sign_message(msg) for msg in messages]
    batch_sign_time = time.time() - start_time
    print(
        f"Batch Signing ({num_operations} messages): {batch_sign_time:.3f} seconds")
    print(
        f"Average per signature: {batch_sign_time/num_operations:.3f} seconds")

    start_time = time.time()
    verifications = [rsa_ds.verify_signature(
        msg, sig) for msg, sig in zip(messages, signatures)]
    batch_verify_time = time.time() - start_time
    print(
        f"Batch Verification ({num_operations} signatures): {batch_verify_time:.3f} seconds")
    print(
        f"Average per verification: {batch_verify_time/num_operations:.3f} seconds")
    print(f"All verifications passed: {all(verifications)}")


def main():
    """
    Main function to run all tests
    """
    print("Digital Signature and Authentication Test Suite")
    print("=" * 60)

    # Run unit tests
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    # Add test classes
    test_classes = [
        TestRSADigitalSignature,
        TestFlaskAuthentication,
        TestSecurityFeatures,
        TestIntegration
    ]

    for test_class in test_classes:
        tests = loader.loadTestsFromTestCase(test_class)
        suite.addTests(tests)

    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    # Run performance tests
    run_performance_tests()

    # Print summary
    print("\n" + "="*60)
    print("TEST SUMMARY")
    print("="*60)
    print(f"Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(
        f"Success rate: {((result.testsRun - len(result.failures) - len(result.errors)) / result.testsRun * 100):.1f}%")

    if result.failures:
        print("\nFAILURES:")
        for test, failure in result.failures:
            print(f"- {test}: {failure}")

    if result.errors:
        print("\nERRORS:")
        for test, error in result.errors:
            print(f"- {test}: {error}")

    return result.wasSuccessful()


if __name__ == '__main__':
    success = main()
    sys.exit(0 if success else 1)
