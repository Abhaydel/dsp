"""
Test Script for Hash Functions and Obfuscation Project
Quick verification that all components work correctly
"""

import sys
import traceback


def test_hash_functions():
    """Test hash function implementations"""
    print("Testing Hash Functions...")
    try:
        from hash_functions import HashGenerator

        hasher = HashGenerator()

        # Test string hashing
        test_hash = hasher.hash_string("test", "sha256")
        expected = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
        assert test_hash == expected, f"Expected {expected}, got {test_hash}"

        # Test multiple algorithms
        hashes = hasher.hash_multiple_algorithms("test")
        assert len(hashes) == 6, f"Expected 6 algorithms, got {len(hashes)}"

        # Test comparison
        assert hasher.compare_hashes(
            "same", "same"), "Identical strings should have same hash"
        assert not hasher.compare_hashes(
            "different", "strings"), "Different strings should have different hashes"

        print("✓ Hash Functions: All tests passed")
        return True

    except Exception as e:
        print(f"✗ Hash Functions: Test failed - {e}")
        traceback.print_exc()
        return False


def test_obfuscation():
    """Test obfuscation implementations"""
    print("Testing Obfuscation Techniques...")
    try:
        from obfuscation_techniques import CodeObfuscator, ObfuscatedFunction

        obfuscator = CodeObfuscator()

        # Test base64 obfuscation
        original_code = "print('Hello, World!')"
        obfuscated = obfuscator.base64_obfuscation(original_code)
        assert "base64" in obfuscated, "Base64 obfuscation should contain 'base64'"
        assert "exec" in obfuscated, "Base64 obfuscation should contain 'exec'"

        # Test string obfuscation
        obfuscated_str = obfuscator.string_obfuscation("test")
        result = eval(obfuscated_str)
        assert result == "test", f"String obfuscation failed: expected 'test', got '{result}'"

        # Test obfuscated function
        obf_func = ObfuscatedFunction()
        result = obf_func.hidden_calculation(5, 6)
        assert result == 40, f"Hidden calculation failed: expected 40, got {result}"

        print("✓ Obfuscation: All tests passed")
        return True

    except Exception as e:
        print(f"✗ Obfuscation: Test failed - {e}")
        traceback.print_exc()
        return False


def test_practical_examples():
    """Test practical examples"""
    print("Testing Practical Examples...")
    try:
        from practical_examples import PasswordManager, FileIntegrityChecker, LicenseKeyGenerator

        # Test password manager
        pm = PasswordManager()
        assert pm.register_user(
            "testuser", "testpass"), "User registration should succeed"
        assert pm.authenticate_user(
            "testuser", "testpass"), "Authentication should succeed"
        assert not pm.authenticate_user(
            "testuser", "wrongpass"), "Wrong password should fail"

        # Test license key generator
        lkg = LicenseKeyGenerator()
        key = lkg.generate_license_key("user1", "prod1")
        assert key.startswith("LIC-"), "License key should start with 'LIC-'"
        assert key.endswith("-2024"), "License key should end with '-2024'"
        assert lkg.validate_license_key(
            key, "user1", "prod1"), "Generated key should be valid"

        print("✓ Practical Examples: All tests passed")
        return True

    except Exception as e:
        print(f"✗ Practical Examples: Test failed - {e}")
        traceback.print_exc()
        return False


def test_code_execution():
    """Test that obfuscated code actually executes"""
    print("Testing Obfuscated Code Execution...")
    try:
        from obfuscation_techniques import CodeObfuscator

        obfuscator = CodeObfuscator()

        # Create test code
        test_code = '''
result = 2 + 3
test_var = "success"
'''

        # Test base64 obfuscation execution
        obfuscated = obfuscator.base64_obfuscation(test_code)

        # Execute in a separate namespace to capture variables
        namespace = {}
        exec(obfuscated, namespace)

        assert namespace.get(
            'result') == 5, "Obfuscated code should execute correctly"
        assert namespace.get(
            'test_var') == "success", "Variables should be set correctly"

        print("✓ Code Execution: All tests passed")
        return True

    except Exception as e:
        print(f"✗ Code Execution: Test failed - {e}")
        traceback.print_exc()
        return False


def run_all_tests():
    """Run all tests and report results"""
    print("=" * 60)
    print("RUNNING COMPREHENSIVE TESTS")
    print("=" * 60)

    tests = [
        test_hash_functions,
        test_obfuscation,
        test_practical_examples,
        test_code_execution
    ]

    passed = 0
    total = len(tests)

    for test in tests:
        if test():
            passed += 1
        print()

    print("=" * 60)
    print(f"TEST RESULTS: {passed}/{total} tests passed")
    print("=" * 60)

    if passed == total:
        print("🎉 All tests passed! The project is working correctly.")
        return True
    else:
        print("❌ Some tests failed. Please check the implementation.")
        return False


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
