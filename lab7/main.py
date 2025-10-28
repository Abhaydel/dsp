"""
Hash Functions and Obfuscation - Main Demonstration
This script demonstrates both hash functions and obfuscation techniques
"""

import sys
import os
from hash_functions import HashGenerator, demonstrate_hash_functions
from obfuscation_techniques import CodeObfuscator, ObfuscatedFunction, demonstrate_obfuscation

def interactive_hash_demo():
    """Interactive demonstration of hash functions"""
    print("\n" + "=" * 60)
    print("INTERACTIVE HASH FUNCTION DEMO")
    print("=" * 60)
    
    hasher = HashGenerator()
    
    while True:
        print("\nChoose an option:")
        print("1. Hash a string")
        print("2. Hash a file")
        print("3. Compare two strings")
        print("4. Generate multiple hashes")
        print("5. Return to main menu")
        
        choice = input("\nEnter your choice (1-5): ").strip()
        
        if choice == '1':
            text = input("Enter text to hash: ")
            algorithm = input("Enter algorithm (md5, sha1, sha256, sha512) [default: sha256]: ").strip() or 'sha256'
            try:
                hash_value = hasher.hash_string(text, algorithm)
                print(f"\n{algorithm.upper()} hash: {hash_value}")
            except ValueError as e:
                print(f"Error: {e}")
        
        elif choice == '2':
            file_path = input("Enter file path: ").strip()
            algorithm = input("Enter algorithm (md5, sha1, sha256, sha512) [default: sha256]: ").strip() or 'sha256'
            try:
                hash_value = hasher.hash_file(file_path, algorithm)
                print(f"\n{algorithm.upper()} hash of file: {hash_value}")
            except (FileNotFoundError, ValueError) as e:
                print(f"Error: {e}")
        
        elif choice == '3':
            text1 = input("Enter first string: ")
            text2 = input("Enter second string: ")
            algorithm = input("Enter algorithm [default: sha256]: ").strip() or 'sha256'
            try:
                are_same = hasher.compare_hashes(text1, text2, algorithm)
                print(f"\nStrings are {'identical' if are_same else 'different'}")
                print(f"Hash 1: {hasher.hash_string(text1, algorithm)}")
                print(f"Hash 2: {hasher.hash_string(text2, algorithm)}")
            except ValueError as e:
                print(f"Error: {e}")
        
        elif choice == '4':
            text = input("Enter text to hash: ")
            hashes = hasher.hash_multiple_algorithms(text)
            print(f"\nAll hashes for '{text}':")
            for algo, hash_val in hashes.items():
                print(f"{algo.upper()}: {hash_val}")
        
        elif choice == '5':
            break
        
        else:
            print("Invalid choice. Please try again.")

def interactive_obfuscation_demo():
    """Interactive demonstration of obfuscation techniques"""
    print("\n" + "=" * 60)
    print("INTERACTIVE OBFUSCATION DEMO")
    print("=" * 60)
    
    obfuscator = CodeObfuscator()
    
    while True:
        print("\nChoose an option:")
        print("1. Obfuscate custom code")
        print("2. Test obfuscated function")
        print("3. String obfuscation")
        print("4. Multilayer obfuscation")
        print("5. Return to main menu")
        
        choice = input("\nEnter your choice (1-5): ").strip()
        
        if choice == '1':
            print("Enter your Python code (end with 'END' on a new line):")
            code_lines = []
            while True:
                line = input()
                if line.strip() == 'END':
                    break
                code_lines.append(line)
            
            code = '\n'.join(code_lines)
            
            print("\nObfuscation methods:")
            print("1. Base64")
            print("2. Zlib compression")
            print("3. Marshal")
            method = input("Choose method (1-3): ").strip()
            
            try:
                if method == '1':
                    obfuscated = obfuscator.base64_obfuscation(code)
                elif method == '2':
                    obfuscated = obfuscator.zlib_compression_obfuscation(code)
                elif method == '3':
                    obfuscated = obfuscator.marshal_obfuscation(code)
                else:
                    print("Invalid method")
                    continue
                
                print("\nObfuscated code:")
                print("-" * 40)
                print(obfuscated)
                
                # Ask if user wants to execute it
                execute = input("\nExecute obfuscated code? (y/n): ").strip().lower()
                if execute == 'y':
                    try:
                        exec(obfuscated)
                    except Exception as e:
                        print(f"Execution error: {e}")
                        
            except Exception as e:
                print(f"Obfuscation error: {e}")
        
        elif choice == '2':
            obf_func = ObfuscatedFunction()
            
            print("Testing obfuscated function...")
            x = int(input("Enter first number: "))
            y = int(input("Enter second number: "))
            result = obf_func.hidden_calculation(x, y)
            print(f"Hidden calculation result: {result}")
            
            password = input("Enter password to reveal secret: ")
            secret = obf_func.reveal_secret(password)
            print(f"Result: {secret}")
        
        elif choice == '3':
            text = input("Enter string to obfuscate: ")
            obfuscated_str = obfuscator.string_obfuscation(text)
            print(f"\nObfuscated string: {obfuscated_str}")
            print(f"Deobfuscated result: {eval(obfuscated_str)}")
        
        elif choice == '4':
            print("Enter your Python code (end with 'END' on a new line):")
            code_lines = []
            while True:
                line = input()
                if line.strip() == 'END':
                    break
                code_lines.append(line)
            
            code = '\n'.join(code_lines)
            
            try:
                obfuscated = obfuscator.multilayer_obfuscation(code)
                print("\nMultilayer obfuscated code:")
                print("-" * 40)
                print(obfuscated)
            except Exception as e:
                print(f"Obfuscation error: {e}")
        
        elif choice == '5':
            break
        
        else:
            print("Invalid choice. Please try again.")

def create_sample_files():
    """Create sample files for demonstration"""
    # Create a sample text file
    sample_content = """This is a sample file for hash function testing.
It contains multiple lines of text.
Hash functions can process files of any size.
This demonstrates file integrity checking."""
    
    with open("sample.txt", "w") as f:
        f.write(sample_content)
    
    # Create a sample Python script
    sample_script = '''# Sample Python script
def greet(name):
    return f"Hello, {name}!"

if __name__ == "__main__":
    print(greet("World"))
'''
    
    with open("sample_script.py", "w") as f:
        f.write(sample_script)
    
    print("Sample files created: sample.txt, sample_script.py")

def main():
    """Main program loop"""
    print("=" * 80)
    print("HASH FUNCTIONS AND OBFUSCATION DEMONSTRATION")
    print("=" * 80)
    print("This program demonstrates:")
    print("- Various hash function implementations (MD5, SHA-1, SHA-256, etc.)")
    print("- Code obfuscation techniques")
    print("- Practical applications of both concepts")
    
    while True:
        print("\n" + "=" * 50)
        print("MAIN MENU")
        print("=" * 50)
        print("1. Run hash function demonstrations")
        print("2. Run obfuscation demonstrations")
        print("3. Interactive hash function demo")
        print("4. Interactive obfuscation demo")
        print("5. Create sample files")
        print("6. Exit")
        
        choice = input("\nEnter your choice (1-6): ").strip()
        
        if choice == '1':
            demonstrate_hash_functions()
        
        elif choice == '2':
            demonstrate_obfuscation()
        
        elif choice == '3':
            interactive_hash_demo()
        
        elif choice == '4':
            interactive_obfuscation_demo()
        
        elif choice == '5':
            create_sample_files()
        
        elif choice == '6':
            print("\nGoodbye!")
            break
        
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
