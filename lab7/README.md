# Hash Functions and Obfuscation Techniques

This project demonstrates the implementation of common hash functions and various code obfuscation techniques in Python.

## Project Structure

```
Lab7/
├── hash_functions.py          # Hash function implementations
├── obfuscation_techniques.py  # Code obfuscation methods
├── practical_examples.py     # Real-world applications
├── main.py                   # Main demonstration program
├── test_project.py           # Comprehensive test suite
└── README.md                 # This file
```

## Steps to Execute the Project

### Prerequisites
1. **Python Installation**: Ensure Python 3.6 or higher is installed on your system
2. **Navigate to Project Directory**: Open terminal/command prompt and navigate to the Lab7 folder
   ```bash
   cd "C:\Users\Vaibhav\Desktop\College notes\DSP\Lab7"
   ```

### Method 1: Quick Start (Recommended)
Run the main interactive program that provides all features through a menu system:

```bash
python main.py
```

**What this does:**
- Launches an interactive menu with 6 options
- Provides guided demonstrations
- Allows hands-on experimentation
- Includes sample file creation

**Menu Options:**
1. **Hash Function Demonstrations** - Automated showcase of all hash features
2. **Obfuscation Demonstrations** - Automated showcase of obfuscation techniques
3. **Interactive Hash Tools** - Hands-on hash function utilities
4. **Interactive Obfuscation Tools** - Hands-on code obfuscation
5. **Create Sample Files** - Generate test files for experimentation
6. **Exit** - Close the program

### Method 2: Individual Module Testing

#### A. Test Hash Functions Only
```bash
python hash_functions.py
```
**Output:** Complete demonstration of all hash algorithms, file hashing, and integrity checking

#### B. Test Obfuscation Techniques Only
```bash
python obfuscation_techniques.py
```
**Output:** Showcase of all obfuscation methods with before/after code examples

#### C. Test Practical Applications
```bash
python practical_examples.py
```
**Output:** Real-world examples including password management, file integrity monitoring, and license key generation

### Method 3: Run Comprehensive Tests
Verify all components work correctly:

```bash
python test_project.py
```
**Output:** Automated test suite that validates all functionality

### Method 4: Interactive Python Session
For custom experimentation:

```python
# Start Python interpreter
python

# Import and use modules directly
from hash_functions import HashGenerator
from obfuscation_techniques import CodeObfuscator

# Example usage
hasher = HashGenerator()
print(hasher.hash_string("Your text here", "sha256"))

obfuscator = CodeObfuscator()
obfuscated = obfuscator.base64_obfuscation("print('Hello World')")
exec(obfuscated)
```

### Execution Examples

#### Example 1: Hash a Custom String
```bash
python main.py
# Choose option 3 (Interactive Hash Tools)
# Choose option 1 (Hash a string)
# Enter your text and preferred algorithm
```

#### Example 2: Obfuscate Custom Code
```bash
python main.py
# Choose option 4 (Interactive Obfuscation Tools)
# Choose option 1 (Obfuscate custom code)
# Enter your Python code, type 'END' when finished
# Choose your preferred obfuscation method
```

#### Example 3: File Integrity Checking
```bash
python main.py
# Choose option 5 (Create sample files)
# Choose option 3 (Interactive Hash Tools)
# Choose option 2 (Hash a file)
# Enter the path to sample.txt
```

### Expected Outputs

**Successful Hash Function Demo:**
```
============================================================
HASH FUNCTIONS DEMONSTRATION
============================================================
Original String: Hello, World! This is a test string for hashing.
----------------------------------------
MD5: ec3d2cd87b791647768da4ef0994526d
SHA1: 979effcfd6760da3370dfd42e2aa11956e29b432
SHA256: deffb0bfaa6a2b15343dd520cef373a3a622ebc85fd9f1313dbf423a0e0f906b
...
```

**Successful Obfuscation Demo:**
```
============================================================
CODE OBFUSCATION DEMONSTRATION
============================================================
Original Code:
def simple_function(x, y):
    result = x + y
    return result

1. Base64 Obfuscation:
import base64
exec(base64.b64decode('...').decode())
...
```

**Successful Test Run:**
```
============================================================
RUNNING COMPREHENSIVE TESTS
============================================================
Testing Hash Functions...
✓ Hash Functions: All tests passed
Testing Obfuscation Techniques...
✓ Obfuscation: All tests passed
...
🎉 All tests passed! The project is working correctly.
```

### Troubleshooting

**Common Issues:**

1. **"python" command not recognized**
   - Try `python3` instead of `python`
   - Ensure Python is added to your system PATH

2. **Import errors**
   - Ensure all files are in the same directory
   - Check that file names match exactly

3. **Permission errors**
   - Ensure you have write permissions in the directory
   - Run terminal as administrator if necessary

**For Windows PowerShell users:**
If you encounter execution policy issues, you may need to run:
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### Next Steps
After running the project:
1. Experiment with different hash algorithms
2. Try obfuscating your own Python code
3. Test file integrity checking with your own files
4. Explore the practical examples for real-world applications
5. Modify the code to add new features or obfuscation techniques

## Features

### Hash Functions (`hash_functions.py`)

#### Supported Hash Algorithms
- **MD5**: Fast but cryptographically broken (for demonstration only)
- **SHA-1**: Deprecated for security applications
- **SHA-224**: Part of SHA-2 family
- **SHA-256**: Most commonly used secure hash
- **SHA-384**: Longer hash for higher security
- **SHA-512**: Longest standard hash

#### Capabilities
- **String Hashing**: Generate hash values for text strings
- **File Hashing**: Process files of any size with chunk reading
- **Hash Comparison**: Compare integrity of two strings/files
- **Multiple Algorithms**: Generate hashes using all supported algorithms
- **File Integrity Verification**: Check if files have been modified

#### Key Features
- Memory-efficient file processing using chunked reading
- Support for large files without memory overflow
- Comprehensive error handling
- Demonstration of avalanche effect (small input changes cause dramatic hash changes)

### Obfuscation Techniques (`obfuscation_techniques.py`)

#### Obfuscation Methods

1. **Base64 Encoding**
   - Simple encoding to make code unreadable
   - Easily reversible but effective for basic obfuscation

2. **Zlib Compression**
   - Compresses code and encodes it
   - Reduces code size while obfuscating

3. **Marshal Serialization**
   - Uses Python's marshal module to serialize bytecode
   - More complex obfuscation method

4. **Variable Name Obfuscation**
   - Replaces meaningful variable names with random strings
   - Makes code logic harder to follow

5. **String Obfuscation**
   - Converts strings to character code arrays
   - Hides string literals in the code

6. **Multilayer Obfuscation**
   - Combines multiple techniques for maximum obfuscation
   - Applies layers sequentially for enhanced protection

#### ObfuscatedFunction Class
- Demonstrates practical obfuscation implementation
- Includes hidden calculations and password-protected secrets
- Shows how obfuscated functions can still be functional

## Usage

### Running the Program

```bash
python main.py
```

This will start the interactive menu system where you can:
1. Run automated demonstrations
2. Use interactive hash function tools
3. Experiment with obfuscation techniques
4. Create sample files for testing

### Direct Module Usage

#### Hash Functions Example

```python
from hash_functions import HashGenerator

# Create hasher instance
hasher = HashGenerator()

# Hash a string
hash_value = hasher.hash_string("Hello World", "sha256")
print(f"SHA-256: {hash_value}")

# Hash a file
file_hash = hasher.hash_file("sample.txt", "sha256")
print(f"File hash: {file_hash}")

# Generate multiple hashes
all_hashes = hasher.hash_multiple_algorithms("test string")
for algorithm, hash_val in all_hashes.items():
    print(f"{algorithm}: {hash_val}")

# Verify file integrity
is_valid = hasher.verify_file_integrity("sample.txt", expected_hash, "sha256")
print(f"File is valid: {is_valid}")
```

#### Obfuscation Example

```python
from obfuscation_techniques import CodeObfuscator

# Create obfuscator instance
obfuscator = CodeObfuscator()

# Original code
code = '''
def hello():
    print("Hello, World!")
hello()
'''

# Apply different obfuscation techniques
base64_code = obfuscator.base64_obfuscation(code)
compressed_code = obfuscator.zlib_compression_obfuscation(code)
marshal_code = obfuscator.marshal_obfuscation(code)

# Execute obfuscated code
exec(base64_code)  # This will run the original function
```

## Educational Purposes

### Hash Functions Applications
- **Data Integrity**: Verify files haven't been corrupted or modified
- **Password Storage**: Store password hashes instead of plain text
- **Digital Signatures**: Part of cryptographic signature schemes
- **Blockchain**: Used in cryptocurrency and blockchain technology
- **Checksums**: Verify data transmission accuracy

### Obfuscation Use Cases
- **Software Protection**: Make reverse engineering more difficult
- **Intellectual Property Protection**: Hide proprietary algorithms
- **Anti-Tampering**: Prevent unauthorized code modification
- **Code Minification**: Reduce code size for distribution
- **Security Through Obscurity**: Additional layer of protection

## Security Considerations

### Hash Functions
- **MD5 and SHA-1**: Should not be used for security-critical applications
- **SHA-256/SHA-512**: Currently considered secure for most applications
- **Salting**: Always use salt when hashing passwords
- **Key Derivation**: Use proper key derivation functions (PBKDF2, bcrypt, scrypt)

### Obfuscation Limitations
- **Not Encryption**: Obfuscation is not a security measure by itself
- **Reversible**: All obfuscation techniques can be reversed with effort
- **Performance Impact**: Obfuscated code may run slower
- **Maintenance**: Obfuscated code is harder to debug and maintain

## Examples and Demonstrations

The program includes several built-in demonstrations:

1. **Avalanche Effect**: Shows how small input changes create completely different hashes
2. **File Integrity**: Demonstrates file hashing and verification
3. **Hash Comparison**: Compares hashes to detect differences
4. **Obfuscation Layers**: Shows progressive obfuscation complexity
5. **Deobfuscation**: Demonstrates that obfuscated code still executes correctly

## Requirements

- Python 3.6 or higher
- Standard library modules:
  - `hashlib`
  - `base64`
  - `marshal`
  - `zlib`
  - `os`
  - `random`
  - `string`

No external dependencies required - uses only Python standard library.

## Learning Objectives

After working with this project, you should understand:

1. **Hash Function Properties**:
   - Deterministic output
   - Avalanche effect
   - Fixed output size
   - Collision resistance

2. **Practical Hash Applications**:
   - File integrity checking
   - Password verification
   - Digital signatures
   - Data deduplication

3. **Obfuscation Techniques**:
   - Code transformation methods
   - Layered obfuscation strategies
   - Limitations and weaknesses
   - Practical implementation

4. **Security Concepts**:
   - Difference between obfuscation and encryption
   - When to use different hash algorithms
   - Security best practices
   - Reverse engineering challenges

## Disclaimer

This code is for educational purposes only. Do not use these obfuscation techniques for malicious purposes. Always follow ethical guidelines and legal requirements when implementing security measures.
