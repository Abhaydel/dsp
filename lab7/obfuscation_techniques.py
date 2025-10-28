"""
Obfuscation Techniques in Python
Various methods to obfuscate Python code and hide logic
Educational purposes only - demonstrates code obfuscation concepts
"""

import base64
import marshal
import types
import zlib
import ast
import random
import string

class CodeObfuscator:
    """A class to demonstrate various code obfuscation techniques"""
    
    def __init__(self):
        """Initialize the obfuscator"""
        self.variable_mapping = {}
        self.function_mapping = {}
    
    def base64_obfuscation(self, code: str) -> str:
        """
        Simple base64 encoding obfuscation
        
        Args:
            code (str): Python code to obfuscate
            
        Returns:
            str: Obfuscated code using base64 encoding
        """
        encoded_code = base64.b64encode(code.encode()).decode()
        obfuscated = f"""
import base64
exec(base64.b64decode('{encoded_code}').decode())
"""
        return obfuscated
    
    def zlib_compression_obfuscation(self, code: str) -> str:
        """
        Obfuscation using zlib compression
        
        Args:
            code (str): Python code to obfuscate
            
        Returns:
            str: Obfuscated code using zlib compression
        """
        compressed = zlib.compress(code.encode())
        encoded = base64.b64encode(compressed).decode()
        obfuscated = f"""
import zlib, base64
exec(zlib.decompress(base64.b64decode('{encoded}')).decode())
"""
        return obfuscated
    
    def marshal_obfuscation(self, code: str) -> str:
        """
        Obfuscation using marshal serialization
        
        Args:
            code (str): Python code to obfuscate
            
        Returns:
            str: Obfuscated code using marshal
        """
        compiled_code = compile(code, '<string>', 'exec')
        marshaled = marshal.dumps(compiled_code)
        encoded = base64.b64encode(marshaled).decode()
        obfuscated = f"""
import marshal, base64
exec(marshal.loads(base64.b64decode('{encoded}')))
"""
        return obfuscated
    
    def generate_random_name(self, length: int = 8) -> str:
        """Generate a random variable/function name"""
        return ''.join(random.choices(string.ascii_letters + '_', k=length))
    
    def variable_name_obfuscation(self, code: str) -> str:
        """
        Simple variable name obfuscation
        Note: This is a basic implementation and may not handle all cases
        
        Args:
            code (str): Python code to obfuscate
            
        Returns:
            str: Code with obfuscated variable names
        """
        lines = code.split('\n')
        obfuscated_lines = []
        
        for line in lines:
            # Simple pattern matching for variable assignments
            if '=' in line and not line.strip().startswith('#'):
                parts = line.split('=', 1)
                if len(parts) == 2:
                    var_part = parts[0].strip()
                    value_part = parts[1].strip()
                    
                    # Check if it's a simple variable assignment
                    if var_part.isidentifier() and var_part not in self.variable_mapping:
                        new_name = self.generate_random_name()
                        self.variable_mapping[var_part] = new_name
                    
                    # Replace in the line
                    for old_name, new_name in self.variable_mapping.items():
                        line = line.replace(old_name, new_name)
            else:
                # Replace variables in other lines
                for old_name, new_name in self.variable_mapping.items():
                    line = line.replace(old_name, new_name)
            
            obfuscated_lines.append(line)
        
        return '\n'.join(obfuscated_lines)
    
    def string_obfuscation(self, text: str) -> str:
        """
        Obfuscate strings by converting to character codes
        
        Args:
            text (str): String to obfuscate
            
        Returns:
            str: Obfuscated string representation
        """
        char_codes = [str(ord(c)) for c in text]
        return f"''.join(chr(x) for x in [{','.join(char_codes)}])"
    
    def multilayer_obfuscation(self, code: str) -> str:
        """
        Apply multiple layers of obfuscation
        
        Args:
            code (str): Python code to obfuscate
            
        Returns:
            str: Heavily obfuscated code
        """
        # Layer 1: Variable name obfuscation
        obfuscated = self.variable_name_obfuscation(code)
        
        # Layer 2: Compression
        obfuscated = self.zlib_compression_obfuscation(obfuscated)
        
        # Layer 3: Base64 encoding
        obfuscated = self.base64_obfuscation(obfuscated)
        
        return obfuscated


class ObfuscatedFunction:
    """Example of an obfuscated function class"""
    
    def __init__(self):
        # Obfuscated function stored as encoded string
        self._encoded_func = """
aW1wb3J0IGJhc2U2NCwgemxpYg==
"""
        # More complex obfuscated calculation
        self._calc_data = "eJwLycgsVsjIzEvLL8pNzStRslIw0jM0MjEzMbZSUEovykvMTQWKFesZ6hkZGOkZmZjrKQAFjfQMDRTyi_KLShWMFYx1rRQ8SzJSixJzUhVySzMBZm1q8g=="
    
    def _decode_and_execute(self, encoded_data: str):
        """Decode and execute obfuscated code"""
        import base64, zlib
        try:
            decoded = base64.b64decode(encoded_data)
            decompressed = zlib.decompress(decoded).decode()
            return compile(decompressed, '<obfuscated>', 'eval')
        except:
            return None
    
    def hidden_calculation(self, x: int, y: int) -> int:
        """A function with hidden logic"""
        # The actual calculation is obfuscated
        # This is just a simple example - in reality it calculates x * y + 10
        
        # Obfuscated way to calculate x * y + 10
        a = x.__mul__(y)
        b = a.__add__(10)
        return b
    
    def reveal_secret(self, password: str) -> str:
        """Function that reveals a secret if correct password is provided"""
        # Obfuscated password check
        correct_hash = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"  # SHA-256 of "secret123"
        
        import hashlib
        provided_hash = hashlib.sha256(password.encode()).hexdigest()
        
        if provided_hash == correct_hash:
            # Obfuscated secret message
            secret = self.string_obfuscation("The secret is: Code obfuscation is a technique to make code harder to understand!")
            return eval(secret)
        else:
            return "Access denied!"
    
    def string_obfuscation(self, text: str) -> str:
        """Helper method for string obfuscation"""
        char_codes = [str(ord(c)) for c in text]
        return f"''.join(chr(x) for x in [{','.join(char_codes)}])"


def demonstrate_obfuscation():
    """Demonstrate various obfuscation techniques"""
    print("=" * 60)
    print("CODE OBFUSCATION DEMONSTRATION")
    print("=" * 60)
    
    obfuscator = CodeObfuscator()
    
    # Original simple function
    original_code = '''
def simple_function(x, y):
    result = x + y
    message = "The sum is: " + str(result)
    return message

print(simple_function(5, 3))
'''
    
    print("Original Code:")
    print("-" * 40)
    print(original_code)
    
    print("\n" + "=" * 60)
    print("OBFUSCATION TECHNIQUES")
    print("=" * 60)
    
    # 1. Base64 Obfuscation
    print("\n1. Base64 Obfuscation:")
    print("-" * 40)
    base64_obfuscated = obfuscator.base64_obfuscation(original_code)
    print(base64_obfuscated)
    
    # 2. Zlib Compression Obfuscation
    print("\n2. Zlib Compression Obfuscation:")
    print("-" * 40)
    zlib_obfuscated = obfuscator.zlib_compression_obfuscation(original_code)
    print(zlib_obfuscated)
    
    # 3. Marshal Obfuscation
    print("\n3. Marshal Obfuscation:")
    print("-" * 40)
    marshal_obfuscated = obfuscator.marshal_obfuscation(original_code)
    print(marshal_obfuscated)
    
    # 4. Variable Name Obfuscation
    print("\n4. Variable Name Obfuscation:")
    print("-" * 40)
    var_obfuscated = obfuscator.variable_name_obfuscation(original_code)
    print(var_obfuscated)
    
    # 5. Multilayer Obfuscation
    print("\n5. Multilayer Obfuscation:")
    print("-" * 40)
    multilayer_obfuscated = obfuscator.multilayer_obfuscation(original_code)
    print(multilayer_obfuscated[:200] + "..." if len(multilayer_obfuscated) > 200 else multilayer_obfuscated)
    
    # Demonstrate obfuscated function class
    print("\n" + "=" * 60)
    print("OBFUSCATED FUNCTION DEMONSTRATION")
    print("=" * 60)
    
    obf_func = ObfuscatedFunction()
    
    # Test hidden calculation
    result = obf_func.hidden_calculation(7, 6)
    print(f"Hidden calculation result (7, 6): {result}")
    
    # Test secret reveal with wrong password
    print(f"Wrong password: {obf_func.reveal_secret('wrong')}")
    
    # Test secret reveal with correct password
    print(f"Correct password: {obf_func.reveal_secret('secret123')}")
    
    print("\n" + "=" * 60)
    print("TESTING OBFUSCATED CODE EXECUTION")
    print("=" * 60)
    
    # Execute the base64 obfuscated code to show it works
    print("Executing base64 obfuscated code:")
    try:
        exec(base64_obfuscated)
    except Exception as e:
        print(f"Error executing obfuscated code: {e}")


# Example of a heavily obfuscated function
def _0x1a2b3c():
    """An example of extreme obfuscation"""
    _0x4d5e6f = lambda _0x7g8h9i: ''.join(chr(x) for x in [72, 101, 108, 108, 111, 44, 32, 87, 111, 114, 108, 100, 33])
    _0x1j2k3l = _0x4d5e6f(None)
    return _0x1j2k3l


if __name__ == "__main__":
    demonstrate_obfuscation()
    
    print("\n" + "=" * 60)
    print("EXTREME OBFUSCATION EXAMPLE")
    print("=" * 60)
    print(f"Heavily obfuscated function result: {_0x1a2b3c()}")
