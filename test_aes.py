#!/usr/bin/env python3
"""
Test script for AES-128 C implementation

This script tests the C implementation of AES-128 against a reference 
Python implementation to ensure correctness.
"""

import ctypes
import os
import random
import sys
import unittest

# Add aes submodule to path
sys.path.append('./aes')  # Import the AES implementation from the submodule
try:
    from aes import AES, encrypt, decrypt
    # Import the individual transformation functions directly since they are available
    from aes import sub_bytes, shift_rows, mix_columns, add_round_key
    from aes import bytes2matrix, matrix2bytes
    from aes import inv_sub_bytes, inv_shift_rows, inv_mix_columns
except ImportError:
    print("Error: Could not import the reference AES implementation.")
    print("Please ensure you have added a Python AES implementation as a submodule.")
    sys.exit(1)

class TestAES(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Load the C library
        try:
            cls.rijndael = ctypes.CDLL('./rijndael.so')
        except OSError:
            print("Error: Could not load rijndael.so. Make sure it's compiled.")
            sys.exit(1)
            
        # Set the return types for the C functions
        cls.rijndael.aes_encrypt_block.restype = ctypes.POINTER(ctypes.c_ubyte)
        cls.rijndael.aes_decrypt_block.restype = ctypes.POINTER(ctypes.c_ubyte)
        cls.rijndael.expand_key.restype = ctypes.POINTER(ctypes.c_ubyte)
        
    def test_subbytes(self):
        """Test the SubBytes transformation"""
        for i in range(3):  # Test with 3 random inputs as required
            # Generate random input block
            input_data = bytes([random.randint(0, 255) for _ in range(16)])
            input_copy = input_data[:]  # Make a copy for Python implementation
            
            # Create C buffer for the input
            c_block = ctypes.create_string_buffer(input_data)
            
            # Apply SubBytes in C
            self.rijndael.sub_bytes(c_block)
            c_result = bytes(c_block)[:16]
            
            # Apply SubBytes in Python
            # Convert byte array to matrix for Python implementation
            py_matrix = bytes2matrix(input_copy)
            sub_bytes(py_matrix)
            py_result = matrix2bytes(py_matrix)
            
            # Compare results
            self.assertEqual(c_result, py_result, 
                           f"Test {i+1}/3: SubBytes mismatch: Input={input_data.hex()}, "
                           f"C result={c_result.hex()}, Python result={py_result.hex()}")

    def test_shiftrows(self):
        """Test the ShiftRows transformation"""
        for i in range(3):  # Test with 3 random inputs as required
            # Generate random input block
            input_data = bytes([random.randint(0, 255) for _ in range(16)])
            input_copy = input_data[:]  # Make a copy for Python implementation
            
            # Create C buffer for the input
            c_block = ctypes.create_string_buffer(input_data)
            
            # Apply ShiftRows in C
            self.rijndael.shift_rows(c_block)
            c_result = bytes(c_block)[:16]
            
            # Apply ShiftRows in Python
            # Convert byte array to matrix for Python implementation
            py_matrix = bytes2matrix(input_copy)
            shift_rows(py_matrix)
            py_result = matrix2bytes(py_matrix)
            
            # Compare results
            self.assertEqual(c_result, py_result, 
                           f"Test {i+1}/3: ShiftRows mismatch: Input={input_data.hex()}, "
                           f"C result={c_result.hex()}, Python result={py_result.hex()}")

    def test_mixcolumns(self):
        """Test the MixColumns transformation"""
        for i in range(3):  # Test with 3 random inputs as required
            # Generate random input block
            input_data = bytes([random.randint(0, 255) for _ in range(16)])
            input_copy = input_data[:]  # Make a copy for Python implementation
            
            # Create C buffer for the input
            c_block = ctypes.create_string_buffer(input_data)
            
            # Apply MixColumns in C
            self.rijndael.mix_columns(c_block)
            c_result = bytes(c_block)[:16]
            
            # Apply MixColumns in Python
            # Convert byte array to matrix for Python implementation
            py_matrix = bytes2matrix(input_copy)
            mix_columns(py_matrix)
            py_result = matrix2bytes(py_matrix)
            
            # Compare results
            self.assertEqual(c_result, py_result, 
                           f"Test {i+1}/3: MixColumns mismatch: Input={input_data.hex()}, "
                           f"C result={c_result.hex()}, Python result={py_result.hex()}")

    def test_addroundkey(self):
        """Test the AddRoundKey transformation"""
        for i in range(3):  # Test with 3 random inputs as required
            # Generate random input block and round key
            input_data = bytes([random.randint(0, 255) for _ in range(16)])
            round_key = bytes([random.randint(0, 255) for _ in range(16)])
            input_copy = input_data[:]  # Make a copy for Python implementation
            
            # Create C buffers
            c_block = ctypes.create_string_buffer(input_data)
            c_key = ctypes.create_string_buffer(round_key)
            
            # Apply AddRoundKey in C
            self.rijndael.add_round_key(c_block, c_key)
            c_result = bytes(c_block)[:16]
            
            # Apply AddRoundKey in Python
            # Convert byte array to matrix for Python implementation
            py_block_matrix = bytes2matrix(input_copy)
            py_key_matrix = bytes2matrix(round_key)
            add_round_key(py_block_matrix, py_key_matrix)
            py_result = matrix2bytes(py_block_matrix)
            
            # Compare results
            self.assertEqual(c_result, py_result, 
                            f"Test {i+1}/3: AddRoundKey mismatch: Block={input_data.hex()}, "
                            f"Key={round_key.hex()}, C={c_result.hex()}, "
                            f"Python={py_result.hex()}")

    def test_invsubbytes(self):
        """Test the InvSubBytes transformation"""
        for i in range(3):  # Test with 3 random inputs as required
            # Generate random input block
            input_data = bytes([random.randint(0, 255) for _ in range(16)])
            input_copy = input_data[:]  # Make a copy for Python implementation
            
            # Create C buffer for the input
            c_block = ctypes.create_string_buffer(input_data)
            
            # Apply InvSubBytes in C - using the C function name
            self.rijndael.invert_sub_bytes(c_block)
            c_result = bytes(c_block)[:16]
            
            # Apply InvSubBytes in Python
            # Convert byte array to matrix for Python implementation
            py_matrix = bytes2matrix(input_copy)
            inv_sub_bytes(py_matrix)
            py_result = matrix2bytes(py_matrix)
            
            # Compare results
            self.assertEqual(c_result, py_result, 
                           f"Test {i+1}/3: InvSubBytes mismatch: Input={input_data.hex()}, "
                           f"C result={c_result.hex()}, Python result={py_result.hex()}")

    def test_invshiftrows(self):
        """Test the InvShiftRows transformation"""
        for i in range(3):  # Test with 3 random inputs as required
            # Generate random input block
            input_data = bytes([random.randint(0, 255) for _ in range(16)])
            input_copy = input_data[:]  # Make a copy for Python implementation
            
            # Create C buffer for the input
            c_block = ctypes.create_string_buffer(input_data)
            
            # Apply InvShiftRows in C - using the C function name
            self.rijndael.invert_shift_rows(c_block)
            c_result = bytes(c_block)[:16]
            
            # Apply InvShiftRows in Python
            # Convert byte array to matrix for Python implementation
            py_matrix = bytes2matrix(input_copy)
            inv_shift_rows(py_matrix)
            py_result = matrix2bytes(py_matrix)
            
            # Compare results
            self.assertEqual(c_result, py_result, 
                           f"Test {i+1}/3: InvShiftRows mismatch: Input={input_data.hex()}, "
                           f"C result={c_result.hex()}, Python result={py_result.hex()}")

    def test_invmixcolumns(self):
        """Test the InvMixColumns transformation"""
        for i in range(3):  # Test with 3 random inputs as required
            # Generate random input block
            input_data = bytes([random.randint(0, 255) for _ in range(16)])
            input_copy = input_data[:]  # Make a copy for Python implementation
            
            # Create C buffer for the input
            c_block = ctypes.create_string_buffer(input_data)
            
            # Apply InvMixColumns in C - using the C function name
            self.rijndael.invert_mix_columns(c_block)
            c_result = bytes(c_block)[:16]
            
            # Apply InvMixColumns in Python
            # Convert byte array to matrix for Python implementation
            py_matrix = bytes2matrix(input_copy)
            inv_mix_columns(py_matrix)
            py_result = matrix2bytes(py_matrix)
            
            # Compare results
            self.assertEqual(c_result, py_result, 
                           f"Test {i+1}/3: InvMixColumns mismatch: Input={input_data.hex()}, "
                           f"C result={c_result.hex()}, Python result={py_result.hex()}")

    def test_encrypt_decrypt_full(self):
        """Test the full encryption and decryption process"""
        for i in range(3):  # Test with 3 random inputs as required
            # Generate random plaintext and key
            plaintext = bytes([random.randint(0, 255) for _ in range(16)])
            key = bytes([random.randint(0, 255) for _ in range(16)])
            
            print(f"\nTest {i+1}/3:")
            print(f"Plaintext: {plaintext.hex()}")
            print(f"Key: {key.hex()}")
            
            # Create C buffers
            c_plaintext = ctypes.create_string_buffer(plaintext)
            c_key = ctypes.create_string_buffer(key)
            
            # ENCRYPTION TEST
            
            # Encrypt using C implementation
            c_ciphertext_ptr = self.rijndael.aes_encrypt_block(c_plaintext, c_key)
            c_ciphertext = bytes([c_ciphertext_ptr[i] for i in range(16)])
            print(f"C Ciphertext: {c_ciphertext.hex()}")
            
            # Create Python AES instance and encrypt
            py_aes = AES(key)
            py_ciphertext = py_aes.encrypt_block(plaintext)
            print(f"Python Ciphertext: {py_ciphertext.hex()}")
            
            # Compare encryption results
            self.assertEqual(c_ciphertext, py_ciphertext, 
                           f"Encryption mismatch: Plaintext={plaintext.hex()}, "
                           f"Key={key.hex()}, C ciphertext={c_ciphertext.hex()}, "
                           f"Python ciphertext={py_ciphertext.hex()}")
            
            # DECRYPTION TEST
            
            # Decrypt C ciphertext using C implementation
            c_cipher_buffer = ctypes.create_string_buffer(c_ciphertext)
            c_decrypted_ptr = self.rijndael.aes_decrypt_block(c_cipher_buffer, c_key)
            c_decrypted = bytes([c_decrypted_ptr[i] for i in range(16)])
            print(f"C Decrypted: {c_decrypted.hex()}")
            
            # Decrypt Python ciphertext using Python implementation
            py_decrypted = py_aes.decrypt_block(py_ciphertext)
            print(f"Python Decrypted: {py_decrypted.hex()}")
            
            # Compare decryption results with original plaintext
            self.assertEqual(c_decrypted, plaintext, 
                           f"C Decryption mismatch: Original={plaintext.hex()}, "
                           f"Decrypted={c_decrypted.hex()}")
            
            self.assertEqual(py_decrypted, plaintext, 
                           f"Python Decryption mismatch: Original={plaintext.hex()}, "
                           f"Decrypted={py_decrypted.hex()}")
            
            # Free C allocated memory
            libc = ctypes.CDLL(None)
            libc.free.argtypes = [ctypes.c_void_p]
            libc.free(c_ciphertext_ptr)
            libc.free(c_decrypted_ptr)

if __name__ == '__main__':
    unittest.main()