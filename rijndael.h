/*
 * Name: Luo Weiting
 * Student Number: D24125441
 * Description: This header file defines the interface for an AES-128 (Rijndael) encryption and decryption library.
 * It provides functions to encrypt and decrypt 128-bit blocks using a 128-bit key, along with the other internal helper functions
 * for AES transformations and key expansion.
 */

 #ifndef RIJNDAEL_H
 #define RIJNDAEL_H
 
 #define BLOCK_ACCESS(block, row, col) (block[(row * 4) + col])
 #define BLOCK_SIZE 16

 /*
* Additional declaration
 */
 #define KEY_SIZE 16
 #define NUM_ROUNDS 10
 #define EXPANDED_KEY_SIZE (KEY_SIZE * (NUM_ROUNDS + 1))
 
 /*
  * Main encrypt/decrypt functions - the entry points to the library
  * for programs hoping to use it to encrypt or decrypt data
  */
 unsigned char *aes_encrypt_block(unsigned char *plaintext, unsigned char *key);
 unsigned char *aes_decrypt_block(unsigned char *ciphertext, unsigned char *key);
 

/*
 * Internal helper functions for AES transformations and key expansion.
 */
 /* Function prototypes for the core AES operations */
 void sub_bytes(unsigned char *block);
 void shift_rows(unsigned char *block);
 void mix_columns(unsigned char *block);
 void add_round_key(unsigned char *block, unsigned char *round_key);

 /* Function prototypes for the inverse AES operations */
 void invert_sub_bytes(unsigned char *block);
 void invert_shift_rows(unsigned char *block);
 void invert_mix_columns(unsigned char *block);
 
 /* Key expansion function prototype */
 unsigned char *expand_key(unsigned char *cipher_key);

 #endif
 