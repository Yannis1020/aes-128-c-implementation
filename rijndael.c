/*
 * Name: Luo Weiting
 * Student Number: D24125441
 * Description: This file implements the AES-128 (Rijndael) encryption and decryption algorithm.
 */

 #include <stdlib.h>
 #include <string.h>
 #include "rijndael.h"
 
 /* S-box and inverse S-box for SubBytes and InvSubBytes */
 static const unsigned char s_box[256] = {
   0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
   0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
   0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
   0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
   0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
   0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
   0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
   0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
   0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
   0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
   0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
   0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
   0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
   0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
   0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
   0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
 };
 
 static const unsigned char inv_s_box[256] = {
   0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
   0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
   0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
   0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
   0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
   0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
   0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
   0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
   0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
   0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
   0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
   0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
   0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
   0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
   0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
   0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
 };
 
 /* Round constants for key expansion */
 static const unsigned char rcon[10] = {
   0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
 };
 
 /*
  * Helper Functions for Galois Field Operations
  */
 
 /* Helper function to multiply by 2 in GF(2^8) */
 static unsigned char galois_multiply_by_2(unsigned char value) {
   return (value << 1) ^ (((value >> 7) & 1) * 0x1b);
 }
 
 /* Helper function to multiply by 3 in GF(2^8) */
 static unsigned char galois_multiply_by_3(unsigned char value) {
   return galois_multiply_by_2(value) ^ value;
 }
 
 /* Helper function to multiply by 9 in GF(2^8) */
 static unsigned char galois_multiply_by_9(unsigned char value) {
   unsigned char result = galois_multiply_by_2(galois_multiply_by_2(galois_multiply_by_2(value)));
   return result ^ value;
 }
 
 /* Helper function to multiply by 11 (0x0b) in GF(2^8) */
 static unsigned char galois_multiply_by_11(unsigned char value) {
   unsigned char times_2 = galois_multiply_by_2(value);
   unsigned char times_8 = galois_multiply_by_2(galois_multiply_by_2(times_2));
   return times_8 ^ times_2 ^ value;
 }
 
 /* Helper function to multiply by 13 (0x0d) in GF(2^8) */
 static unsigned char galois_multiply_by_13(unsigned char value) {
   unsigned char times_2 = galois_multiply_by_2(value);
   unsigned char times_4 = galois_multiply_by_2(times_2);
   unsigned char times_8 = galois_multiply_by_2(times_4);
   return times_8 ^ times_4 ^ value;
 }
 
 /* Helper function to multiply by 14 (0x0e) in GF(2^8) */
 static unsigned char galois_multiply_by_14(unsigned char value) {
   unsigned char times_2 = galois_multiply_by_2(value);
   unsigned char times_4 = galois_multiply_by_2(times_2);
   unsigned char times_8 = galois_multiply_by_2(times_4);
   return times_8 ^ times_4 ^ times_2;
 }
 
 /*
  * Operations used when encrypting a block
  */
 void sub_bytes(unsigned char *block) {
   for (int i = 0; i < BLOCK_SIZE; i++) {
     block[i] = s_box[block[i]];
   }
 }
 
 /* 
  * Fixed shift_rows - To match Python's column-major layout, we need to adjust how
  * we access elements. The Python implementation applies shifts to columns, where 
  * each column represents a "word" of the AES state.
  */
 void shift_rows(unsigned char *block) {
   unsigned char temp;
   
   /* The indices in our flat array need to match Python's column-major shifts */
   
   /* Row 1: Shift left by 1 (bytes 1, 5, 9, 13 in column-major order) */
   temp = BLOCK_ACCESS(block, 0, 1);
   BLOCK_ACCESS(block, 0, 1) = BLOCK_ACCESS(block, 1, 1);
   BLOCK_ACCESS(block, 1, 1) = BLOCK_ACCESS(block, 2, 1);
   BLOCK_ACCESS(block, 2, 1) = BLOCK_ACCESS(block, 3, 1);
   BLOCK_ACCESS(block, 3, 1) = temp;
   
   /* Row 2: Shift left by 2 (bytes 2, 6, 10, 14 in column-major order) */
   temp = BLOCK_ACCESS(block, 0, 2);
   BLOCK_ACCESS(block, 0, 2) = BLOCK_ACCESS(block, 2, 2);
   BLOCK_ACCESS(block, 2, 2) = temp;
   
   temp = BLOCK_ACCESS(block, 1, 2);
   BLOCK_ACCESS(block, 1, 2) = BLOCK_ACCESS(block, 3, 2);
   BLOCK_ACCESS(block, 3, 2) = temp;
   
   /* Row 3: Shift left by 3 (or right by 1) (bytes 3, 7, 11, 15 in column-major order) */
   temp = BLOCK_ACCESS(block, 0, 3);
   BLOCK_ACCESS(block, 0, 3) = BLOCK_ACCESS(block, 3, 3);
   BLOCK_ACCESS(block, 3, 3) = BLOCK_ACCESS(block, 2, 3);
   BLOCK_ACCESS(block, 2, 3) = BLOCK_ACCESS(block, 1, 3);
   BLOCK_ACCESS(block, 1, 3) = temp;
 }
 
 /* 
  * Fixed mix_columns - Align with Python implementation's column approach.
  * The Python implementation applies the MixColumns to each column of the state matrix.
  */
 void mix_columns(unsigned char *block) {
   unsigned char temp[4];
   
   for (int col = 0; col < 4; col++) {
     /* Save the original column values */
     for (int row = 0; row < 4; row++) {
       temp[row] = BLOCK_ACCESS(block, col, row);
     }
     
     /* Calculate the new values for each row in this column */
     BLOCK_ACCESS(block, col, 0) = galois_multiply_by_2(temp[0]) ^ 
                                  galois_multiply_by_3(temp[1]) ^ 
                                  temp[2] ^ temp[3];
                                  
     BLOCK_ACCESS(block, col, 1) = temp[0] ^ 
                                  galois_multiply_by_2(temp[1]) ^ 
                                  galois_multiply_by_3(temp[2]) ^ 
                                  temp[3];
                                  
     BLOCK_ACCESS(block, col, 2) = temp[0] ^ temp[1] ^ 
                                  galois_multiply_by_2(temp[2]) ^ 
                                  galois_multiply_by_3(temp[3]);
                                  
     BLOCK_ACCESS(block, col, 3) = galois_multiply_by_3(temp[0]) ^ 
                                  temp[1] ^ temp[2] ^ 
                                  galois_multiply_by_2(temp[3]);
   }
 }
 
 /*
  * Operations used when decrypting a block
  */
 void invert_sub_bytes(unsigned char *block) {
   for (int i = 0; i < BLOCK_SIZE; i++) {
     block[i] = inv_s_box[block[i]];
   }
 }
 
 /* 
  * Fixed invert_shift_rows - Match Python implementation's column-major approach
  */
 void invert_shift_rows(unsigned char *block) {
   unsigned char temp;
   
   /* Row 1: Shift right by 1 */
   temp = BLOCK_ACCESS(block, 3, 1);
   BLOCK_ACCESS(block, 3, 1) = BLOCK_ACCESS(block, 2, 1);
   BLOCK_ACCESS(block, 2, 1) = BLOCK_ACCESS(block, 1, 1);
   BLOCK_ACCESS(block, 1, 1) = BLOCK_ACCESS(block, 0, 1);
   BLOCK_ACCESS(block, 0, 1) = temp;
   
   /* Row 2: Shift right by 2 */
   temp = BLOCK_ACCESS(block, 0, 2);
   BLOCK_ACCESS(block, 0, 2) = BLOCK_ACCESS(block, 2, 2);
   BLOCK_ACCESS(block, 2, 2) = temp;
   
   temp = BLOCK_ACCESS(block, 1, 2);
   BLOCK_ACCESS(block, 1, 2) = BLOCK_ACCESS(block, 3, 2);
   BLOCK_ACCESS(block, 3, 2) = temp;
   
   /* Row 3: Shift right by 3 (or left by 1) */
   temp = BLOCK_ACCESS(block, 1, 3);
   BLOCK_ACCESS(block, 1, 3) = BLOCK_ACCESS(block, 2, 3);
   BLOCK_ACCESS(block, 2, 3) = BLOCK_ACCESS(block, 3, 3);
   BLOCK_ACCESS(block, 3, 3) = BLOCK_ACCESS(block, 0, 3);
   BLOCK_ACCESS(block, 0, 3) = temp;
 }
 
 /* 
  * Fixed invert_mix_columns - Match Python implementation's column approach
  */
 void invert_mix_columns(unsigned char *block) {
   unsigned char temp[4];
   
   for (int col = 0; col < 4; col++) {
     /* Save the original column values */
     for (int row = 0; row < 4; row++) {
       temp[row] = BLOCK_ACCESS(block, col, row);
     }
     
     /* Calculate the new values for each row in this column */
     BLOCK_ACCESS(block, col, 0) = galois_multiply_by_14(temp[0]) ^ 
                                  galois_multiply_by_11(temp[1]) ^ 
                                  galois_multiply_by_13(temp[2]) ^ 
                                  galois_multiply_by_9(temp[3]);
                                  
     BLOCK_ACCESS(block, col, 1) = galois_multiply_by_9(temp[0]) ^ 
                                  galois_multiply_by_14(temp[1]) ^ 
                                  galois_multiply_by_11(temp[2]) ^ 
                                  galois_multiply_by_13(temp[3]);
                                  
     BLOCK_ACCESS(block, col, 2) = galois_multiply_by_13(temp[0]) ^ 
                                  galois_multiply_by_9(temp[1]) ^ 
                                  galois_multiply_by_14(temp[2]) ^ 
                                  galois_multiply_by_11(temp[3]);
                                  
     BLOCK_ACCESS(block, col, 3) = galois_multiply_by_11(temp[0]) ^ 
                                  galois_multiply_by_13(temp[1]) ^ 
                                  galois_multiply_by_9(temp[2]) ^ 
                                  galois_multiply_by_14(temp[3]);
   }
 }
 
 /*
  * Fixed add_round_key - Match Python implementation's approach
  */
 void add_round_key(unsigned char *block, unsigned char *round_key) {
   for (int i = 0; i < BLOCK_SIZE; i++) {
     block[i] ^= round_key[i];
   }
 }
 
 /*
  * Fixed expand_key - Match Python implementation's key expansion
  * The key_words need to be arranged in a format compatible with the Python implementation
  */
 unsigned char *expand_key(unsigned char *cipher_key) {
   /* Allocate memory for all round keys */
   unsigned char *expanded_key = (unsigned char *)malloc(EXPANDED_KEY_SIZE);
   if (!expanded_key) {
     return NULL;  /* Memory allocation failed */
   }
   
   /* Copy the first round key (the original key) */
   memcpy(expanded_key, cipher_key, KEY_SIZE);
   
   /* Generate the remaining round keys */
   for (int i = 1; i <= NUM_ROUNDS; i++) {
     /* Start of the current round key in the expanded key */
     unsigned char *prev_key = expanded_key + (i - 1) * KEY_SIZE;
     unsigned char *current_key = expanded_key + i * KEY_SIZE;
     
     /* Take the last 4 bytes of the previous round key */
     unsigned char temp[4];
     temp[0] = prev_key[12];
     temp[1] = prev_key[13];
     temp[2] = prev_key[14];
     temp[3] = prev_key[15];
     
     /* Perform the key schedule core on the last word */
     
     /* Rotate word (circular left shift) */
     unsigned char t = temp[0];
     temp[0] = temp[1];
     temp[1] = temp[2];
     temp[2] = temp[3];
     temp[3] = t;
     
     /* Apply S-box to all bytes */
     for (int j = 0; j < 4; j++) {
       temp[j] = s_box[temp[j]];
     }
     
     /* XOR with round constant */
     temp[0] ^= rcon[i-1];
     
     /* Generate the first word of the current round key */
     for (int j = 0; j < 4; j++) {
       current_key[j] = prev_key[j] ^ temp[j];
     }
     
     /* Generate the remaining three words */
     for (int j = 4; j < 16; j++) {
       current_key[j] = prev_key[j] ^ current_key[j-4];
     }
   }
   
   return expanded_key;
 }
 
 /*
  * The implementations of the functions declared in the
  * header file should go here
  */
 unsigned char *aes_encrypt_block(unsigned char *plaintext, unsigned char *key) {
   /* Allocate memory for the output ciphertext */
   unsigned char *output = (unsigned char *)malloc(BLOCK_SIZE);
   if (!output) {
     return NULL;  /* Memory allocation failed */
   }
   
   /* Copy the plaintext to the output buffer (to avoid modifying the original) */
   memcpy(output, plaintext, BLOCK_SIZE);
   
   /* Generate the round keys */
   unsigned char *expanded_key = expand_key(key);
   if (!expanded_key) {
     free(output);
     return NULL;  /* Key expansion failed */
   }
   
   /* Initial round: AddRoundKey only */
   add_round_key(output, expanded_key);
   
   /* Main rounds (1-9) */
   for (int round = 1; round < NUM_ROUNDS; round++) {
     sub_bytes(output);
     shift_rows(output);
     mix_columns(output);
     add_round_key(output, expanded_key + (round * KEY_SIZE));
   }
   
   /* Final round (no MixColumns) */
   sub_bytes(output);
   shift_rows(output);
   add_round_key(output, expanded_key + (NUM_ROUNDS * KEY_SIZE));
   
   /* Free the expanded key */
   free(expanded_key);
   
   return output;
 }
 
 unsigned char *aes_decrypt_block(unsigned char *ciphertext, unsigned char *key) {
   /* Allocate memory for the output plaintext */
   unsigned char *output = (unsigned char *)malloc(BLOCK_SIZE);
   if (!output) {
     return NULL;  /* Memory allocation failed */
   }
   
   /* Copy the ciphertext to the output buffer (to avoid modifying the original) */
   memcpy(output, ciphertext, BLOCK_SIZE);
   
   /* Generate the round keys */
   unsigned char *expanded_key = expand_key(key);
   if (!expanded_key) {
     free(output);
     return NULL;  /* Key expansion failed */
   }
   
   /* Initial round: AddRoundKey only */
   add_round_key(output, expanded_key + (NUM_ROUNDS * KEY_SIZE));
   
   /* Main rounds (9-1) */
   for (int round = NUM_ROUNDS - 1; round > 0; round--) {
     invert_shift_rows(output);
     invert_sub_bytes(output);
     add_round_key(output, expanded_key + (round * KEY_SIZE));
     invert_mix_columns(output);
   }
   
   /* Final round (no InvMixColumns) */
   invert_shift_rows(output);
   invert_sub_bytes(output);
   add_round_key(output, expanded_key);
   
   /* Free the expanded key */
   free(expanded_key);
   
   return output;
 }