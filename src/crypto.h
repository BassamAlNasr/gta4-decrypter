/*
Architecture reverse engineered and documented by:
https://gtamods.com/wiki/Cryptography#GTA_IV

The encryption algorithm used for IMG, RPF, and SCO files is the Advanced
Encryption Standard (AES) and the following configuration has been picked by
Rockstar Games:

* Block size:  128 bit (16 byte)
* Key size:    256 bit (32 byte)
* Cypher mode: electronic code book (ECB)
* Repetitions: 16 times

This means that all encrypted data (the cyphertext) can be split up into 16
byte blocks and decrypted independently. Decryption is done by executing the
AES-128 decrypt routine 16 times on each data block. If the last block is
smaller than 16 bytes, it is left unencrypted in Rockstar's archives.

The 256-bit key necessary to decrypt the cyphertext can be retrieved from the
gtaiv.exe executable at the following raw file offsets:

---------------------------
| Game Version |  Offset  |
---------------------------
| 1.0.3 US     | 0xB75C9C |
---------------------------
| 1.0.4 US     | 0xB7AEF4 |
---------------------------
| 1.0.6 US     | 0xBE6540 |
---------------------------
| 1.0.7 US     | 0xBE7540 |
---------------------------
| 1.0.8 US     | 0xC95FD8 |
---------------------------
| 1.2.0.59     | 0xC5B73C |
---------------------------

and from the eflc.exe executable:

---------------------------
| Game Version |  Offset  |
---------------------------
| 1.1.1 US     | 0xC705E0 |
---------------------------
| 1.1.2 US     | 0xBEF028 |
---------------------------

The key is the same for all game versions on all platforms (PC, XBOX 360, PS3).
Use the following SHA-1 hash to verify the correctness of the retrieved key:

DE A3 75 EF 1E 6E F2 22 3A 12 21 C2 C5 75 C4 7B F1 7E FA 5E

*/

#ifndef CRYPTO_H
#define CRYPTO_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/aes.h>

#include "types.h"

// Verify that the input data computes to the expected hash value.
int verify_sha1_hash(const Byte* input_data,
                     size_t      data_length,
                     const Byte* expected_hash);

// AES 256 decryption in ECB mode with n repetitions and a predefined 16 byte
// block size encryption order.
int decrypt_aes_256_ecb_repeated(const Byte* input_data,
                                 Byte*       output_data,
                                 size_t      input_len,
                                 const Byte* key,
                                 int         repetitions);

// AES 256 encryption in ECB mode with n repetitions and a predefined 16 byte
// block size encryption order.
int encrypt_aes_256_ecb_repeated(Byte*    input_data,
                                 Byte*    output_data,
                                 size_t   input_len,
                                 Byte*    key,
                                 uint32_t repetitions);

#endif
