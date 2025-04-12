#include "crypto.h"

int verify_sha1_hash(const Byte* input_data,
                     size_t      data_length,
                     const Byte* expected_hash) {
  Byte computed_hash[SHA_DIGEST_LENGTH];

  // Compute the SHA-1 hash of the input data.
  SHA1(input_data, data_length, computed_hash);

  if (memcmp(computed_hash, expected_hash, SHA_DIGEST_LENGTH) == 0) return 1;
  else                                                              return 0;
}

int openssl_errors(EVP_CIPHER_CTX* ctx) {
  unsigned long err;
  while ((err = ERR_get_error()))
    printf("%s\n", ERR_error_string(err, NULL));
  if (ctx != NULL)
    EVP_CIPHER_CTX_free(ctx);
  return 0;
}

int decrypt_aes_256_ecb_repeated(
  const Byte* input_data,
  Byte*       output_data,
  size_t      input_len,
  const Byte* key,
  int         repetitions) {

  Byte block[16];
  int  write_len;

  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  if (!ctx)
    return openssl_errors(NULL);

  if (EVP_DecryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, key, NULL) != 1)
    return openssl_errors(ctx);

  // Disable padding since we are working with ECB mode.
  EVP_CIPHER_CTX_set_padding(ctx, 0);

  // The encrypted data is split up in blocks consisting of 16 byte chunks.
  for (size_t i = 0; i < (size_t)(input_len / 16); i++) {
    memcpy(block, (Byte*)(input_data + i * 16), 16);

    // Decrypt the block with 16 repetitions
    for (int j = 0; j < repetitions; j++) {
      if (EVP_DecryptUpdate(ctx, block, &write_len, block, 16) != 1)
        return openssl_errors(ctx);
    }

    memcpy(output_data + i * 16, block, 16);
  }

  // If the last block is smaller than 16 bytes then copy it in its encrypted form.
  if (input_len % 16 != 0) {
    const Byte* last_block = input_data + (input_len / 16) * 16;
    size_t last_block_len  = input_len % 16;

    memcpy(output_data + (input_len / 16) * 16, last_block, last_block_len);
  }

  if (EVP_DecryptFinal_ex(ctx, output_data, &write_len) != 1)
    return openssl_errors(ctx);

  EVP_CIPHER_CTX_free(ctx);

  return input_len;
}

// Pad the data to a multiple of 16 bytes.
static inline void pad_data(Byte* data, size_t* len) {
  size_t padding_len = 16 - (*len % 16);
  if (padding_len == 16)
    return;

  for (size_t i = 0; i < padding_len; i++)
      data[*len + i] = padding_len;  // PKCS#7 padding value.

  *len += padding_len;
}

int encrypt_aes_256_ecb_repeated(
  Byte*    input_data,
  Byte*    output_data,
  size_t   input_len,
  Byte*    key,
  uint32_t repetitions) {

  Byte block[16];
  int  write_len;

  pad_data(input_data, &input_len);

  // Initialize the EVP context for AES-256 encryption in ECB mode
  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  if (ctx == NULL)
    return openssl_errors(NULL);

  if (EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, key, NULL) != 1)
    return openssl_errors(ctx);

  // For each block of the input data
  for (size_t i = 0; i < (size_t)(input_len / 16); i++) {
    memcpy(block, (Byte*)(input_data + i * 16), 16);

    // 16 repetitions (encrypt the block 16 times)
    for (uint32_t j = 0; j < repetitions; j++) {
      // Encrypt the block using AES-256 in ECB mode.
      if (EVP_EncryptUpdate(ctx, block, &write_len, block, 16) != 1)
        return openssl_errors(ctx);
    }

    memcpy(output_data + i * 16, block, 16);
  }

  EVP_CIPHER_CTX_free(ctx);

  return input_len;
}
