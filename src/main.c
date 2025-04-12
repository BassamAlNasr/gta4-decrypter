#include "hexdump.h"
#include "crypto.h"
#include "utils.h"

int usage(char** argv) {
  printf(
    "Usage:\n  %s <option>\n  options:\n"
    "  <-k> <.exe> <off>:\n"
    "    Retrieve the key from the executable <.exe> at the file offset <off>.\n"
    "  <-d> <.exe> <off> <infile> <outfile>:\n"
    "    Decrypt the file <infile> and save the decrypted file in <outfile>.\n"
    "  <-e> <.exe> <off> <infile> <outfile>:\n"
    "    Encrypt the file <infile> and save the encrypted file in <outfile>.\n\n"
    "  Example:\n"
    "  %s -d GTAIV.exe 0xff vehicles.img vehicles.img\n\n"
    "  <.exe>    is the path to \'GTAIV.exe\'.\n"
    "  <off>     is the file offset at which the encryption key resides at.\n"
    "  <infile>  is the input file.\n"
    "  <outfile> is the output file.\n",
    argv[0], argv[0]);
  return 0;
}

int retrieve_key(char* exepath, size_t off) {
  Byte expected_hash[SHA_DIGEST_LENGTH] = {0xDE, 0xA3, 0x75, 0xEF, 0x1E, 0x6E,
                                           0xF2, 0x22, 0x3A, 0x12, 0x21, 0xC2,
                                           0xC5, 0x75, 0xC4, 0x7B, 0xF1, 0x7E,
                                           0xFA, 0x5E};
  Byte* key = hexdump(off, 32, exepath);

  if (key == NULL)
    return 1;

  if (!verify_sha1_hash(key, 32, expected_hash))
    printf("FAILURE: %s: Incorrect key found at the file offset: 0x%02lX\n", exepath, off);
  print_hexdump(key, 32);

  FREE(key);

  return 0;
}

int encrypt(char* exepath, size_t off, char* infile, char* outfile) {
  size_t        ret;
  unsigned int* val;
  Byte expected_hash[SHA_DIGEST_LENGTH] = {0xDE, 0xA3, 0x75, 0xEF, 0x1E, 0x6E,
                                           0xF2, 0x22, 0x3A, 0x12, 0x21, 0xC2,
                                           0xC5, 0x75, 0xC4, 0x7B, 0xF1, 0x7E,
                                           0xFA, 0x5E};

  Byte* key = hexdump(off, 32, exepath);
  if (key == NULL)
    return 1;

  if (!verify_sha1_hash(key, 32, expected_hash)) {
    printf("FAILURE: %s: Incorrect key found at the file offset: 0x%02lX\n", exepath, off);
    print_hexdump(key, 32);
    return 1;
  }

  Crypto* unencrypted = get_file_content(infile);
  if (unencrypted == NULL) {
    printf("%s: failed to retrieve the file content.\n", infile);
    FREE(key);
    return 1;
  }

  val = (unsigned int*)unencrypted->data;
  if (*val != 0xA94E2A52)
    printf("0x%X: Incorrect magic number. The unencrypted file \'%s\' is likely"
           " already decrypted or incompatible with GTA IV.\n", *val, infile);

  Byte* encrypted_data = (Byte*)malloc((unencrypted->size)*sizeof(Byte));
  CHECK2(encrypted_data, "Memory allocation failed.");

  ret = encrypt_aes_256_ecb_repeated(unencrypted->data, encrypted_data, unencrypted->size, key, 16);
  if (ret != unencrypted->size)
    printf("The encrypted file size: %ld is not equal to the unencrypted file size: %ld.\n",
           ret, unencrypted->size);
  ret = write_buffer_to_file(outfile, encrypted_data, unencrypted->size);
  if (ret != unencrypted->size)
    printf("Failed to properly write the encrypted data to: %s", outfile);

  val = (unsigned int*)encrypted_data;
  if (*val != 0x61DD943D)
    printf("0x%X: Incorrect magic number. The encrypted file \'%s\' is likely "
           "incompatible with GTA IV.\n", *val, outfile);

  FREE(key);
  FREE(unencrypted->data);
  FREE(unencrypted);
  FREE(encrypted_data);

  return 0;
}

int decrypt(char* exepath, size_t off, char* infile, char* outfile) {
  size_t        ret;
  unsigned int* val;
  Byte expected_hash[SHA_DIGEST_LENGTH] = {0xDE, 0xA3, 0x75, 0xEF, 0x1E, 0x6E,
                                           0xF2, 0x22, 0x3A, 0x12, 0x21, 0xC2,
                                           0xC5, 0x75, 0xC4, 0x7B, 0xF1, 0x7E,
                                           0xFA, 0x5E};

  Byte* key = hexdump(off, 32, exepath);
  if (key == NULL)
    return 1;

  if (!verify_sha1_hash(key, 32, expected_hash)) {
    printf("FAILURE: %s: Incorrect key found at the file offset: 0x%02lX\n", exepath, off);
    print_hexdump(key, 32);
    return 1;
  }

  Crypto* encrypted = get_file_content(infile);
  if (encrypted == NULL) {
    printf("%s: failed to retrieve the file content.\n", infile);
    FREE(key);
    return 1;
  }

  val = (unsigned int*)encrypted->data;
  if (*val != 0x61DD943D)
    printf("0x%X: Incorrect magic number. The encrypted file \'%s\' is likely "
           "already decrypted or incompatible with GTA IV.\n", *val, infile);

  Byte* decrypted_data = (Byte*)malloc((encrypted->size)*sizeof(Byte));
  CHECK2(decrypted_data, "Memory allocation failed.");

  ret = decrypt_aes_256_ecb_repeated(encrypted->data, decrypted_data, encrypted->size, key, 16);
  if (ret != encrypted->size)
    printf("The decrypted file size: %ld is not equal to the encrypted file size: %ld.\n",
           ret, encrypted->size);
  ret = write_buffer_to_file(outfile, decrypted_data, encrypted->size);
  if (ret != encrypted->size)
    printf("Failed to properly write the decrypted data to: %s", outfile);

  val = (unsigned int*)decrypted_data;
  if (*val != 0xA94E2A52)
    printf("0x%X: Incorrect magic number. The decrypted file \'%s\' is likely "
           "incompatible with GTA IV.\n", *val, outfile);

  FREE(key);
  FREE(encrypted->data);
  FREE(encrypted);
  FREE(decrypted_data);

  return 0;
}

int main(int argc, char** argv) {
  if (argc == 4) {
    if (strcmp(argv[1], "-k"))
      return usage(argv);

    if (!is_hex(argv[3])) {
      printf("The argument: \'%s\' is not a hexadecimal value: 0x..\n", argv[3]);
      return 1;
    }

    return retrieve_key(argv[2], to_hex(argv[3]));
  }
  else if (argc == 6) {
    if (!is_hex(argv[3])) {
      printf("The argument: \'%s\' is not a hexadecimal value: 0x..\n", argv[3]);
      return 1;
    }

    if (!strcmp(argv[1], "-e"))
      return encrypt(argv[2], to_hex(argv[3]), argv[4], argv[5]);
    else if (!strcmp(argv[1], "-d"))
      return decrypt(argv[2], to_hex(argv[3]), argv[4], argv[5]);
  }

  usage(argv);

  return 0;
}
