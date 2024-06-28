#include "aes.h"
#include <tomcrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>


int aes(unsigned char *plaintext, unsigned char *key, unsigned char *IV, size_t plaintext_len, size_t key_len, size_t IV_len)
{
    unsigned char ciphertext[1038];  // Ensure this is large enough to hold the output ciphertext
    int err;
    symmetric_CBC cbc;

    // Register cipher
    if (register_cipher(&aes_desc) == -1)
    {
        printf("Unable to register cipher\n");
        return -1;
    }

    // Start CBC mode
    if ((err = cbc_start(
        find_cipher("aes"), 
        IV,
        key,
        key_len,  // Key length in bytes
        0,        // 0 is standard
        &cbc)) != CRYPT_OK)
    {
        printf("cbc_start error: %s\n", error_to_string(err));
        return -1;
    }

    // Encrypt plaintext
    if ((err = cbc_encrypt(
        plaintext,
        ciphertext,
        plaintext_len,
        &cbc)) != CRYPT_OK)
    {
        printf("cbc_encrypt error: %s\n", error_to_string(err));
        return -1;
    }

    // Done with CBC mode
    if ((err = cbc_done(&cbc)) != CRYPT_OK) {
        printf("cbc_done error: %s\n", error_to_string(err));
        return -1;
    }

    zeromem(key, key_len);
    zeromem(&cbc, sizeof(cbc));

    return 0;
}