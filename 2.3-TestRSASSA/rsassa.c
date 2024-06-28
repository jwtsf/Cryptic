#define _POSIX_C_SOURCE 200809L
#define HEAP_HINT NULL
#include "rsassa.h"
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include "2-cycle_timing.h"
#include <sys/random.h>
#include <string.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

int rsaSSA(unsigned char* plaintext) {
    int ret;
    RsaKey key;
    WC_RNG rng;
    byte hash[HASH_LENGTH];
    byte pSignature[KEY_LENGTH / 8];
    

    // Initialize wolfSSL
    wolfSSL_Init();

    // Initialize RSA key
    ret = wc_InitRsaKey(&key, NULL);
    if (ret != 0) {
        fprintf(stderr, "Failed to initialize RSA key: %d\n", ret);
        return -1;
    }

    // Initialize RNG
    ret = wc_InitRng(&rng);
    if (ret != 0) {
        fprintf(stderr, "Failed to initialize RNG: %d\n", ret);
        wc_FreeRsaKey(&key);
        return -1;
    }

    // Set RNG for RSA key
    ret = wc_RsaSetRNG(&key, &rng);
    if (ret != 0) {
        fprintf(stderr, "Failed to set RNG for RSA key: %d\n", ret);
        wc_FreeRsaKey(&key);
        wc_FreeRng(&rng);
        return -1;
    }

    // Generate RSA key pair
    ret = wc_MakeRsaKey(&key, KEY_LENGTH, WC_RSA_EXPONENT, &rng);
    if (ret != 0) {
        fprintf(stderr, "Failed to generate RSA key pair: %d\n", ret);
        wc_FreeRsaKey(&key);
        wc_FreeRng(&rng);
        return -1;
    }

    // Hash the message
    ret = wc_Sha256Hash((const byte*)plaintext, strlen(plaintext), hash);
    if (ret != 0) {
        fprintf(stderr, "Failed to hash message: %d\n", ret);
        wc_FreeRsaKey(&key);
        wc_FreeRng(&rng);
        return -1;
    }

    // Sign the hash using RSA-PSS
    ret = wc_rsaSSA_Sign(hash, HASH_LENGTH, pSignature, sizeof(pSignature),
                          WC_HASH_TYPE_SHA256, WC_MGF1SHA256, &key, &rng);
    if (ret <= 0) {
        fprintf(stderr, "Failed to sign hash: %d\n", ret);
        wc_FreeRsaKey(&key);
        wc_FreeRng(&rng);
        return -1;
    }


    // Clean up
    wc_FreeRsaKey(&key);
    wc_FreeRng(&rng);
    wolfSSL_Cleanup();

    return 0;
}