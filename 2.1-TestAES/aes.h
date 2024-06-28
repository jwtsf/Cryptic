#ifndef AES_H_
#define AES_H_

#include <stddef.h>

int aes(unsigned char *plaintext, unsigned char *key, unsigned char *IV, size_t plaintext_len, size_t key_len, size_t IV_len);

#endif /* AES_H_ */
