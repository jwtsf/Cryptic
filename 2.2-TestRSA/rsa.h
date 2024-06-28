#ifndef RSA_H_
#define RSA_H_


#include <stddef.h>


#define KEY_LENGTH 3072
#define HASH_LENGTH 256

int rsa(unsigned char *plaintext);

#endif /* RSA_H_ */