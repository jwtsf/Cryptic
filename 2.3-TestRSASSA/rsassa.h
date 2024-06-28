#ifndef RSASSA_H
#define RSASSA_H

#include <gcrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

// Constants
#define KEY_LENGTH 2048
#define HASH_LENGTH 256

int rsaSSA(unsigned char* plaintext);

#endif // RSASSA_H
