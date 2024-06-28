#ifndef SHA_H_
#define SHA_H_

#include <stddef.h>

int msg_hashing(unsigned char* plaintext);
int file_hashing();

#endif /* SHA_H_ */