#define _POSIX_C_SOURCE 200809L
#define HEAP_HINT NULL
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include "2-cycle_timing.h"
#include <sys/random.h>
#include <string.h>
 
#define KEY_LENGTH 3072
#define HASH_LENGTH 256

int rsa2048(unsigned char* in) {
    WC_RNG rng;
    RsaKey key;
    byte out[256];
    int ret;

    ret = wc_InitRng(&rng);

 #ifdef WC_RSA_BLINDING                                                                                                             
         ret = wc_RsaSetRNG(&key, &rng);                                          
        /* check ret is not less than 0 */                                                                                                                                               
 #endif
    /* Initialize WolfSSL */
    wolfSSL_Init();


    /* Generate RSA key pair */
    if ((ret = wc_InitRsaKey(&key, HEAP_HINT)) != 0) {
        printf("Error initializing RSA key: %d\n", ret);
        return -1;
    }

    if ((ret = wc_MakeRsaKey(&key, 3072, WC_RSA_EXPONENT, &rng)) != 0) {
        printf("Error generating RSA key pair: %d\n", ret);
        return -1;
    }

    /* Perform RSA encryption with OAEP padding */
    ret = wc_RsaPublicEncrypt_ex(in, sizeof(in), out, sizeof(out), &key, &rng, WC_RSA_OAEP_PAD, WC_HASH_TYPE_SHA256, WC_MGF1SHA1, NULL, 0);
    if (ret < 0) {
    printf("Encryption failed");
    }

    /* Clean up */
    wc_FreeRsaKey(&key);
    wolfSSL_Cleanup();

    return 0;
}

struct timespec start, end;

//This measures execution runtime
float cpu_time(int (*f)(unsigned char*), unsigned char *plaintext, size_t plaintext_len)
{
    clock_gettime(CLOCK_MONOTONIC_RAW, &start);

    int x = (*f)(plaintext);

    clock_gettime(CLOCK_MONOTONIC_RAW, &end);

    const uint64_t ns = (end.tv_sec * 1000000000 + end.tv_nsec) - (start.tv_sec * 1000000000 + start.tv_nsec);
    float time_spent = ns / 1000000000.0;

    return time_spent;


    return time_spent;
}


//This measures CPU cycles for encryption process
float cpu_cycles(int (*f)(unsigned char*), unsigned char *plaintext, size_t plaintext_len)
{

    //Measure the overhead of timing

    uint64_t timing_overhead;
    timing_overhead = measure_overhead();
    printf("Timing overhead: %lu clock cycles\n", timing_overhead);


    //Compute the length of processed data 

    int byte_length_of_processed_data = plaintext_len;
    float rate;

    uint64_t *cycles = (uint64_t *)malloc(NUM_TIMINGS * sizeof(uint64_t));
    uint64_t temp;
    for (uint64_t i = 0; i < NUM_TIMINGS; i++){
        temp = start_timer();

        int x = (*f)(plaintext);

        temp = end_timer() - temp;
        cycles[i] = temp;
    }    
    qsort(cycles, NUM_TIMINGS, sizeof(uint64_t), compare_u64);
    rate = (float)(cycles[NUM_TIMINGS / 2] - timing_overhead) / byte_length_of_processed_data;
    free(cycles);
    return rate;   
}

//This measures throughput
float throughput(int (*f)(unsigned char* ), unsigned char *plaintext, size_t plaintext_len)
{
    int byte_length_of_processed_data = plaintext_len;
    float time = cpu_time(rsa2048, plaintext, plaintext_len);
    float throughput = byte_length_of_processed_data/time;
    return throughput;
}

unsigned char random_char_selector(int x)
{
    unsigned char charset[]= "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    return charset[x];
}

//return random string

unsigned char*  random_string_generator(int strlen)
{
    unsigned char *str = (unsigned char* )malloc((strlen + 1) * sizeof(char));
    if (!str) {
        fprintf(stderr, "Memory allocation failed\n");
        exit(1);
    }
    srand(time(NULL));
    //unsigned char str[strlen];
    int x;
    int i;
    for ( i=0; i<strlen-1 ; i++)
    {
        x = rand()%62;
        str[i] = random_char_selector(x);
    }
    str[i] = '\0';
    //printf("%s\n", str);
    return str;
}

//This measures execution runtime
int main()
{
    FILE *fpt;
    fpt = fopen("WolfsslRSA-3072-OAEP.csv", "w+");
    fprintf(fpt, "Data length, CPU cycles, Run Time, Throughput\n");

    for (int L = 11; L < (KEY_LENGTH/8) - (2*HASH_LENGTH/8) -1 ; L=L+10)
    {

        unsigned char *plaintext = random_string_generator(L);
        size_t plaintext_len = strlen((unsigned char* )plaintext);

        
        float time_spent = cpu_time(rsa2048, plaintext, plaintext_len);
        float rate = cpu_cycles(rsa2048, plaintext,  plaintext_len);
        float Throughput = throughput(rsa2048, plaintext,  plaintext_len);


        //printf("Runtime: %f seconds\n", time_spent);
        printf("Speed of algorithm: %f [Clock cycles]/[Byte]\n", rate);
        printf("Runtime: %f seconds\n", time_spent);
        printf("Throughput: %f Bytes/second\n", Throughput);
        printf("Length: %ld", plaintext_len);
        printf("\n");
        


        // Print the string and its actual length
        //printf("String: %s\n", buffer);
        printf("\n");

        fprintf(fpt, "%ld, %f, %f, %f\n", plaintext_len, rate, time_spent, Throughput);
    }

    //}
    fclose(fpt);
    return 0;

}
