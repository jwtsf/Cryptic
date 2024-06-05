#define _POSIX_C_SOURCE 200809L
#include <gcrypt.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include "2-cycle_timing.h"
#include <sys/random.h>
#include <string.h>

#define HASH_LENGTH 256
#define KEY_LENGTH 2048
#define HASH_ALGO GCRY_MD_SHA256

void handle_errors(const char *msg) {
    fprintf(stderr, "%s\n", msg);
    exit(EXIT_FAILURE);
}

struct generateMD{
    gcry_sexp_t rsa_keypair, rsa_params, data;

};

typedef struct generateMD Struct;

Struct retrieveMDparam(unsigned char* message){
    
    Struct msg;

    //gcry_sexp_t rsa_keypair, data, rsa_params; 
    gcry_error_t err;

    // Initialize libgcrypt
    if (!gcry_check_version(GCRYPT_VERSION)) {
        handle_errors("libgcrypt version mismatch");
    }
    // Generate RSA key pair
    err = gcry_sexp_build(&msg.rsa_params, NULL,
                          "(genkey (rsa (nbits 4:2048)))");
    if (err) handle_errors("Failed to build S-expression for RSA parameters");

    err = gcry_pk_genkey(&msg.rsa_keypair, msg.rsa_params);
    if (err) handle_errors("Failed to generate RSA key pair");

    // Message to sign
    unsigned char hash[HASH_LENGTH/8];
    gcry_md_hash_buffer(GCRY_MD_SHA256, hash, message, strlen(message));

    // Build S-expression for the data to sign
    err = gcry_sexp_build(&msg.data, NULL,
                          "(data (flags pkcs1) (hash sha256 %b))",
                          sizeof(hash), hash);
    if (err) handle_errors("Failed to build S-expression for data");

    return msg;
}

void print_sexp(const char *label, gcry_sexp_t sexp) {
    size_t length = gcry_sexp_sprint(sexp, GCRYSEXP_FMT_ADVANCED, NULL, 0);
    char *buffer = malloc(length);
    if (!buffer) handle_errors("Memory allocation failed");

    gcry_sexp_sprint(sexp, GCRYSEXP_FMT_ADVANCED, buffer, length);
    printf("%s:\n%s\n", label, buffer);
    free(buffer);
}

int rsaPSS(unsigned char* plaintext) {
    gcry_error_t err;
    gcry_sexp_t signature;

    Struct md = retrieveMDparam(plaintext);

    // Sign the data
    err = gcry_pk_sign(&signature, md.data, md.rsa_keypair);
    if (err) 
    {
        handle_errors("Failed to sign data");
    }

    // Clean up
    gcry_sexp_release(md.rsa_keypair);
    gcry_sexp_release(md.rsa_params);
    gcry_sexp_release(md.data);
    gcry_sexp_release(signature);

    return 0;
}

struct timespec start, end;

//This measures execution runtime
float cpu_time(int (*f)(unsigned char*), unsigned char *plaintext, size_t plaintext_len)
{
    float time_spent;
    uint64_t *cycles = (uint64_t *)malloc(NUM_TIMINGS * sizeof(uint64_t));
    //uint64_t temp;
    for (uint64_t i = 0; i < NUM_TIMINGS; i++){
        clock_gettime(CLOCK_MONOTONIC_RAW, &start);

        int x = (*f)(plaintext);

        clock_gettime(CLOCK_MONOTONIC_RAW, &end);
        const uint64_t ns = (end.tv_sec * 1000000000 + end.tv_nsec) - (start.tv_sec * 1000000000 + start.tv_nsec);

        cycles[i] = ns;
    }    
    qsort(cycles, NUM_TIMINGS, sizeof(uint64_t), compare_u64);
    time_spent = (float)(cycles[NUM_TIMINGS / 2])/ 1000000000.0;
    free(cycles);


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
    float time = cpu_time(rsaPSS, plaintext, plaintext_len);
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
    fpt = fopen("LibgcryptRSA-2048-PKCSV15.csv", "w+");
    fprintf(fpt, "Data length, CPU cycles, Run Time, Throughput\n");

    for (int L = 11; L < (KEY_LENGTH/8) - (2*HASH_LENGTH/8) -1 ; L=L+10)
    {

        unsigned char *plaintext = random_string_generator(L);
        size_t plaintext_len = strlen((unsigned char* )plaintext);

        
        float time_spent = cpu_time(rsaPSS, plaintext, plaintext_len);
        float rate = cpu_cycles(rsaPSS, plaintext,  plaintext_len);
        float Throughput = throughput(rsaPSS, plaintext,  plaintext_len);


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

