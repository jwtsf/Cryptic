#define _POSIX_C_SOURCE 200809L
#include <tomcrypt.h>
#include "aes.h"
#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include "2-cycle_timing.h"
#include <sys/random.h>
#include <string.h>



//return random character

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

struct timespec start, end;

//This measures execution runtime
float cpu_time(int (*f)(unsigned char*  , unsigned char* , unsigned char* ,size_t, size_t, size_t), unsigned char *plaintext, unsigned char *key, unsigned char *IV,size_t plaintext_len, size_t key_len, size_t IV_len)
{
    
    clock_gettime(CLOCK_MONOTONIC_RAW, &start);

    int x = (*f)(plaintext, key, IV, plaintext_len, key_len, IV_len);

    clock_gettime(CLOCK_MONOTONIC_RAW, &end);

    const uint64_t ns = (end.tv_sec * 1000000000 + end.tv_nsec) - (start.tv_sec * 1000000000 + start.tv_nsec);
    float time_spent = ns / 1000000.0;

    return time_spent;
}


//This measures CPU cycles for encryption process
float cpu_cycles(int (*f)(unsigned char*  , unsigned char* , unsigned char* ,size_t, size_t, size_t), unsigned char *plaintext, unsigned char *key, unsigned char *IV,size_t plaintext_len, size_t key_len, size_t IV_len)
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

        int x = (*f)(plaintext, key, IV, plaintext_len, key_len, IV_len);

        temp = end_timer() - temp;
        cycles[i] = temp;
    }    
    qsort(cycles, NUM_TIMINGS, sizeof(uint64_t), compare_u64);
    rate = (float)(cycles[NUM_TIMINGS / 2] - timing_overhead) / byte_length_of_processed_data;
    free(cycles);
    return rate;   
}

//This measures throughput
float throughput(int (*f)(unsigned char*  , unsigned char* , unsigned char* ,size_t, size_t, size_t), unsigned char *plaintext, unsigned char *key, unsigned char *IV,size_t plaintext_len, size_t key_len, size_t IV_len)
{
    int byte_length_of_processed_data = plaintext_len;
    float time = cpu_time(aes, plaintext, key, IV, plaintext_len, key_len, IV_len);
    float throughput = byte_length_of_processed_data/time;
    return throughput;
}



//This measures execution runtime
int main()
{
    //retrieve BSM data
    FILE* ptr = fopen("bsm.csv", "r");
    if (ptr == NULL) {
        printf("no such file.");
        return 0;
    }

    FILE *fpt;
    fpt = fopen("Results/Libtomcrypt256-CBC2.csv", "w+");
    fprintf(fpt, "Data length, CPU cycles, Run Time, Throughput\n");

    unsigned char buffer[1038];
    while (fgets(buffer, sizeof(buffer), ptr) != NULL) {
        // Remove the newline character at the end of the line, if present
        size_t len = strlen(buffer);
        if (len > 0 && buffer[len - 1] == '\n') {
            buffer[len - 1] = '\0';
        }
        //define variables
        // Allocate memory for plaintext
        unsigned char *plaintext = malloc((len + 1) * sizeof(char));
        if (plaintext == NULL) {
            fprintf(stderr, "Memory allocation failed\n");
            fclose(ptr);
            return 1;
        }

        // Copy buffer to plaintext
        strcpy(plaintext, buffer);
        unsigned char *key =random_string_generator(32);
        unsigned char *IV = random_string_generator(16);
        size_t plaintext_len = strlen((unsigned char* )plaintext);
        size_t key_len = 32;
        size_t IV_len = 16;

        float time_spent = 1000*cpu_time(aes, plaintext, key, IV, plaintext_len, key_len, IV_len);
        float rate = cpu_cycles(aes, plaintext, key, IV, plaintext_len, key_len, IV_len);
        float Throughput = throughput(aes, plaintext, key, IV, plaintext_len, key_len, IV_len);


        //printf("Runtime: %f seconds\n", time_spent);
        printf("Speed of algorithm: %f [Clock cycles]/[Byte]\n", rate);
        printf("Runtime: %f seconds\n", time_spent);
        printf("Throughput: %f Bytes/second\n", Throughput);
        printf("Length: %ld", plaintext_len);
        printf("\n");

        // Print the string and its actual length
        printf("String: %s\n", buffer);
        printf("Key Length: %zu\n", key_len);
        printf("\n");

        fprintf(fpt, "%ld, %f, %f, %f\n", plaintext_len, rate, time_spent, Throughput);

    }
    fclose(ptr);
    return 0;

}
