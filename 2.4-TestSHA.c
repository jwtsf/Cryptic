#define _POSIX_C_SOURCE 200809L
#include <tomcrypt.h>
#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include "2-cycle_timing.h"
#include <sys/random.h>

int file_hashing()
{
    int idx, err;
    unsigned long len;
    unsigned char out[256];

    if (register_hash(&sha256_desc) == -1)
    {
        printf("Error resgistering hash\n");
        return -1;
    }

    idx = find_hash("sha256");

    len = sizeof(out);

    FILE* ptr = fopen("bsm.csv", "r");

    if ((err = hash_filehandle(
        idx,
        ptr,
        out,
        &len
    )) != CRYPT_OK)
    {
        printf("Error in hashing file %s", error_to_string(err));
    }

    printf("SHA-256 hash: ");
    for (int i = 0; i < sizeof(out); i++) {
        printf("%02x", out[i]);
    }
    printf("\n");

    return 0;
}

int msg_hashing(unsigned char* plaintext)
{
    int idx, err;
    unsigned long len;
    unsigned char hash[64];
    size_t plaintext_len = strlen((unsigned char* )plaintext);

    if (register_hash(&sha3_512_desc) == -1)
    {
        printf("Error resgistering hash\n");
        return -1;
    }

    idx = find_hash("sha3-512");

    len = sizeof(hash);

    if ((err = hash_memory(
        idx,
        plaintext,
        plaintext_len,
        hash,
        &len
    )) != CRYPT_OK)
    {
        printf("Error hashing data: %s\n", error_to_string(err));
        return -1;
    }

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
    float time = cpu_time(msg_hashing, plaintext, plaintext_len);
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
    fpt = fopen("Libtomcrypt-SHA3-512.csv", "w+");
    fprintf(fpt, "Data length, CPU cycles, Run Time, Throughput\n");

    unsigned char buffer[1038];
    // Read and discard the first line
    if (fgets(buffer, sizeof(buffer),ptr) == NULL) {
        perror("Error reading file");
        fclose(ptr);
        return EXIT_FAILURE;
    }

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
        size_t plaintext_len = strlen((unsigned char* )plaintext);


        float time_spent = 1000000*cpu_time(msg_hashing, plaintext, plaintext_len);
        float rate = cpu_cycles(msg_hashing, plaintext,plaintext_len);
        float Throughput = throughput(msg_hashing, plaintext, plaintext_len);


        //printf("Runtime: %f seconds\n", time_spent);
        printf("Speed of algorithm: %f [Clock cycles]/[Byte]\n", rate);
        printf("Runtime: %f seconds\n", time_spent);
        printf("Throughput: %f Bytes/second\n", Throughput);
        printf("Length: %ld", plaintext_len);
        printf("\n");

        // Print the string and its actual length
        printf("String: %s\n", buffer);
        printf("\n");

        fprintf(fpt, "%ld, %f, %f, %f\n", plaintext_len, rate, time_spent, Throughput);

    }
    fclose(ptr);
    return 0;

}