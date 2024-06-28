#define _POSIX_C_SOURCE 200809L
#define HEAP_HINT NULL
#include "rsassa.h"
#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include "2-cycle_timing.h"
#include <sys/random.h>
#include <string.h>


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
    float time = cpu_time(rsaSSA, plaintext, plaintext_len);
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
    return str;
}

//This measures execution runtime
int main()
{
    FILE *fpt;
    fpt = fopen("Results/LibgcryptRSA-2048-PKCSV15.csv", "w+");
    fprintf(fpt, "Data length, CPU cycles, Run Time, Throughput\n");

    for (int L = 11; L < (KEY_LENGTH/8) - (2*HASH_LENGTH/8) -1 ; L=L+10)
    {

        unsigned char *plaintext = random_string_generator(L);
        size_t plaintext_len = strlen((unsigned char* )plaintext);

        
        float time_spent = cpu_time(rsaSSA, plaintext, plaintext_len);
        float rate = cpu_cycles(rsaSSA, plaintext,  plaintext_len);
        float Throughput = throughput(rsaSSA, plaintext,  plaintext_len);


        //printf("Runtime: %f seconds\n", time_spent);
        printf("Speed of algorithm: %f [Clock cycles]/[Byte]\n", rate);
        printf("Runtime: %f seconds\n", time_spent);
        printf("Throughput: %f Bytes/second\n", Throughput);
        printf("Length: %ld", plaintext_len);
        printf("\n");
        
        printf("\n");

        fprintf(fpt, "%ld, %f, %f, %f\n", plaintext_len, rate, time_spent, Throughput);
    }

    //}
    fclose(fpt);
    return 0;

}

