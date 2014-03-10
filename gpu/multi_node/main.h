#include <stdio.h>
#include <mpi.h>
#include <string.h>

#include "sha1_gpu.h"

#define MAX(a,b) (((a)>(b))?(a):(b))
#define MIN(a,b) (((a)<(b))?(a):(b))

#define MASTER 0
#define MAX_LENGTH 6


void run_master(int me, int nprocs, int argc, char** argv);
void run_worker(int me, int nprocs);

extern "C" void call_kernel (uint8_t *prepend, char *charset);
//int next_password(char* current_pw, uint8_t* current_idxs, uint8_t current_len);
//int crack_password_permutations(uint8_t* hash_ptr, int current_len, char* solution, int ends_with);
//int crack_password(uint8_t* hash, char* solution, int ends_with);
