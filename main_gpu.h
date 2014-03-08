#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sha1.h"

int next_password (char* current_pw, uint8_t* current_idxs, uint8_t current_len);

extern "C" void run_kernel (uint8_t *hash, char *password);
