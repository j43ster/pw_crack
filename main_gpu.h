#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sha1.h"

int next_password (char* current_pw, uint8_t* current_idxs, uint8_t current_len);

extern "C" void run_kernel (char *password, int pw_len, const char *charset, int num_chars);
