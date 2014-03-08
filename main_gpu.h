#include <stdio.h>
#include <string.h>

#include "sha1.h"

const char *charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVYXYZ0123456789";

int next_password (char* current_pw, uint8_t* current_idxs, uint8_t current_len);

extern "C" void run_kernel (char *hash, char *password, int max_len);
