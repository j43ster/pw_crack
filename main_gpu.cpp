#include "main_gpu.h"

const char *charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVYXYZ0123456789";

int main(int argc, char** argv) {

   sha1nfo hash;
   uint8_t *hash_ptr;
   const char *pw = "64f";
   int i;
   uint8_t start_len = 1;
   uint8_t end_len = 3;
   char *password = (char *)malloc (end_len + 1);

   sha1_init(&hash);
   sha1_write(&hash, pw, strlen(pw)); 
   hash_ptr = sha1_result(&hash);
   printHash(hash_ptr);

   run_kernel (hash_ptr, password);
   
   printf ("Cracked Password: %s\n", password);
   return 0;
}
