#include "main_gpu.h"

int main(int argc, char** argv) {

   sha1nfo hash;
   uint8_t *hash_ptr;
   const char *pw = "64f";
   int i;
   uint8_t start_len = 1;
   uint8_t end_len = 3;

   sha1_init(&hash);
   sha1_write(&hash, pw, strlen(pw)); 
   hash_ptr = sha1_result(&hash);
   printHash(hash_ptr);

   sha1nfo current_hash;
   uint8_t *current_hash_ptr;
   char    current_pw[100];
   uint8_t current_idxs[100]; // index into charset
   uint8_t current_len = 1;

   for (current_len = start_len; current_len <= end_len; current_len++) {

      // initialize
      for (i = 0; i < 100; i++) {
         current_pw[i] = 0;
         current_idxs[i] = 0;
      }

      for (i = 0; i < current_len; i++) {
         current_pw[0] = charset[0];
      }

      do { // loops over password space for given password length
         // hash current password attempt
         sha1_init(&current_hash);
         sha1_write(&current_hash, current_pw, strlen(current_pw));
         current_hash_ptr = sha1_result(&current_hash);

         // check if equal to hash we are cracking
         if (strncmp((char *)hash_ptr, (char *)current_hash_ptr, BLOCK_LENGTH) == 0) {
            printf("found a password with a matching hash!\n");
            printHash(current_hash_ptr);
            printf("password is: %s\n", current_pw);
         }

      } while (next_password(current_pw, current_idxs, current_len));
   }
}

int next_password(char* current_pw, uint8_t* current_idxs, uint8_t current_len) {

   int chk_len = current_len - 1;
   int done = 0;

   while (!done) {

      if (chk_len == -1) {
         return 0;
      }

      if (current_pw[chk_len] != charset[61]) {
         //printf("incrementing current char\n");
         current_idxs[chk_len]++;
         current_pw[chk_len] = charset[current_idxs[chk_len]];
         return 1;
      }
      else {
         //printf("reinitializing current char\n");
         current_pw[chk_len] = charset[0];
         current_idxs[chk_len] = 0;
         chk_len--;
      } 
   }

   return 1;
}
