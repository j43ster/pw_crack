#include "main.h"
const char *charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

int id = 1;
int my_id;


int main(int argc, char *argv[]) {
  int me, nprocs;

  MPI_Init(&argc, &argv);
  MPI_Comm_size(MPI_COMM_WORLD, &nprocs);
  MPI_Comm_rank(MPI_COMM_WORLD, &me);
  MPI_Barrier(MPI_COMM_WORLD);
  
  my_id = me;

  run_worker(me, nprocs);
  
  MPI_Barrier(MPI_COMM_WORLD);
  MPI_Finalize();
}

void run_worker(int me, int nprocs) {

   char solution[100];
   uint8_t hash_ptr[HASH_LENGTH + 1];
   int num_workers = nprocs;
   int i, j;

   // compute work needed by this node
   int domain = strlen(charset);
   int work_per_node = (int)(((float)domain / num_workers) + 0.99);
   int my_start = MIN(domain, work_per_node * me);
   int my_end = MIN(domain, my_start + work_per_node);
   printf("domain: %d, work_per_node: %d\n", domain, work_per_node);
   printf("%d here: computing <%d, %d>: %d\n", me, my_start, my_end, my_end - my_start);

  uint8_t prepend[NUM_PREPEND];

  for (i = 0; i < strlen(charset); i++) {
    for (j = my_start; j < my_end; j++) {
      prepend[0] = j;
      prepend[1] = i;
      call_kernel (prepend, (char *)charset);
    }
  }

   // distributed cpu version
   //while there is work
   //for (i = my_start; i < my_end; i++) {
      // compute work and send back results
     // crack_password(hash_ptr, solution, i); 
   //}
}

/*int crack_password(uint8_t* hash_ptr, char* solution, int ends_with) {

   uint8_t start_len = 1;
   uint8_t end_len = MAX_LENGTH;
   uint8_t current_len = 1;

   for (current_len = start_len; current_len <= end_len; current_len++) {

      if (crack_password_permutations(hash_ptr, current_len, solution, ends_with)) {
         solution[current_len] = 0;
         printf("solution is: %s\n", solution);
         return 1;
      }
   }

   return 0;
}

int crack_password_permutations(uint8_t* hash_ptr, int current_len, char* solution, int ends_with) {

   sha1nfo current_hash;
   uint8_t *current_hash_ptr;
   char    current_pw[100];
   uint8_t current_idxs[100]; // index into charset
   int i;

   // initialize
   for (i = 0; i < 100; i++) {
      current_pw[i] = 0;
      current_idxs[i] = 0;
   }

   for (i = 0; i < current_len; i++) {
      current_pw[0] = charset[0];
   }
   
   current_pw[current_len-1] = charset[ends_with];
   //if (my_id == id)
    //  printf("start: %s\n", current_pw);

   do { // loops over password space for given password length
      //printf("%s\n", current_pw);
      // hash current password attempt
      sha1_init(&current_hash);
      sha1_write(&current_hash, current_pw, strlen(current_pw));
      current_hash_ptr = sha1_result(&current_hash);

      // check if equal to hash we are cracking
      if (strncmp((char *)hash_ptr, (char *)current_hash_ptr, HASH_LENGTH) == 0) {

         strncpy(solution, current_pw, current_len);

         printf("found a password with a matching hash!\n");
         printHash(current_hash_ptr);
         printf("password is: %s\n", current_pw);

         return 1;
      }
   } while (next_password(current_pw, current_idxs, current_len - 1));

   return 0;
}

int next_password(char* current_pw, uint8_t* current_idxs, uint8_t current_len) {

   int chk_len = current_len - 1;
   int done = 0;

   //if (my_id == id)
   //   printf("%s -> ", current_pw);

   while (!done) {

      if (chk_len == -1) {
         //if (my_id == id)
         //   printf("breaking\n");
         return 0;
      }

      if (current_pw[chk_len] != charset[strlen(charset)-1]) {
         //printf("incrementing current char\n");
         current_idxs[chk_len]++;
         current_pw[chk_len] = charset[current_idxs[chk_len]];
        
         //if (my_id == id)
            //printf("%s\n", current_pw);
   
         return 1;
      }
      else {
         //printf("reinitializing current char\n");
         current_pw[chk_len] = charset[0];
         current_idxs[chk_len] = 0;
         chk_len--;
      } 
   }

   return 0;
}*/
