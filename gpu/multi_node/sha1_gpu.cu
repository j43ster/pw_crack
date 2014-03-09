#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sha1_gpu.h"


#define BLOCKS 512
#define MAX_BLOCKS 64000

#define HANDLE_ERROR( err ) (handle_error( err, __FILE__, __LINE__ ))

const char *charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVYXYZ0123456789";

__device__ const uint8_t sha1InitState[] = {
  0x01,0x23,0x45,0x67, // H0
  0x89,0xab,0xcd,0xef, // H1
  0xfe,0xdc,0xba,0x98, // H2
  0x76,0x54,0x32,0x10, // H3
  0xf0,0xe1,0xd2,0xc3  // H4
};

__device__ unsigned long powers[MAX_LEN];

// ----------------------------------------------------------------------------
//                    GPU FUNCTIONS
// ----------------------------------------------------------------------------

__device__ void d_sha1_init(sha1nfo *s) {
  memcpy(s->state.b,sha1InitState,HASH_LENGTH);
  s->byteCount = 0;
  s->bufferOffset = 0;
}

__device__ uint32_t d_sha1_rol32(uint32_t number, uint8_t bits) {
  return ((number << bits) | (number >> (32-bits)));
}

__device__ void d_sha1_hashBlock(sha1nfo *s) {
  uint8_t i;
  uint32_t a,b,c,d,e,t;

  a=s->state.w[0];
  b=s->state.w[1];
  c=s->state.w[2];
  d=s->state.w[3];
  e=s->state.w[4];
  for (i=0; i<80; i++) {
    if (i>=16) {
      t = s->buffer.w[(i+13)&15] ^ s->buffer.w[(i+8)&15] ^ s->buffer.w[(i+2)&15] ^ s->buffer.w[i&15];
      s->buffer.w[i&15] = d_sha1_rol32(t,1);
    }
    if (i<20) {
      t = (d ^ (b & (c ^ d))) + SHA1_K0;
    } else if (i<40) {
      t = (b ^ c ^ d) + SHA1_K20;
    } else if (i<60) {
      t = ((b & c) | (d & (b | c))) + SHA1_K40;
    } else {
      t = (b ^ c ^ d) + SHA1_K60;
    }
    t+=d_sha1_rol32(a,5) + e + s->buffer.w[i&15];
    e=d;
    d=c;
    c=d_sha1_rol32(b,30);
    b=a;
    a=t;
  }
  s->state.w[0] += a;
  s->state.w[1] += b;
  s->state.w[2] += c;
  s->state.w[3] += d;
  s->state.w[4] += e;
}

__device__ void d_sha1_addUncounted(sha1nfo *s, uint8_t data) {
  s->buffer.b[s->bufferOffset ^ 3] = data;
  s->bufferOffset++;
  if (s->bufferOffset == BLOCK_LENGTH) {
    d_sha1_hashBlock(s);
    s->bufferOffset = 0;
  }
}

__device__ void d_sha1_writebyte(sha1nfo *s, uint8_t data) {
  ++s->byteCount;
  d_sha1_addUncounted(s, data);
}

__device__ void d_sha1_write(sha1nfo *s, const char *data, size_t len) {
	for (;len--;) d_sha1_writebyte(s, (uint8_t) *data++);
}

__device__ void d_sha1_pad(sha1nfo *s) {
  // Implement SHA-1 padding (fips180-2 §5.1.1)

  // Pad with 0x80 followed by 0x00 until the end of the block
  d_sha1_addUncounted(s, 0x80);
  while (s->bufferOffset != 56) d_sha1_addUncounted(s, 0x00);

  // Append length in the last 8 bytes
  d_sha1_addUncounted(s, 0); // We're only using 32 bit lengths
  d_sha1_addUncounted(s, 0); // But SHA-1 supports 64 bit lengths
  d_sha1_addUncounted(s, 0); // So zero pad the top bits
  d_sha1_addUncounted(s, s->byteCount >> 29); // Shifting to multiply by 8
  d_sha1_addUncounted(s, s->byteCount >> 21); // as SHA-1 supports bitstreams as well as
  d_sha1_addUncounted(s, s->byteCount >> 13); // byte.
  d_sha1_addUncounted(s, s->byteCount >> 5);
  d_sha1_addUncounted(s, s->byteCount << 3);
}

__device__ uint8_t* d_sha1_result(sha1nfo *s) {
  int i;
  // Pad to complete the last block
  d_sha1_pad(s);
  
  // Swap byte order back
  for (i=0; i<5; i++) {
    uint32_t a,b;
    a=s->state.w[i];
    b=a<<24;
    b|=(a<<8) & 0x00ff0000;
    b|=(a>>8) & 0x0000ff00;
    b|=a>>24;
    s->state.w[i]=b;
  }
  
  // Return pointer to hash (20 charset)
  return s->state.b;
}

__device__ void d_print_hash(uint8_t* hash) {
  int i;
  for (i=0; i<20; i++) {
    printf("%02x", hash[i]);
  }
  printf("\n");
}

__device__ int next_password(char *charset, int num_chars, char* current_pw, uint8_t* current_idxs, int current_len) {

   int chk_len = current_len - 1;
   int done = 0;
      
   while (!done) {

      if (chk_len < 0) {
         return 0;
      }

      if (current_pw[chk_len] != charset[num_chars - 1]) {
         current_idxs[chk_len]++;
         current_pw[chk_len] = charset[current_idxs[chk_len]];
        
         return 1;
      }
      else {
         current_pw[chk_len] = charset[0];
         current_idxs[chk_len] = 0;
         chk_len--;
      } 
   }

   return 0;
}

__device__ int check_eq (char *hash, char *other_hash) {
  int index = 0;

  while (index < HASH_LENGTH) {
    if (hash[index] != other_hash[index]) {
      return 1;
    }
    index++;
  }
  return 0;
}

__device__ void compute_hash (char *password, int len, uint8_t *current_hash_ptr) {
   uint8_t *hash;
   sha1nfo current_hash;
   d_sha1_init(&current_hash);
   d_sha1_write(&current_hash, password, len);
   hash = d_sha1_result(&current_hash);
   memcpy(current_hash_ptr, hash, HASH_LENGTH);
}

__device__ void perform_permutations (char *pw, int len, uint8_t *hash,
                                      char *charset, int num_chars, int section) {
   char    current_pw[MAX_LEN + 1];
   uint8_t current_idxs[MAX_LEN + 1]; // index into charset
   uint8_t current_hash_ptr[HASH_LENGTH];
   int i;
   
   // initialize
   for (i = 0; i < MAX_LEN + 1; i++) {
      current_pw[i] = 0;
      current_idxs[i] = 0;
   }

   for (i = 0; i < len; i++) {
      current_pw[i] = pw[i];
   }
   
   do { // loops over password space for given password length
      compute_hash (current_pw, len, current_hash_ptr);

      // check if equal to hash we are cracking
      if (check_eq((char *)hash, (char *)current_hash_ptr) == 0) {
        printf ("Found Password: %s\n", current_pw);
      }
   } while (next_password (charset, num_chars, current_pw, current_idxs, 
                          (len - NUM_STATIC - NUM_PREPEND - 
                          (section != NO_SECTION) ? 1 : 0)));
}

__device__ void crack_password_helper (int section, uint8_t *hash, char *charset, int num_chars, 
                                       int len, uint8_t *static_chars, uint8_t *prepend) {
   char current_pw[MAX_LEN + 1];
   int i,j;
   
   // initialize
   for (i = 0; i < MAX_LEN + 1; i++) {
     if (i < len) {
       current_pw[i] = charset[0];
     }
     else {
      current_pw[i] = 0;
     }
   }

   // Set static chars at the end of the string
   for (i = 0, j = NUM_STATIC-1; i <= NUM_STATIC && i < len; i++, j--) {
     current_pw[len - 1 - i] = charset[static_chars[j]];
   }

   for (i = 0, j = NUM_PREPEND-1; i < NUM_PREPEND ; i++, j--) {
     current_pw[len - 1 - NUM_STATIC - i] = charset[prepend[j]];
   }
   
   if ((len - NUM_PREPEND) > NUM_STATIC && section > NO_SECTION) {
     int end, chars_per_section = (num_chars / NUM_SECTIONS) + 1;
     if (section == (NUM_SECTIONS - 1)) {
       end = (num_chars - (section * chars_per_section));
     }
     else {
       end = chars_per_section;
     }
       
     for (i = 0; i <= end; i++) {
       current_pw[len - 1 - NUM_STATIC - NUM_PREPEND] = charset[i + section*chars_per_section];
       perform_permutations(current_pw, len, hash, charset, num_chars, section);
     }
   }
   else {
     perform_permutations(current_pw, len, hash, charset, num_chars, section);
   }
}

__global__ void crack_password (int section, char *charset, int max_len, int num_chars, uint8_t *prepend) {
   uint8_t static_chars[NUM_STATIC];
   static_chars[0] = blockIdx.x;
   static_chars[1] = blockIdx.y;
   static_chars[2] = threadIdx.x;

   char *password = "16zbf0";
   int pw_len = 6;
   uint8_t hash[HASH_LENGTH];
   
   compute_hash (password, pw_len, hash);
   
   crack_password_helper (section, hash, charset, num_chars, max_len, 
                          static_chars, prepend);
}

// ----------------------------------------------------------------------------
//                    CPU FUNCTIONS
// ----------------------------------------------------------------------------

void handle_error(cudaError_t err, const char *file, int line ) {
  if (err != cudaSuccess) {
    fprintf(stderr, "%s in %s at line %d\n", cudaGetErrorString( err ), file, line);
          exit(EXIT_FAILURE);
  }
}

/*
 * prepend must be an array of size NUM_PREPEND found in sha1_gpu.h
 */
void call_kernel (uint8_t *prepend) {
  char *d_charset;
  uint8_t *d_prepend;
  int num_chars = strlen (charset), len, section;
  dim3 grid (num_chars, num_chars);

  // Setup Device Variables
  HANDLE_ERROR (cudaMalloc (&d_charset, num_chars));
  HANDLE_ERROR (cudaMemcpy (d_charset, charset, num_chars, cudaMemcpyHostToDevice));
  
  HANDLE_ERROR (cudaMalloc (&d_prepend, NUM_PREPEND));
  HANDLE_ERROR (cudaMemcpy (d_prepend, prepend, NUM_PREPEND, cudaMemcpyHostToDevice));
  
  //for (len = NUM_PREPEND + NUM_STATIC + 1; len <= MAX_LEN; len++) {
  for (len = MAX_LEN; len <= MAX_LEN; len++) {
    if ((len - NUM_PREPEND) >= MAX_WITH_SECTION) {
      for (section = 0; section < NUM_SECTIONS; section++) {
        crack_password<<<grid, num_chars>>> (section, d_charset, len, num_chars, d_prepend);
        HANDLE_ERROR (cudaDeviceSynchronize());
      }
    }
    else {
      // Execute Kernel
      crack_password<<<grid, num_chars>>> (NO_SECTION, d_charset, len, num_chars, d_prepend);
    }
    HANDLE_ERROR (cudaDeviceSynchronize());
  }
 
  // Free Device memory
  HANDLE_ERROR (cudaFree (d_charset));
  HANDLE_ERROR (cudaFree (d_prepend));
}

int main (int argc, char *argv[]) {
  int i;

  uint8_t prepend[NUM_PREPEND];

  for (i = 0; i < strlen (charset); i++) {
    prepend[0] = i;
    call_kernel (prepend);
  }
}
