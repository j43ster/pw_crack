#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sha1.h"


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

__device__ int next_password(char *charset, int num_chars, char* current_pw, uint8_t* current_idxs, uint8_t current_len) {

   int chk_len = current_len - 1;
   int done = 0;
      
   while (!done) {

      if (chk_len == -1) {
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

__device__ void copy_password (char *result, char *source, int len) {
  int index;

  for (index = 0; index < len; index++) {
    result[index] = source[index];
  }
}

__device__ void compute_hash (char *password, int len, uint8_t *current_hash_ptr) {
   uint8_t *hash;
   sha1nfo current_hash;
   d_sha1_init(&current_hash);
   d_sha1_write(&current_hash, password, len);
   hash = d_sha1_result(&current_hash);
   memcpy(current_hash_ptr, hash, HASH_LENGTH);
}

__device__ void crack_password_helper (uint8_t *hash, char *charset, int num_chars, 
                                       int len, char *d_password, int last_char, int second_last_char) {
   char    current_pw[100];
   uint8_t current_idxs[100]; // index into charset
   uint8_t current_hash_ptr[HASH_LENGTH];
   int i;

   // initialize
   for (i = 0; i < 100; i++) {
      current_pw[i] = 0;
      current_idxs[i] = 0;
   }

   for (i = 0; i < len; i++) {
      current_pw[0] = charset[0];
   }

   current_pw[len - 2] = charset[second_last_char];
   current_pw[len - 1] = charset[last_char];

   do { // loops over password space for given password length
      compute_hash (current_pw, len, current_hash_ptr);

      // check if equal to hash we are cracking
      if (check_eq((char *)hash, (char *)current_hash_ptr) == 0) {
         copy_password (d_password, current_pw, len);
      }
   } while (next_password (charset, num_chars, current_pw, current_idxs, len - 2));
}

__global__ void crack_password (uint8_t *hash, char *d_password, char *charset, int max_len, int num_chars) {
   int last_char = blockIdx.x;
   int second_last_char = threadIdx.x;
   int start_len = 2;
   int end_len = max_len;
   int len;
 
   if (threadIdx.x == 0 && blockIdx.x == 0) {
     char *password = "16b9";
     int pw_len = 4;

     compute_hash (password, pw_len, hash);
   }
   
   __syncthreads();
   
   for (len = start_len; len <= end_len; len++) {
     crack_password_helper (hash, charset, num_chars, len, d_password, last_char, second_last_char);
   }
   
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

int main (int argc, char *argv[]) {
  uint8_t *d_hash;
  char *password, *d_password, *d_charset;
  int num_chars = strlen (charset);
  
  password = (char *) malloc (MAX_LEN + 1);
  memset (password, '\0', MAX_LEN + 1);
  // Setup Device Variables
  HANDLE_ERROR (cudaMalloc (&d_hash, HASH_LENGTH));
  HANDLE_ERROR (cudaMalloc (&d_password, MAX_LEN + 1));
  
  HANDLE_ERROR (cudaMalloc (&d_charset, num_chars));
  HANDLE_ERROR (cudaMemcpy (d_charset, charset, num_chars, cudaMemcpyHostToDevice));

  // Execute Kernel
  crack_password<<<num_chars, num_chars>>> (d_hash, d_password, d_charset, MAX_LEN, num_chars);

  // Copy cracked password back
  HANDLE_ERROR (cudaMemcpy (password, d_password, MAX_LEN, cudaMemcpyDeviceToHost));
 
  // Free Device memory
  HANDLE_ERROR (cudaFree (d_hash));
  HANDLE_ERROR (cudaFree (d_password));

  printf ("Found Password: %s\n", password);
}

void sha1_init(sha1nfo *s) {
  memcpy(s->state.b,sha1InitState,HASH_LENGTH);
  s->byteCount = 0;
  s->bufferOffset = 0;
}

uint32_t sha1_rol32(uint32_t number, uint8_t bits) {
  return ((number << bits) | (number >> (32-bits)));
}

void sha1_hashBlock(sha1nfo *s) {
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
      s->buffer.w[i&15] = sha1_rol32(t,1);
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
    t+=sha1_rol32(a,5) + e + s->buffer.w[i&15];
    e=d;
    d=c;
    c=sha1_rol32(b,30);
    b=a;
    a=t;
  }
  s->state.w[0] += a;
  s->state.w[1] += b;
  s->state.w[2] += c;
  s->state.w[3] += d;
  s->state.w[4] += e;
}

void sha1_addUncounted(sha1nfo *s, uint8_t data) {
  s->buffer.b[s->bufferOffset ^ 3] = data;
  s->bufferOffset++;
  if (s->bufferOffset == BLOCK_LENGTH) {
    sha1_hashBlock(s);
    s->bufferOffset = 0;
  }
}

void sha1_writebyte(sha1nfo *s, uint8_t data) {
  ++s->byteCount;
  sha1_addUncounted(s, data);
}

void sha1_write(sha1nfo *s, const char *data, size_t len) {
	for (;len--;) sha1_writebyte(s, (uint8_t) *data++);
}

void sha1_pad(sha1nfo *s) {
  // Implement SHA-1 padding (fips180-2 §5.1.1)

  // Pad with 0x80 followed by 0x00 until the end of the block
  sha1_addUncounted(s, 0x80);
  while (s->bufferOffset != 56) sha1_addUncounted(s, 0x00);

  // Append length in the last 8 bytes
  sha1_addUncounted(s, 0); // We're only using 32 bit lengths
  sha1_addUncounted(s, 0); // But SHA-1 supports 64 bit lengths
  sha1_addUncounted(s, 0); // So zero pad the top bits
  sha1_addUncounted(s, s->byteCount >> 29); // Shifting to multiply by 8
  sha1_addUncounted(s, s->byteCount >> 21); // as SHA-1 supports bitstreams as well as
  sha1_addUncounted(s, s->byteCount >> 13); // byte.
  sha1_addUncounted(s, s->byteCount >> 5);
  sha1_addUncounted(s, s->byteCount << 3);
}

uint8_t* sha1_result(sha1nfo *s) {
  int i;
  // Pad to complete the last block
  sha1_pad(s);
  
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

void printHash(uint8_t* hash) {
  int i;
  for (i=0; i<20; i++) {
    printf("%02x", hash[i]);
  }
  printf("\n");
}
