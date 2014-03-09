#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define HASH_LENGTH 20
#define BLOCK_LENGTH 64

#define MAX_LEN 6
#define NUM_STATIC 3
#define NUM_PREPEND 1 

#define MAX_WITH_SECTION 5
#define NUM_SECTIONS 3 
#define NO_SECTION -1


union _buffer {
	uint8_t b[BLOCK_LENGTH];
	uint32_t w[BLOCK_LENGTH/4];
};

union _state {
	uint8_t b[HASH_LENGTH];
	uint32_t w[HASH_LENGTH/4];
};

typedef struct sha1nfo {
	union _buffer buffer;
	uint8_t bufferOffset;
	union _state state;
	uint32_t byteCount;
	uint8_t keyBuffer[BLOCK_LENGTH];
	uint8_t innerHash[HASH_LENGTH];
} sha1nfo;

#define SHA1_K0 0x5a827999
#define SHA1_K20 0x6ed9eba1
#define SHA1_K40 0x8f1bbcdc
#define SHA1_K60 0xca62c1d6
