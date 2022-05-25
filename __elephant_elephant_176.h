#ifndef ELEPHANT_176
#define ELEPHANT_176

#define SPONGENT176
#define BLOCK_SIZE 22

typedef unsigned char BYTE;
typedef unsigned long long SIZE;

void permutation(BYTE* state);

void lfsr_step(BYTE* output, BYTE* input);

void get_ad_block(BYTE* output, const BYTE* ad, SIZE adlen, const BYTE* npub, SIZE i);

void get_c_block(BYTE* output, const BYTE* c, SIZE clen, SIZE i);

int __elephant_crypto_aead_encrypt(
	unsigned char* c, unsigned long long* clen,
	const unsigned char* m, unsigned long long mlen,
	const unsigned char* ad, unsigned long long adlen,
	const unsigned char* nsec,
	const unsigned char* npub,
	const unsigned char* k);

#endif
