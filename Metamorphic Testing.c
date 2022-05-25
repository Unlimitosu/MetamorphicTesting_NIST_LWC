#include "Metamorphic Testing.h"


void printBlock(uint8_t* b) {
	int size = _msize(b) / sizeof(uint8_t);
	for (int i = 0; i < size; i++)
		printf("%02x ", b[i]);
	printf("\n");
}

/*****************************ASCON*********************************/
void BCT_ASCON(uint8_t* Plaintext, size_t size) {

	//! Parameters
	uint8_t* Ciphertext_Origin = NULL;	//! Ciphertext of buf
	uint8_t* Ciphertext_Test = NULL;	//! Ciphertext of buf_copy
	uint8_t* buf = NULL;	//! Copy of Plaintext. Not flipped.
	uint8_t* buf_copy = NULL;	//! Copy od Plaintext. Flipped
	uint8_t* AD = NULL; //! Associated Data
	uint8_t* npub = NULL; //! Nonce
	uint8_t mk[32] = { 0, };			//! Master key
	int i = 0, j = 0;	//! Index for for loops
	int errnum = 1;	//! The number of Errors for debugging
	int flag = 1;	//! Flag will be 0 if the test fails
	unsigned long long clen = size + TAGBYTES; //! Ciphertext size
	unsigned long long* clen_ptr = &clen;			//! Pointer of clen
	const unsigned char* nsec = NULL;			//! We will not use nsec

	//! Memory Allocations
	//! Ciphertext buffer size = Plaintext size + Tag size
	Ciphertext_Origin = (uint8_t*)calloc(size + TAGBYTES, sizeof(uint8_t));
	Ciphertext_Test = (uint8_t*)calloc(size + TAGBYTES, sizeof(uint8_t));
	buf = (uint8_t*)calloc(size, sizeof(uint8_t));
	buf_copy = (uint8_t*)calloc(size, sizeof(uint8_t));
	AD = (uint8_t*)calloc(size, sizeof(uint8_t));
	npub = (uint8_t*)calloc(size, sizeof(uint8_t));

	assert(Ciphertext_Origin != NULL);
	assert(Ciphertext_Test != NULL);
	assert(buf != NULL);
	assert(buf_copy != NULL);
	assert(AD != NULL);
	assert(npub != NULL);

	//! Key Settings
	for (i = 0; i < 16; i++) mk[i] = i * 0x11;
	for (i = 16; i < 24; i++) mk[i] = (i - 16) * 0x11;

	//! Copy 16-bytes from the original Plaintext
	memcpy(buf, Plaintext, 16);

	//! Encrypt Original Plaintext
	__ascon_crypto_aead_encrypt(Ciphertext_Origin, clen_ptr, buf, size, AD, size, nsec, npub, mk);

	//! Bit Contribution Test
	for (j = 1; j <= size * 8 - 1; j++) {
		memcpy(buf_copy, Plaintext, 16);

		//! Bit Flipping
		buf_copy[j / 8] ^= 1 << (j % 8);

		//! Encrypt Flipped Plaintext
		*clen_ptr = size;
		__ascon_crypto_aead_encrypt(Ciphertext_Test, clen_ptr, buf_copy, size, AD, size, nsec, npub, mk);

		//! If two ciphertexts are same 
		if (!memcmp(Ciphertext_Origin, Ciphertext_Test, size)) {
			printf("ERROR #%d\n", errnum++);
			printf("Ciphertext Origin: "); printBlock(Ciphertext_Origin); printf("\n");
			printf("Ciphertext Test  : "); printBlock(Ciphertext_Test);   printf("\n");
			flag = 0;
		}
	}

	if (flag) printf("ASCON Bit Contribution Test SUCCESS!\n");

	//! Free Memories
	if (Ciphertext_Origin != NULL)	free(Ciphertext_Origin);
	if (Ciphertext_Test != NULL)	free(Ciphertext_Test);
	if (buf != NULL)				free(buf);
	if (buf_copy != NULL)			free(buf_copy);
	if (AD != NULL)				    free(AD);
	if (npub != NULL)				free(npub);
}
void BCT_ASCON_hash(uint8_t* Plaintext, size_t size) {

	//! Parameters
	uint8_t* Ciphertext_Origin = NULL;	//! Ciphertext of buf
	uint8_t* Ciphertext_Test = NULL;	//! Ciphertext of buf_copy
	uint8_t* buf = NULL;	//! Copy of Plaintext. Not flipped.
	uint8_t* buf_copy = NULL;	//! Copy od Plaintext. Flipped
	uint8_t* AD = NULL; //! Associated Data
	uint8_t* npub = NULL; //! Nonce
	uint8_t mk[32] = { 0, };			//! Master key
	int i = 0, j = 0;	//! Index for for loops
	int errnum = 1;	//! The number of Errors for debugging
	int flag = 1;	//! Flag will be 0 if the test fails
	unsigned long long clen = size + TAGBYTES; //! Ciphertext size
	unsigned long long* clen_ptr = &clen;			//! Pointer of clen
	const unsigned char* nsec = NULL;			//! We will not use nsec

	//! Memory Allocations
	//! Ciphertext buffer size = Plaintext size + Tag size
	Ciphertext_Origin = (uint8_t*)calloc(size + TAGBYTES, sizeof(uint8_t));
	Ciphertext_Test = (uint8_t*)calloc(size + TAGBYTES, sizeof(uint8_t));
	buf = (uint8_t*)calloc(size, sizeof(uint8_t));
	buf_copy = (uint8_t*)calloc(size, sizeof(uint8_t));
	AD = (uint8_t*)calloc(size, sizeof(uint8_t));
	npub = (uint8_t*)calloc(size, sizeof(uint8_t));

	assert(Ciphertext_Origin != NULL);
	assert(Ciphertext_Test != NULL);
	assert(buf != NULL);
	assert(buf_copy != NULL);
	assert(AD != NULL);
	assert(npub != NULL);

	//! Key Settings
	for (i = 0; i < 16; i++) mk[i] = i * 0x11;
	for (i = 16; i < 24; i++) mk[i] = (i - 16) * 0x11;

	//! Copy 16-bytes from the original Plaintext
	memcpy(buf, Plaintext, 16);

	//! Encrypt Original Plaintext
	__ascon_crypto_hash(Ciphertext_Origin, buf, size);

	//! Bit Contribution Test
	for (j = 1; j <= size * 8 - 1; j++) {
		memcpy(buf_copy, Plaintext, 16);

		//! Bit Flipping
		buf_copy[j / 8] ^= 1 << (j % 8);

		//! Encrypt Flipped Plaintext
		*clen_ptr = size;
		__ascon_crypto_hash(Ciphertext_Test, buf_copy, size);

		//! If two ciphertexts are same 
		if (!memcmp(Ciphertext_Origin, Ciphertext_Test, size)) {
			printf("ERROR #%d\n", errnum++);
			printf("Ciphertext Origin: "); printBlock(Ciphertext_Origin); printf("\n");
			printf("Ciphertext Test  : "); printBlock(Ciphertext_Test);   printf("\n");
			flag = 0;
		}
	}

	if (flag) printf("ASCON_hash Bit Contribution Test SUCCESS!\n");

	//! Free Memories
	if (Ciphertext_Origin != NULL)	free(Ciphertext_Origin);
	if (Ciphertext_Test != NULL)	free(Ciphertext_Test);
	if (buf != NULL)				free(buf);
	if (buf_copy != NULL)			free(buf_copy);
	if (AD != NULL)				    free(AD);
	if (npub != NULL)				free(npub);
}
void BET_ASCON(uint8_t* Plaintext, size_t size) {

	//! Parameters
	uint8_t* Ciphertext_Origin = NULL;	//! Ciphertext of buf
	uint8_t* Ciphertext_Test = NULL;	//! Ciphertext of buf_copy
	uint8_t* buf = NULL;	//! Copy of Plaintext. Not flipped.
	uint8_t* buf_copy = NULL;	//! Copy od Plaintext. Flipped
	uint8_t* AD = NULL; //! Associated Data
	uint8_t* npub = NULL; //! Nonce
	uint8_t mk[32] = { 0, };			//! Master key
	int i = 0, j = 0;	//! Index for for loops
	int errnum = 1;	//! The number of Errors for debugging
	int flag = 1;	//! Flag will be 0 if the test fails
	unsigned long long clen = size + TAGBYTES; //! Ciphertext size
	unsigned long long* clen_ptr = &clen;	   //! Pointer of clen
	const unsigned char* nsec = NULL;	   //! We will not use nsec

	//! Memory Allocations
	//! Ciphertext buffer size = Plaintext size + Tag size
	//! buf_copy size = size + EXCLUSION_BYTELEN
	Ciphertext_Origin = (uint8_t*)calloc(size + TAGBYTES, sizeof(uint8_t));
	Ciphertext_Test = (uint8_t*)calloc(size + TAGBYTES, sizeof(uint8_t));
	buf = (uint8_t*)calloc(size, sizeof(uint8_t));
	buf_copy = (uint8_t*)calloc(size + EXCLUSION_BYTELEN, sizeof(uint8_t));
	AD = (uint8_t*)calloc(size, sizeof(uint8_t));
	npub = (uint8_t*)calloc(size, sizeof(uint8_t));

	assert(Ciphertext_Origin != NULL);
	assert(Ciphertext_Test != NULL);
	assert(buf != NULL);
	assert(buf_copy != NULL);
	assert(AD != NULL);
	assert(npub != NULL);

	//! Key Settings
	for (i = 0; i < 16; i++) mk[i] = i * 0x11;
	for (i = 16; i < 24; i++) mk[i] = (i - 16) * 0x11;


	for (i = 1; i <= size; i++) {
		//! Copy 16-bytes from the original Plaintext
		memcpy(buf, Plaintext, i);

		//! Encrypt Original Plaintext
		__ascon_crypto_aead_encrypt(Ciphertext_Origin, clen_ptr, buf, i, AD, i, nsec, npub, mk);

		for (j = 0; j < EXCLUSION_BYTELEN * 8; j++) { // 128
			//! Flip 
			memcpy(buf_copy, Plaintext, i + 1);
			buf_copy[i + j / 8] ^= 1 << (j % 8);
			__ascon_crypto_aead_encrypt(Ciphertext_Test, clen_ptr, buf_copy, i, AD, i, nsec, npub, mk);

			if (memcmp(Ciphertext_Origin, Ciphertext_Test, i)) {
				printf("ERROR #%d\n", errnum++);
				printf("Ciphertext Origin: "); printBlock(Ciphertext_Origin); printf("\n");
				printf("Ciphertext Test  : "); printBlock(Ciphertext_Test);   printf("\n");
				flag = 0;
			}
		}
	}

	if (flag) printf("ASCON Bit Exclusion Test SUCCESS!\n");

	//! Free memories
	if (Ciphertext_Origin != NULL)	free(Ciphertext_Origin);
	if (Ciphertext_Test != NULL)	free(Ciphertext_Test);
	if (buf != NULL)	free(buf);
	if (buf_copy != NULL)	free(buf_copy);
	if (AD != NULL)	free(AD);
	if (npub != NULL)	free(npub);

	return;
}
void BET_ASCON_hash(uint8_t* Plaintext, size_t size) {

	//! Parameters
	uint8_t* Ciphertext_Origin = NULL;	//! Ciphertext of buf
	uint8_t* Ciphertext_Test = NULL;	//! Ciphertext of buf_copy
	uint8_t* buf = NULL;	//! Copy of Plaintext. Not flipped.
	uint8_t* buf_copy = NULL;	//! Copy od Plaintext. Flipped
	uint8_t* AD = NULL; //! Associated Data
	uint8_t* npub = NULL; //! Nonce
	uint8_t mk[32] = { 0, };			//! Master key
	int i = 0, j = 0;	//! Index for for loops
	int errnum = 1;	//! The number of Errors for debugging
	int flag = 1;	//! Flag will be 0 if the test fails
	unsigned long long clen = size + TAGBYTES; //! Ciphertext size
	unsigned long long* clen_ptr = &clen;	   //! Pointer of clen
	const unsigned char* nsec = NULL;	   //! We will not use nsec

	//! Memory Allocations
	//! Ciphertext buffer size = Plaintext size + Tag size
	//! buf_copy size = size + EXCLUSION_BYTELEN
	Ciphertext_Origin = (uint8_t*)calloc(size + TAGBYTES, sizeof(uint8_t));
	Ciphertext_Test = (uint8_t*)calloc(size + TAGBYTES, sizeof(uint8_t));
	buf = (uint8_t*)calloc(size, sizeof(uint8_t));
	buf_copy = (uint8_t*)calloc(size + EXCLUSION_BYTELEN, sizeof(uint8_t));
	AD = (uint8_t*)calloc(size, sizeof(uint8_t));
	npub = (uint8_t*)calloc(size, sizeof(uint8_t));

	assert(Ciphertext_Origin != NULL);
	assert(Ciphertext_Test != NULL);
	assert(buf != NULL);
	assert(buf_copy != NULL);
	assert(AD != NULL);
	assert(npub != NULL);

	//! Key Settings
	for (i = 0; i < 16; i++) mk[i] = i * 0x11;
	for (i = 16; i < 24; i++) mk[i] = (i - 16) * 0x11;


	for (i = 1; i <= size; i++) {
		//! Copy 16-bytes from the original Plaintext
		memcpy(buf, Plaintext, i);

		//! Encrypt Original Plaintext
		__ascon_crypto_hash(Ciphertext_Origin, buf, i);

		for (j = 0; j < EXCLUSION_BYTELEN * 8; j++) { // 128
			//! Flip 
			memcpy(buf_copy, Plaintext, i + 1);
			buf_copy[i + j / 8] ^= 1 << (j % 8);
			__ascon_crypto_hash(Ciphertext_Test, buf_copy, i);

			if (memcmp(Ciphertext_Origin, Ciphertext_Test, i)) {
				printf("ERROR #%d\n", errnum++);
				printf("Ciphertext Origin: "); printBlock(Ciphertext_Origin); printf("\n");
				printf("Ciphertext Test  : "); printBlock(Ciphertext_Test);   printf("\n");
				printf("buf      	     : "); printBlock(buf);			      printf("\n");
				printf("buf_copy	     : "); printBlock(buf_copy);		  printf("\n");
				flag = 0;
			}
		}
	}

	if (flag) printf("ASCON_hash Bit Exclusion Test SUCCESS!\n");

	//! Free memories
	if (Ciphertext_Origin != NULL)	free(Ciphertext_Origin);
	if (Ciphertext_Test != NULL)	free(Ciphertext_Test);
	if (buf != NULL)	free(buf);
	if (buf_copy != NULL)	free(buf_copy);
	if (AD != NULL)	free(AD);
	if (npub != NULL)	free(npub);

	return;
}

/****************************Elephant*******************************/
void BCT_Elephant(uint8_t* Plaintext, size_t size) {

	//! Parameters
	uint8_t* Ciphertext_Origin = NULL;	//! Ciphertext of buf
	uint8_t* Ciphertext_Test = NULL;	//! Ciphertext of buf_copy
	uint8_t* buf = NULL;	//! Copy of Plaintext. Not flipped.
	uint8_t* buf_copy = NULL;	//! Copy od Plaintext. Flipped
	uint8_t* AD = NULL; //! Associated Data
	uint8_t* npub = NULL; //! Nonce
	uint8_t mk[32] = { 0, };			//! Master key
	int i = 0, j = 0;	//! Index for for loops
	int errnum = 1;	//! The number of Errors for debugging
	int flag = 1;	//! Flag will be 0 if the test fails
	unsigned long long clen = size + TAGBYTES; //! Ciphertext size
	unsigned long long* clen_ptr = &clen;			//! Pointer of clen
	const unsigned char* nsec = NULL;			//! We will not use nsec

	//! Memory Allocations
	//! Ciphertext buffer size = Plaintext size + Tag size
	Ciphertext_Origin = (uint8_t*)calloc(size + TAGBYTES, sizeof(uint8_t));
	Ciphertext_Test = (uint8_t*)calloc(size + TAGBYTES, sizeof(uint8_t));
	buf = (uint8_t*)calloc(size, sizeof(uint8_t));
	buf_copy = (uint8_t*)calloc(size, sizeof(uint8_t));
	AD = (uint8_t*)calloc(size, sizeof(uint8_t));
	npub = (uint8_t*)calloc(size, sizeof(uint8_t));

	assert(Ciphertext_Origin != NULL);
	assert(Ciphertext_Test != NULL);
	assert(buf != NULL);
	assert(buf_copy != NULL);
	assert(AD != NULL);
	assert(npub != NULL);

	//! Key Settings
	for (i = 0; i < 16; i++) mk[i] = i * 0x11;
	for (i = 16; i < 24; i++) mk[i] = (i - 16) * 0x11;

	//! Copy 16-bytes from the original Plaintext
	memcpy(buf, Plaintext, 16);

	//! Encrypt Original Plaintext
	__elephant_crypto_aead_encrypt(Ciphertext_Origin, clen_ptr, buf, size, AD, size, nsec, npub, mk);

	//! Bit Contribution Test
	for (j = 1; j <= size * 8 - 1; j++) {
		memcpy(buf_copy, Plaintext, 16);

		//! Bit Flipping
		buf_copy[j / 8] ^= 1 << (j % 8);

		//! Encrypt Flipped Plaintext
		*clen_ptr = size;
		__elephant_crypto_aead_encrypt(Ciphertext_Test, clen_ptr, buf_copy, size, AD, size, nsec, npub, mk);

		//! If two ciphertexts are same 
		if (!memcmp(Ciphertext_Origin, Ciphertext_Test, size)) {
			printf("ERROR #%d\n", errnum++);
			printf("Ciphertext Origin: "); printBlock(Ciphertext_Origin); printf("\n");
			printf("Ciphertext Test  : "); printBlock(Ciphertext_Test);   printf("\n");
			flag = 0;
		}
	}

	if (flag) printf("Elephant Bit Contribution Test SUCCESS!\n");

	//! Free Memories
	if (Ciphertext_Origin != NULL)	free(Ciphertext_Origin);
	if (Ciphertext_Test != NULL)	free(Ciphertext_Test);
	if (buf != NULL)				free(buf);
	if (buf_copy != NULL)			free(buf_copy);
	if (AD != NULL)				    free(AD);
	if (npub != NULL)				free(npub);
}
void BET_Elephant(uint8_t* Plaintext, size_t size) {

	//! Parameters
	uint8_t* Ciphertext_Origin = NULL;	//! Ciphertext of buf
	uint8_t* Ciphertext_Test = NULL;	//! Ciphertext of buf_copy
	uint8_t* buf = NULL;	//! Copy of Plaintext. Not flipped.
	uint8_t* buf_copy = NULL;	//! Copy od Plaintext. Flipped
	uint8_t* AD = NULL; //! Associated Data
	uint8_t* npub = NULL; //! Nonce
	uint8_t mk[32] = { 0, };			//! Master key
	int i = 0, j = 0;	//! Index for for loops
	int errnum = 1;	//! The number of Errors for debugging
	int flag = 1;	//! Flag will be 0 if the test fails
	unsigned long long clen = size + TAGBYTES; //! Ciphertext size
	unsigned long long* clen_ptr = &clen;	   //! Pointer of clen
	const unsigned char* nsec = NULL;	   //! We will not use nsec

	//! Memory Allocations
	//! Ciphertext buffer size = Plaintext size + Tag size
	//! buf_copy size = size + EXCLUSION_BYTELEN
	Ciphertext_Origin = (uint8_t*)calloc(size + TAGBYTES, sizeof(uint8_t));
	Ciphertext_Test = (uint8_t*)calloc(size + TAGBYTES, sizeof(uint8_t));
	buf = (uint8_t*)calloc(size, sizeof(uint8_t));
	buf_copy = (uint8_t*)calloc(size + EXCLUSION_BYTELEN, sizeof(uint8_t));
	AD = (uint8_t*)calloc(size, sizeof(uint8_t));
	npub = (uint8_t*)calloc(size, sizeof(uint8_t));

	assert(Ciphertext_Origin != NULL);
	assert(Ciphertext_Test != NULL);
	assert(buf != NULL);
	assert(buf_copy != NULL);
	assert(AD != NULL);
	assert(npub != NULL);

	//! Key Settings
	for (i = 0; i < 16; i++) mk[i] = i * 0x11;
	for (i = 16; i < 24; i++) mk[i] = (i - 16) * 0x11;


	for (i = 1; i <= size; i++) {
		//! Copy 16-bytes from the original Plaintext
		memcpy(buf, Plaintext, i);

		//! Encrypt Original Plaintext
		__elephant_crypto_aead_encrypt(Ciphertext_Origin, clen_ptr, buf, i, AD, i, nsec, npub, mk);

		for (j = 0; j < EXCLUSION_BYTELEN * 8; j++) { // 128
			//! Flip 
			memcpy(buf_copy, Plaintext, i + 1);
			buf_copy[i + j / 8] ^= 1 << (j % 8);
			__elephant_crypto_aead_encrypt(Ciphertext_Test, clen_ptr, buf_copy, i, AD, i, nsec, npub, mk);

			if (memcmp(Ciphertext_Origin, Ciphertext_Test, i)) {
				printf("ERROR #%d\n", errnum++);
				printf("Ciphertext Origin: "); printBlock(Ciphertext_Origin); printf("\n");
				printf("Ciphertext Test  : "); printBlock(Ciphertext_Test);   printf("\n");
				flag = 0;
			}
		}
	}

	if (flag) printf("Elephant Bit Exclusion Test SUCCESS!\n");

	//! Free memories
	if (Ciphertext_Origin != NULL)	free(Ciphertext_Origin);
	if (Ciphertext_Test != NULL)	free(Ciphertext_Test);
	if (buf != NULL)	free(buf);
	if (buf_copy != NULL)	free(buf_copy);
	if (AD != NULL)	free(AD);
	if (npub != NULL)	free(npub);

	return;
}

/***************************GIFT-COFB*******************************/
void BCT_GIFT_COFB(uint8_t* Plaintext, size_t size) {

	//! Parameters
	uint8_t* Ciphertext_Origin = NULL;	//! Ciphertext of buf
	uint8_t* Ciphertext_Test = NULL;	//! Ciphertext of buf_copy
	uint8_t* buf = NULL;	//! Copy of Plaintext. Not flipped.
	uint8_t* buf_copy = NULL;	//! Copy od Plaintext. Flipped
	uint8_t* AD = NULL; //! Associated Data
	uint8_t* npub = NULL; //! Nonce
	uint8_t mk[32] = { 0, };			//! Master key
	int i = 0, j = 0;	//! Index for for loops
	int errnum = 1;	//! The number of Errors for debugging
	int flag = 1;	//! Flag will be 0 if the test fails
	unsigned long long clen = size + TAGBYTES; //! Ciphertext size
	unsigned long long* clen_ptr = &clen;			//! Pointer of clen
	const unsigned char* nsec = NULL;			//! We will not use nsec

	//! Memory Allocations
	//! Ciphertext buffer size = Plaintext size + Tag size
	Ciphertext_Origin = (uint8_t*)calloc(size + TAGBYTES, sizeof(uint8_t));
	Ciphertext_Test = (uint8_t*)calloc(size + TAGBYTES, sizeof(uint8_t));
	buf = (uint8_t*)calloc(size, sizeof(uint8_t));
	buf_copy = (uint8_t*)calloc(size, sizeof(uint8_t));
	AD = (uint8_t*)calloc(size, sizeof(uint8_t));
	npub = (uint8_t*)calloc(size, sizeof(uint8_t));

	assert(Ciphertext_Origin != NULL);
	assert(Ciphertext_Test != NULL);
	assert(buf != NULL);
	assert(buf_copy != NULL);
	assert(AD != NULL);
	assert(npub != NULL);

	//! Key Settings
	for (i = 0; i < 16; i++) mk[i] = i * 0x11;
	for (i = 16; i < 24; i++) mk[i] = (i - 16) * 0x11;

	//! Copy 16-bytes from the original Plaintext
	memcpy(buf, Plaintext, 16);

	//! Encrypt Original Plaintext
	__gift_crypto_aead_encrypt(Ciphertext_Origin, clen_ptr, buf, size, AD, size, nsec, npub, mk);

	//! Bit Contribution Test
	for (j = 1; j <= size * 8 - 1; j++) {
		memcpy(buf_copy, Plaintext, 16);

		//! Bit Flipping
		buf_copy[j / 8] ^= 1 << (j % 8);

		//! Encrypt Flipped Plaintext
		*clen_ptr = size;
		__gift_crypto_aead_encrypt(Ciphertext_Test, clen_ptr, buf_copy, size, AD, size, nsec, npub, mk);

		//! If two ciphertexts are same 
		if (!memcmp(Ciphertext_Origin, Ciphertext_Test, size)) {
			printf("ERROR #%d\n", errnum++);
			printf("Ciphertext Origin: "); printBlock(Ciphertext_Origin); printf("\n");
			printf("Ciphertext Test  : "); printBlock(Ciphertext_Test);   printf("\n");
			flag = 0;
		}
	}

	if (flag) printf("GIFT-COFB Bit Contribution Test SUCCESS!\n");

	//! Free Memories
	if (Ciphertext_Origin != NULL)	free(Ciphertext_Origin);
	if (Ciphertext_Test != NULL)	free(Ciphertext_Test);
	if (buf != NULL)				free(buf);
	if (buf_copy != NULL)			free(buf_copy);
	if (AD != NULL)				    free(AD);
	if (npub != NULL)				free(npub);
}
void BET_GIFT_COFB(uint8_t* Plaintext, size_t size) {

	//! Parameters
	uint8_t* Ciphertext_Origin = NULL;	//! Ciphertext of buf
	uint8_t* Ciphertext_Test = NULL;	//! Ciphertext of buf_copy
	uint8_t* buf = NULL;	//! Copy of Plaintext. Not flipped.
	uint8_t* buf_copy = NULL;	//! Copy od Plaintext. Flipped
	uint8_t* AD = NULL; //! Associated Data
	uint8_t* npub = NULL; //! Nonce
	uint8_t mk[32] = { 0, };			//! Master key
	int i = 0, j = 0;	//! Index for for loops
	int errnum = 1;	//! The number of Errors for debugging
	int flag = 1;	//! Flag will be 0 if the test fails
	unsigned long long clen = size + TAGBYTES; //! Ciphertext size
	unsigned long long* clen_ptr = &clen;	   //! Pointer of clen
	const unsigned char* nsec = NULL;	   //! We will not use nsec

	//! Memory Allocations
	//! Ciphertext buffer size = Plaintext size + Tag size
	//! buf_copy size = size + EXCLUSION_BYTELEN
	Ciphertext_Origin = (uint8_t*)calloc(size + TAGBYTES, sizeof(uint8_t));
	Ciphertext_Test = (uint8_t*)calloc(size + TAGBYTES, sizeof(uint8_t));
	buf = (uint8_t*)calloc(size, sizeof(uint8_t));
	buf_copy = (uint8_t*)calloc(size + EXCLUSION_BYTELEN, sizeof(uint8_t)); // 256bit
	AD = (uint8_t*)calloc(size, sizeof(uint8_t));
	npub = (uint8_t*)calloc(size, sizeof(uint8_t));

	assert(Ciphertext_Origin != NULL);
	assert(Ciphertext_Test != NULL);
	assert(buf != NULL);
	assert(buf_copy != NULL);
	assert(AD != NULL);
	assert(npub != NULL);

	//! Key Settings
	for (i = 0; i < 16; i++) mk[i] = i * 0x11;
	for (i = 16; i < 24; i++) mk[i] = (i - 16) * 0x11;


	for (i = 0; i < size; i++) {
		//! Copy 16-bytes from the original Plaintext
		memcpy(buf, Plaintext, i + 1);

		//! Encrypt Original Plaintext
		__gift_crypto_aead_encrypt(Ciphertext_Origin, clen_ptr, buf, size, AD, size, nsec, npub, mk);

		for (j = 0; j < EXCLUSION_BYTELEN * 8; j++) { // 128
			//! Flip 
			memcpy(buf_copy, Plaintext, i + 1);
			buf_copy[i + j / 8 + 1] ^= 1 << (j % 8);
			__gift_crypto_aead_encrypt(Ciphertext_Test, clen_ptr, buf_copy, size, AD, size, nsec, npub, mk);

			if (memcmp(buf, buf_copy, i + 1)) {
				printf("ERROR #%d\n", errnum++);
				printf("Ciphertext Origin: "); printBlock(Ciphertext_Origin); printf("\n");
				printf("Ciphertext Test  : "); printBlock(Ciphertext_Test);   printf("\n");
				flag = 0;
			}
		}
	}

	if (flag) printf("GIFT-COFB Bit Exclusion Test SUCCESS!\n");

	//! Free memories
	if (Ciphertext_Origin != NULL)	free(Ciphertext_Origin);
	if (Ciphertext_Test != NULL)	free(Ciphertext_Test);
	if (buf != NULL)	free(buf);
	if (buf_copy != NULL)	free(buf_copy);
	if (AD != NULL)	free(AD);
	if (npub != NULL)	free(npub);

	return;
}

/**************************Grain-128AEAD****************************/
void BCT_Grain(uint8_t* Plaintext, size_t size) {

	//! Parameters
	uint8_t* Ciphertext_Origin = NULL;	//! Ciphertext of buf
	uint8_t* Ciphertext_Test = NULL;	//! Ciphertext of buf_copy
	uint8_t* buf = NULL;	//! Copy of Plaintext. Not flipped.
	uint8_t* buf_copy = NULL;	//! Copy od Plaintext. Flipped
	uint8_t* AD = NULL; //! Associated Data
	uint8_t* npub = NULL; //! Nonce
	uint8_t mk[32] = { 0, };			//! Master key
	int i = 0, j = 0;	//! Index for for loops
	int errnum = 1;	//! The number of Errors for debugging
	int flag = 1;	//! Flag will be 0 if the test fails
	unsigned long long clen = size + TAGBYTES; //! Ciphertext size
	unsigned long long* clen_ptr = &clen;			//! Pointer of clen
	const unsigned char* nsec = NULL;			//! We will not use nsec

	//! Memory Allocations
	//! Ciphertext buffer size = Plaintext size + Tag size
	Ciphertext_Origin = (uint8_t*)calloc(size + TAGBYTES, sizeof(uint8_t));
	Ciphertext_Test = (uint8_t*)calloc(size + TAGBYTES, sizeof(uint8_t));
	buf = (uint8_t*)calloc(size, sizeof(uint8_t));
	buf_copy = (uint8_t*)calloc(size, sizeof(uint8_t));
	AD = (uint8_t*)calloc(size, sizeof(uint8_t));
	npub = (uint8_t*)calloc(size, sizeof(uint8_t));

	assert(Ciphertext_Origin != NULL);
	assert(Ciphertext_Test != NULL);
	assert(buf != NULL);
	assert(buf_copy != NULL);
	assert(AD != NULL);
	assert(npub != NULL);

	//! Key Settings
	for (i = 0; i < 16; i++) mk[i] = i * 0x11;
	for (i = 16; i < 24; i++) mk[i] = (i - 16) * 0x11;

	//! Copy 16-bytes from the original Plaintext
	memcpy(buf, Plaintext, 16);

	//! Encrypt Original Plaintext
	__grain_crypto_aead_encrypt(Ciphertext_Origin, clen_ptr, buf, size, AD, size, nsec, npub, mk);

	//! Bit Contribution Test
	for (j = 1; j <= size * 8 - 1; j++) {
		memcpy(buf_copy, Plaintext, 16);

		//! Bit Flipping
		buf_copy[j / 8] ^= 1 << (j % 8);

		//! Encrypt Flipped Plaintext
		*clen_ptr = size;
		__grain_crypto_aead_encrypt(Ciphertext_Test, clen_ptr, buf_copy, size, AD, size, nsec, npub, mk);

		//! If two ciphertexts are same 
		if (!memcmp(Ciphertext_Origin, Ciphertext_Test, size)) {
			printf("ERROR #%d\n", errnum++);
			printf("Ciphertext Origin: "); printBlock(Ciphertext_Origin); printf("\n");
			printf("Ciphertext Test  : "); printBlock(Ciphertext_Test);   printf("\n");
			flag = 0;
		}
	}

	if (flag) printf("Grain-128AEAD Bit Contribution Test SUCCESS!\n");

	//! Free Memories
	if (Ciphertext_Origin != NULL)	free(Ciphertext_Origin);
	if (Ciphertext_Test != NULL)	free(Ciphertext_Test);
	if (buf != NULL)				free(buf);
	if (buf_copy != NULL)			free(buf_copy);
	if (AD != NULL)				    free(AD);
	if (npub != NULL)				free(npub);
}
void BET_Grain(uint8_t* Plaintext, size_t size) {

	//! Parameters
	uint8_t* Ciphertext_Origin = NULL;	//! Ciphertext of buf
	uint8_t* Ciphertext_Test = NULL;	//! Ciphertext of buf_copy
	uint8_t* buf = NULL;	//! Copy of Plaintext. Not flipped.
	uint8_t* buf_copy = NULL;	//! Copy od Plaintext. Flipped
	uint8_t* AD = NULL; //! Associated Data
	uint8_t* npub = NULL; //! Nonce
	uint8_t mk[32] = { 0, };			//! Master key
	int i = 0, j = 0;	//! Index for for loops
	int errnum = 1;	//! The number of Errors for debugging
	int flag = 1;	//! Flag will be 0 if the test fails
	unsigned long long clen = size + TAGBYTES; //! Ciphertext size
	unsigned long long* clen_ptr = &clen;	   //! Pointer of clen
	const unsigned char* nsec = NULL;	   //! We will not use nsec

	//! Memory Allocations
	//! Ciphertext buffer size = Plaintext size + Tag size
	//! buf_copy size = size + EXCLUSION_BYTELEN
	Ciphertext_Origin = (uint8_t*)calloc(size + TAGBYTES, sizeof(uint8_t));
	Ciphertext_Test = (uint8_t*)calloc(size + TAGBYTES, sizeof(uint8_t));
	buf = (uint8_t*)calloc(size, sizeof(uint8_t));
	buf_copy = (uint8_t*)calloc(size + EXCLUSION_BYTELEN, sizeof(uint8_t));
	AD = (uint8_t*)calloc(size, sizeof(uint8_t));
	npub = (uint8_t*)calloc(size, sizeof(uint8_t));

	assert(Ciphertext_Origin != NULL);
	assert(Ciphertext_Test != NULL);
	assert(buf != NULL);
	assert(buf_copy != NULL);
	assert(AD != NULL);
	assert(npub != NULL);

	//! Key Settings
	for (i = 0; i < 16; i++) mk[i] = i * 0x11;
	for (i = 16; i < 24; i++) mk[i] = (i - 16) * 0x11;


	for (i = 1; i <= size; i++) {
		//! Copy 16-bytes from the original Plaintext
		memcpy(buf, Plaintext, i);

		//! Encrypt Original Plaintext
		__grain_crypto_aead_encrypt(Ciphertext_Origin, clen_ptr, buf, i, AD, i, nsec, npub, mk);

		for (j = 0; j < EXCLUSION_BYTELEN * 8; j++) {
			//! Flip 
			memcpy(buf_copy, Plaintext, i + 1);
			buf_copy[i + j / 8] ^= 1 << (j % 8);
			__grain_crypto_aead_encrypt(Ciphertext_Test, clen_ptr, buf_copy, i, AD, i, nsec, npub, mk);

			if (memcmp(Ciphertext_Origin, Ciphertext_Test, i)) {
				printf("ERROR #%d\n", errnum++);
				printf("Ciphertext Origin: "); printBlock(Ciphertext_Origin); printf("\n");
				printf("Ciphertext Test  : "); printBlock(Ciphertext_Test);   printf("\n");
				flag = 0;
			}
		}
	}

	if (flag) printf("Grain-128AEAD Bit Exclusion Test SUCCESS!\n");

	//! Free memories
	if (Ciphertext_Origin != NULL)	free(Ciphertext_Origin);
	if (Ciphertext_Test != NULL)	free(Ciphertext_Test);
	if (buf != NULL)	free(buf);
	if (buf_copy != NULL)	free(buf_copy);
	if (AD != NULL)	free(AD);
	if (npub != NULL)	free(npub);

	return;
}

/*****************************ISAP**********************************/
void BCT_ISAP(uint8_t* Plaintext, size_t size) {

	//! Parameters
	uint8_t* Ciphertext_Origin = NULL;	//! Ciphertext of buf
	uint8_t* Ciphertext_Test = NULL;	//! Ciphertext of buf_copy
	uint8_t* buf = NULL;	//! Copy of Plaintext. Not flipped.
	uint8_t* buf_copy = NULL;	//! Copy od Plaintext. Flipped
	uint8_t* AD = NULL; //! Associated Data
	uint8_t* npub = NULL; //! Nonce
	uint8_t mk[32] = { 0, };			//! Master key
	int i = 0, j = 0;	//! Index for for loops
	int errnum = 1;	//! The number of Errors for debugging
	int flag = 1;	//! Flag will be 0 if the test fails
	unsigned long long clen = size + TAGBYTES; //! Ciphertext size
	unsigned long long* clen_ptr = &clen;			//! Pointer of clen
	const unsigned char* nsec = NULL;			//! We will not use nsec

	//! Memory Allocations
	//! Ciphertext buffer size = Plaintext size + Tag size
	Ciphertext_Origin = (uint8_t*)calloc(size + TAGBYTES, sizeof(uint8_t));
	Ciphertext_Test = (uint8_t*)calloc(size + TAGBYTES, sizeof(uint8_t));
	buf = (uint8_t*)calloc(size, sizeof(uint8_t));
	buf_copy = (uint8_t*)calloc(size, sizeof(uint8_t));
	AD = (uint8_t*)calloc(size, sizeof(uint8_t));
	npub = (uint8_t*)calloc(size, sizeof(uint8_t));

	assert(Ciphertext_Origin != NULL);
	assert(Ciphertext_Test != NULL);
	assert(buf != NULL);
	assert(buf_copy != NULL);
	assert(AD != NULL);
	assert(npub != NULL);

	//! Key Settings
	for (i = 0; i < 16; i++) mk[i] = i * 0x11;
	for (i = 16; i < 24; i++) mk[i] = (i - 16) * 0x11;

	//! Copy 16-bytes from the original Plaintext
	memcpy(buf, Plaintext, 16);

	//! Encrypt Original Plaintext
	__isap_crypto_aead_encrypt(Ciphertext_Origin, clen_ptr, buf, size, AD, size, nsec, npub, mk);

	//! Bit Contribution Test
	for (j = 1; j <= size * 8 - 1; j++) {
		memcpy(buf_copy, Plaintext, 16);

		//! Bit Flipping
		buf_copy[j / 8] ^= 1 << (j % 8);

		//! Encrypt Flipped Plaintext
		*clen_ptr = size;
		__isap_crypto_aead_encrypt(Ciphertext_Test, clen_ptr, buf_copy, size, AD, size, nsec, npub, mk);

		//! If two ciphertexts are same 
		if (!memcmp(Ciphertext_Origin, Ciphertext_Test, size)) {
			printf("ERROR #%d\n", errnum++);
			printf("Ciphertext Origin: "); printBlock(Ciphertext_Origin); printf("\n");
			printf("Ciphertext Test  : "); printBlock(Ciphertext_Test);   printf("\n");
			flag = 0;
		}
	}

	if (flag) printf("ISAP Bit Contribution Test SUCCESS!\n");

	//! Free Memories
	if (Ciphertext_Origin != NULL)	free(Ciphertext_Origin);
	if (Ciphertext_Test != NULL)	free(Ciphertext_Test);
	if (buf != NULL)				free(buf);
	if (buf_copy != NULL)			free(buf_copy);
	if (AD != NULL)				    free(AD);
	if (npub != NULL)				free(npub);
}
void BET_ISAP(uint8_t* Plaintext, size_t size) {

	//! Parameters
	uint8_t* Ciphertext_Origin = NULL;	//! Ciphertext of buf
	uint8_t* Ciphertext_Test = NULL;	//! Ciphertext of buf_copy
	uint8_t* buf = NULL;	//! Copy of Plaintext. Not flipped.
	uint8_t* buf_copy = NULL;	//! Copy od Plaintext. Flipped
	uint8_t* AD = NULL; //! Associated Data
	uint8_t* npub = NULL; //! Nonce
	uint8_t mk[32] = { 0, };			//! Master key
	int i = 0, j = 0;	//! Index for for loops
	int errnum = 1;	//! The number of Errors for debugging
	int flag = 1;	//! Flag will be 0 if the test fails
	unsigned long long clen = size + TAGBYTES; //! Ciphertext size
	unsigned long long* clen_ptr = &clen;	   //! Pointer of clen
	const unsigned char* nsec = NULL;	   //! We will not use nsec

	//! Memory Allocations
	//! Ciphertext buffer size = Plaintext size + Tag size
	//! buf_copy size = size + EXCLUSION_BYTELEN
	Ciphertext_Origin = (uint8_t*)calloc(size + TAGBYTES, sizeof(uint8_t));
	Ciphertext_Test = (uint8_t*)calloc(size + TAGBYTES, sizeof(uint8_t));
	buf = (uint8_t*)calloc(size, sizeof(uint8_t));
	buf_copy = (uint8_t*)calloc(size + EXCLUSION_BYTELEN, sizeof(uint8_t));
	AD = (uint8_t*)calloc(size, sizeof(uint8_t));
	npub = (uint8_t*)calloc(size, sizeof(uint8_t));

	assert(Ciphertext_Origin != NULL);
	assert(Ciphertext_Test != NULL);
	assert(buf != NULL);
	assert(buf_copy != NULL);
	assert(AD != NULL);
	assert(npub != NULL);

	//! Key Settings
	for (i = 0; i < 16; i++) mk[i] = i * 0x11;
	for (i = 16; i < 24; i++) mk[i] = (i - 16) * 0x11;


	for (i = 1; i <= size; i++) {
		//! Copy 16-bytes from the original Plaintext
		memcpy(buf, Plaintext, i);

		//! Encrypt Original Plaintext
		__isap_crypto_aead_encrypt(Ciphertext_Origin, clen_ptr, buf, i, AD, i, nsec, npub, mk);

		for (j = 0; j < EXCLUSION_BYTELEN * 8; j++) { // 128
			//! Flip 
			memcpy(buf_copy, Plaintext, i + 1);
			buf_copy[i + j / 8] ^= 1 << (j % 8);
			__isap_crypto_aead_encrypt(Ciphertext_Test, clen_ptr, buf_copy, i, AD, i, nsec, npub, mk);

			if (memcmp(Ciphertext_Origin, Ciphertext_Test, i)) {
				printf("ERROR #%d\n", errnum++);
				printf("Ciphertext Origin: "); printBlock(Ciphertext_Origin); printf("\n");
				printf("Ciphertext Test  : "); printBlock(Ciphertext_Test);   printf("\n");
				flag = 0;
			}
		}
	}

	if (flag) printf("ISAP Bit Exclusion Test SUCCESS!\n");

	//! Free memories
	if (Ciphertext_Origin != NULL)	free(Ciphertext_Origin);
	if (Ciphertext_Test != NULL)	free(Ciphertext_Test);
	if (buf != NULL)	free(buf);
	if (buf_copy != NULL)	free(buf_copy);
	if (AD != NULL)	free(AD);
	if (npub != NULL)	free(npub);

	return;
}
void UT_ISAP_HASH(uint8_t* Plaintext, size_t size) {
	//! ERROR OCCURED	
	//! UT for ISAP hash
	//! Parameters
	uint8_t* digest1 = NULL;
	uint8_t* digest2 = NULL;	//! Digested message
	uint8_t* msg_frag1 = NULL;
	uint8_t* msg_frag2 = NULL;	//! Message fragment for update test
	uint8_t* buf = NULL;	//! Copy of Plaintext
	uint8_t* buf_copy = NULL;	//! Copy od Plaintext
	uint8_t* npub = NULL; //! Nonce
	uint8_t* AD = NULL;   //! Associated Data
	uint8_t* AD_copy = NULL;   //! Associated Data
	uint8_t mk[16] = { 0, };			//! Master key

	int i = 0, j = 0;	//! Index for for loops
	int errnum = 1;	//! The number of Errors for debugging
	int flag = 1;	//! Flag will be 0 if the test fails
	unsigned long long clen_origin = size + TAGBYTES256; //! Ciphertext size
	unsigned long long clen_copy = size + TAGBYTES256; //! Ciphertext size
	unsigned long long* clenptr_origin = &clen_origin;		//! Pointer of clen
	unsigned long long* clenptr_copy = &clen_copy;		//! Pointer of clen
	unsigned long long ADlen = TAGBYTES256;
	const unsigned char* nsec = NULL;			//! We will not use nsec

	uint8_t state[40];

	//! Memory Allocations

	buf = (uint8_t*)calloc(size * 2, sizeof(uint8_t)); //32
	npub = (uint8_t*)calloc(size, sizeof(uint8_t));
	AD = (uint8_t*)calloc(size, sizeof(uint8_t));
	AD_copy = (uint8_t*)calloc(size, sizeof(uint8_t));


	assert(buf != NULL);
	assert(npub != NULL);
	assert(AD != NULL);
	assert(AD_copy != NULL);

	//! Copy plaintext to buf
	memcpy(buf, Plaintext, size);
	memcpy(buf + size, Plaintext, size);

	for (i = 1; i <= size; i++) {
		for (j = 1; j <= size; j++) {
			buf_copy = (uint8_t*)calloc(i + j, sizeof(uint8_t));
			msg_frag1 = (uint8_t*)calloc(i, sizeof(uint8_t));
			msg_frag2 = (uint8_t*)calloc(j, sizeof(uint8_t));
			digest1 = (uint8_t*)calloc(i + j + TAGBYTES256, sizeof(uint8_t));
			digest2 = (uint8_t*)calloc(i + j + TAGBYTES256, sizeof(uint8_t));

			assert(buf_copy != NULL);
			assert(msg_frag1 != NULL);
			assert(msg_frag2 != NULL);
			assert(digest1 != NULL);
			assert(digest2 != NULL);

			memcpy(buf_copy, buf, i + j);
			memcpy(msg_frag1, buf, i);
			memcpy(msg_frag2, buf + i, j);

			//! Memory copy check
			if (memcmp(buf_copy, msg_frag1, i)) {
				printf("Frag1 memory copy fail\n");
				return;
			}
			if (memcmp(buf_copy + i, msg_frag2, j)) {
				printf("Frag2 memory copy fail\n");
				return;
			}

			//! Digest original message
			__isap_crypto_hash(digest1, buf_copy, i + j);

			//! Digest message fragments
			__isap_Initialization(state);
			__isap_process(state, digest2, msg_frag1, i);
			__isap_process(state, digest2, msg_frag2, j);
			__isap_Finalize(state, digest2);

			//! Error handling
			//! If digest1 != digest2 -> Error
			if (memcmp(digest1, digest2, _msize(digest1))) {
				/*printf("ERROR#%d\n", errnum++);
				printf("Frag1: "); printBlock(msg_frag1);
				printf("Frag2: "); printBlock(msg_frag2);
				printf("buf_copy: "); printBlock(buf_copy);
				printf("digest1: "); printBlock(digest1);
				printf("digest2: "); printBlock(digest2); printf("\n");*/
				flag = 0;
			}
		}
	}

	if (flag) printf("ISAP Update Test Success!\n");
	else printf("ISAP Update Test Failed\n");

	if (digest1)   free(digest1);
	if (digest2)   free(digest2);
	if (msg_frag1) free(msg_frag1);
	if (msg_frag2) free(msg_frag2);
	if (buf)	   free(buf);
	if (buf_copy)  free(buf_copy);
}

/*************************Photon-Beetle*****************************/
void BCT_Photon(uint8_t* Plaintext, size_t size) {

	//! Parameters
	uint8_t* Ciphertext_Origin = NULL;	//! Ciphertext of buf
	uint8_t* Ciphertext_Test = NULL;	//! Ciphertext of buf_copy
	uint8_t* buf = NULL;	//! Copy of Plaintext. Not flipped.
	uint8_t* buf_copy = NULL;	//! Copy od Plaintext. Flipped
	uint8_t* AD = NULL; //! Associated Data
	uint8_t* npub = NULL; //! Nonce
	uint8_t mk[32] = { 0, };			//! Master key
	int i = 0, j = 0;	//! Index for for loops
	int errnum = 1;	//! The number of Errors for debugging
	int flag = 1;	//! Flag will be 0 if the test fails
	unsigned long long clen = size + TAGBYTES; //! Ciphertext size
	unsigned long long* clen_ptr = &clen;			//! Pointer of clen
	const unsigned char* nsec = NULL;			//! We will not use nsec

	//! Memory Allocations
	//! Ciphertext buffer size = Plaintext size + Tag size
	Ciphertext_Origin = (uint8_t*)calloc(size + TAGBYTES, sizeof(uint8_t));
	Ciphertext_Test = (uint8_t*)calloc(size + TAGBYTES, sizeof(uint8_t));
	buf = (uint8_t*)calloc(size, sizeof(uint8_t));
	buf_copy = (uint8_t*)calloc(size, sizeof(uint8_t));
	AD = (uint8_t*)calloc(size, sizeof(uint8_t));
	npub = (uint8_t*)calloc(size, sizeof(uint8_t));

	assert(Ciphertext_Origin != NULL);
	assert(Ciphertext_Test != NULL);
	assert(buf != NULL);
	assert(buf_copy != NULL);
	assert(AD != NULL);
	assert(npub != NULL);

	//! Key Settings
	for (i = 0; i < 16; i++) mk[i] = i * 0x11;
	for (i = 16; i < 24; i++) mk[i] = (i - 16) * 0x11;

	//! Copy 16-bytes from the original Plaintext
	memcpy(buf, Plaintext, 16);

	//! Encrypt Original Plaintext
	__photon_crypto_aead_encrypt(Ciphertext_Origin, clen_ptr, buf, size, AD, size, nsec, npub, mk);

	//! Bit Contribution Test
	for (j = 1; j <= size * 8 - 1; j++) {
		memcpy(buf_copy, Plaintext, 16);

		//! Bit Flipping
		buf_copy[j / 8] ^= 1 << (j % 8);

		//! Encrypt Flipped Plaintext
		*clen_ptr = size;
		__photon_crypto_aead_encrypt(Ciphertext_Test, clen_ptr, buf_copy, size, AD, size, nsec, npub, mk);

		//! If two ciphertexts are same 
		if (!memcmp(Ciphertext_Origin, Ciphertext_Test, size)) {
			printf("ERROR #%d\n", errnum++);
			printf("Ciphertext Origin: "); printBlock(Ciphertext_Origin); printf("\n");
			printf("Ciphertext Test  : "); printBlock(Ciphertext_Test);   printf("\n");
			flag = 0;
		}
	}

	if (flag) printf("Photon-Beetle Bit Contribution Test SUCCESS!\n");

	//! Free Memories
	if (Ciphertext_Origin != NULL)	free(Ciphertext_Origin);
	if (Ciphertext_Test != NULL)	free(Ciphertext_Test);
	if (buf != NULL)				free(buf);
	if (buf_copy != NULL)			free(buf_copy);
	if (AD != NULL)				    free(AD);
	if (npub != NULL)				free(npub);
}
void BET_Photon(uint8_t* Plaintext, size_t size) {

	//! Parameters
	uint8_t* Ciphertext_Origin = NULL;	//! Ciphertext of buf
	uint8_t* Ciphertext_Test = NULL;	//! Ciphertext of buf_copy
	uint8_t* buf = NULL;	//! Copy of Plaintext. Not flipped.
	uint8_t* buf_copy = NULL;	//! Copy od Plaintext. Flipped
	uint8_t* AD = NULL; //! Associated Data
	uint8_t* npub = NULL; //! Nonce
	uint8_t mk[32] = { 0, };			//! Master key
	int i = 0, j = 0;	//! Index for for loops
	int errnum = 1;	//! The number of Errors for debugging
	int flag = 1;	//! Flag will be 0 if the test fails
	unsigned long long clen = size + TAGBYTES; //! Ciphertext size
	unsigned long long* clen_ptr = &clen;	   //! Pointer of clen
	const unsigned char* nsec = NULL;	   //! We will not use nsec

	//! Memory Allocations
	//! Ciphertext buffer size = Plaintext size + Tag size
	//! buf_copy size = size + EXCLUSION_BYTELEN
	Ciphertext_Origin = (uint8_t*)calloc(size + TAGBYTES, sizeof(uint8_t));
	Ciphertext_Test = (uint8_t*)calloc(size + TAGBYTES, sizeof(uint8_t));
	buf = (uint8_t*)calloc(size, sizeof(uint8_t));
	buf_copy = (uint8_t*)calloc(size + EXCLUSION_BYTELEN, sizeof(uint8_t));
	AD = (uint8_t*)calloc(size, sizeof(uint8_t));
	npub = (uint8_t*)calloc(size, sizeof(uint8_t));

	assert(Ciphertext_Origin != NULL);
	assert(Ciphertext_Test != NULL);
	assert(buf != NULL);
	assert(buf_copy != NULL);
	assert(AD != NULL);
	assert(npub != NULL);

	//! Key Settings
	for (i = 0; i < 16; i++) mk[i] = i * 0x11;
	for (i = 16; i < 24; i++) mk[i] = (i - 16) * 0x11;


	for (i = 1; i <= size; i++) {
		//! Copy 16-bytes from the original Plaintext
		memcpy(buf, Plaintext, i);
		//! Encrypt Original Plaintext
		__photon_crypto_aead_encrypt(Ciphertext_Origin, clen_ptr, buf, i, AD, i, nsec, npub, mk);

		for (j = 0; j < EXCLUSION_BYTELEN * 8; j++) {
			//! Flip 
			memcpy(buf_copy, Plaintext, i + 1);
			buf_copy[i + j / 8] ^= 1 << (j % 8);
			__photon_crypto_aead_encrypt(Ciphertext_Test, clen_ptr, buf_copy, i, AD, i, nsec, npub, mk);

			if (memcmp(Ciphertext_Origin, Ciphertext_Test, i)) {
				printf("ERROR #%d\n", errnum++);
				printf("Ciphertext Origin: "); printBlock(Ciphertext_Origin); printf("\n");
				printf("Ciphertext Test  : "); printBlock(Ciphertext_Test);   printf("\n");
				flag = 0;
			}
		}
	}

	if (flag) printf("Photon-Beetle Bit Exclusion Test SUCCESS!\n");

	//! Free memories
	if (Ciphertext_Origin != NULL)	free(Ciphertext_Origin);
	if (Ciphertext_Test != NULL)	free(Ciphertext_Test);
	if (buf != NULL)	free(buf);
	if (buf_copy != NULL)	free(buf_copy);
	if (AD != NULL)	free(AD);
	if (npub != NULL)	free(npub);

	return;
}
/****************************Romulus********************************/
void BCT_RomulusT(uint8_t* Plaintext, size_t size) {
	//! BCT for Schwaemm 256-256
	//! Parameters
	uint8_t* Ciphertext_Origin = NULL;	//! Ciphertext of buf
	uint8_t* Ciphertext_Test = NULL;	//! Ciphertext of buf_copy
	uint8_t* buf = NULL;	//! Copy of Plaintext. Not flipped.
	uint8_t* buf_copy = NULL;	//! Copy od Plaintext. Flipped
	uint8_t* AD = NULL; //! Associated Data
	uint8_t* npub = NULL; //! Nonce
	uint8_t mk[32] = { 0, };			//! Master key
	int i = 0, j = 0;	//! Index for for loops
	int errnum = 1;	//! The number of Errors for debugging
	int flag = 1;	//! Flag will be 0 if the test fails
	unsigned long long clen = size + TAGBYTES256; //! Ciphertext size
	unsigned long long* clen_ptr = &clen;			//! Pointer of clen
	const unsigned char* nsec = NULL;			//! We will not use nsec

	//! Memory Allocations
	//! Ciphertext buffer size = Plaintext size + Tag size
	Ciphertext_Origin = (uint8_t*)calloc(size + TAGBYTES256, sizeof(uint8_t));
	Ciphertext_Test = (uint8_t*)calloc(size + TAGBYTES256, sizeof(uint8_t));
	buf = (uint8_t*)calloc(size, sizeof(uint8_t));
	buf_copy = (uint8_t*)calloc(size, sizeof(uint8_t));
	AD = (uint8_t*)calloc(size, sizeof(uint8_t));
	npub = (uint8_t*)calloc(size, sizeof(uint8_t));

	assert(Ciphertext_Origin != NULL);
	assert(Ciphertext_Test != NULL);
	assert(buf != NULL);
	assert(buf_copy != NULL);
	assert(AD != NULL);
	assert(npub != NULL);

	//! Key Settings
	for (i = 0; i < 16; i++) mk[i] = i * 0x11;
	for (i = 16; i < 24; i++) mk[i] = (i - 16) * 0x11;

	//! Copy 16-bytes from the original Plaintext
	memcpy(buf, Plaintext, 16);

	//! Encrypt Original Plaintext
	romulus_n_encrypt(Ciphertext_Origin, clen_ptr, buf, size, AD, size, nsec, npub, mk);

	//! Bit Contribution Test
	for (j = 1; j <= size * 8 - 1; j++) {
		memcpy(buf_copy, Plaintext, 16);

		//! Bit Flipping
		buf_copy[j / 8] ^= 1 << (j % 8);

		//! Encrypt Flipped Plaintext
		*clen_ptr = size;
		romulus_n_encrypt(Ciphertext_Test, clen_ptr, buf_copy, size, AD, size, nsec, npub, mk);

		//! If two ciphertexts are same 
		if (!memcmp(Ciphertext_Origin, Ciphertext_Test, size)) {
			printf("ERROR #%d\n", errnum++);
			printf("Ciphertext Origin: "); printBlock(Ciphertext_Origin); printf("\n");
			printf("Ciphertext Test  : "); printBlock(Ciphertext_Test);   printf("\n");
			flag = 0;
		}
	}

	if (flag) printf("Romulus Bit Contribution Test SUCCESS!\n");

	//! Free Memories
	if (Ciphertext_Origin != NULL)	free(Ciphertext_Origin);
	if (Ciphertext_Test != NULL)	free(Ciphertext_Test);
	if (buf != NULL)				free(buf);
	if (buf_copy != NULL)			free(buf_copy);
	if (AD != NULL)				    free(AD);
	if (npub != NULL)				free(npub);
}
void BET_RomulusN(uint8_t* Plaintext, size_t size) {

	//! Parameters
	uint8_t* Ciphertext_Origin = NULL;	//! Ciphertext of buf
	uint8_t* Ciphertext_Test = NULL;	//! Ciphertext of buf_copy
	uint8_t* buf = NULL;	//! Copy of Plaintext. Not flipped.
	uint8_t* buf_copy = NULL;	//! Copy od Plaintext. Flipped
	uint8_t* AD = NULL; //! Associated Data
	uint8_t* npub = NULL; //! Nonce
	uint8_t mk[32] = { 0, };			//! Master key
	int i = 0, j = 0;	//! Index for for loops
	int errnum = 1;	//! The number of Errors for debugging
	int flag = 1;	//! Flag will be 0 if the test fails
	unsigned long long clen = size + TAGBYTES; //! Ciphertext size
	unsigned long long* clen_ptr = &clen;	   //! Pointer of clen
	const unsigned char* nsec = NULL;	   //! We will not use nsec

	//! Memory Allocations
	//! Ciphertext buffer size = Plaintext size + Tag size
	//! buf_copy size = size + EXCLUSION_BYTELEN
	Ciphertext_Origin = (uint8_t*)calloc(size + TAGBYTES, sizeof(uint8_t));
	Ciphertext_Test = (uint8_t*)calloc(size + TAGBYTES, sizeof(uint8_t));
	buf = (uint8_t*)calloc(size, sizeof(uint8_t));
	buf_copy = (uint8_t*)calloc(size + EXCLUSION_BYTELEN, sizeof(uint8_t)); // 256bit
	AD = (uint8_t*)calloc(size, sizeof(uint8_t));
	npub = (uint8_t*)calloc(size, sizeof(uint8_t));

	assert(Ciphertext_Origin != NULL);
	assert(Ciphertext_Test != NULL);
	assert(buf != NULL);
	assert(buf_copy != NULL);
	assert(AD != NULL);
	assert(npub != NULL);

	//! Key Settings
	for (i = 0; i < 16; i++) mk[i] = i * 0x11;
	for (i = 16; i < 24; i++) mk[i] = (i - 16) * 0x11;


	for (i = 0; i < size; i++) {
		//! Copy 16-bytes from the original Plaintext
		memcpy(buf, Plaintext, i + 1);

		//! Encrypt Original Plaintext
		romulus_n_encrypt(Ciphertext_Origin, clen_ptr, buf, size, AD, size, nsec, npub, mk);

		for (j = 0; j < EXCLUSION_BYTELEN * 8; j++) { // 128
			//! Flip 
			memcpy(buf_copy, Plaintext, i + 1);
			buf_copy[i + j / 8 + 1] ^= 1 << (j % 8);
			romulus_n_encrypt(Ciphertext_Test, clen_ptr, buf_copy, size, AD, size, nsec, npub, mk);

			if (memcmp(buf, buf_copy, i + 1)) {
				printf("ERROR #%d\n", errnum++);
				printf("Ciphertext Origin: "); printBlock(Ciphertext_Origin); printf("\n");
				printf("Ciphertext Test  : "); printBlock(Ciphertext_Test);   printf("\n");
				flag = 0;
			}
		}
	}

	if (flag) printf("Romulus Bit Exclusion Test SUCCESS!\n");

	//! Free memories
	if (Ciphertext_Origin != NULL)	free(Ciphertext_Origin);
	if (Ciphertext_Test != NULL)	free(Ciphertext_Test);
	if (buf != NULL)	free(buf);
	if (buf_copy != NULL)	free(buf_copy);
	if (AD != NULL)	free(AD);
	if (npub != NULL)	free(npub);

	return;
}


/****************************Sparkle********************************/
void BCT_Sparkle_SCHWAEMM(uint8_t* Plaintext, size_t size) {
	//! BCT for Schwaemm 256-256
	//! Parameters
	uint8_t* Ciphertext_Origin = NULL;	//! Ciphertext of buf
	uint8_t* Ciphertext_Test = NULL;	//! Ciphertext of buf_copy
	uint8_t* buf = NULL;	//! Copy of Plaintext. Not flipped.
	uint8_t* buf_copy = NULL;	//! Copy od Plaintext. Flipped
	uint8_t* AD = NULL; //! Associated Data
	uint8_t* npub = NULL; //! Nonce
	uint8_t mk[32] = { 0, };			//! Master key
	int i = 0, j = 0;	//! Index for for loops
	int errnum = 1;	//! The number of Errors for debugging
	int flag = 1;	//! Flag will be 0 if the test fails
	unsigned long long clen = size + TAGBYTES256; //! Ciphertext size
	unsigned long long* clen_ptr = &clen;			//! Pointer of clen
	const unsigned char* nsec = NULL;			//! We will not use nsec

	//! Memory Allocations
	//! Ciphertext buffer size = Plaintext size + Tag size
	Ciphertext_Origin = (uint8_t*)calloc(size + TAGBYTES256, sizeof(uint8_t));
	Ciphertext_Test = (uint8_t*)calloc(size + TAGBYTES256, sizeof(uint8_t));
	buf = (uint8_t*)calloc(size, sizeof(uint8_t));
	buf_copy = (uint8_t*)calloc(size, sizeof(uint8_t));
	AD = (uint8_t*)calloc(size, sizeof(uint8_t));
	npub = (uint8_t*)calloc(size, sizeof(uint8_t));

	assert(Ciphertext_Origin != NULL);
	assert(Ciphertext_Test != NULL);
	assert(buf != NULL);
	assert(buf_copy != NULL);
	assert(AD != NULL);
	assert(npub != NULL);

	//! Key Settings
	for (i = 0; i < 16; i++) mk[i] = i * 0x11;
	for (i = 16; i < 24; i++) mk[i] = (i - 16) * 0x11;

	//! Copy 16-bytes from the original Plaintext
	memcpy(buf, Plaintext, 16);

	//! Encrypt Original Plaintext
	__sparkle_crypto_aead_encrypt(Ciphertext_Origin, clen_ptr, buf, size, AD, size, nsec, npub, mk);

	//! Bit Contribution Test
	for (j = 1; j <= size * 8 - 1; j++) {
		memcpy(buf_copy, Plaintext, 16);

		//! Bit Flipping
		buf_copy[j / 8] ^= 1 << (j % 8);

		//! Encrypt Flipped Plaintext
		*clen_ptr = size;
		__sparkle_crypto_aead_encrypt(Ciphertext_Test, clen_ptr, buf_copy, size, AD, size, nsec, npub, mk);

		//! If two ciphertexts are same 
		if (!memcmp(Ciphertext_Origin, Ciphertext_Test, size)) {
			printf("ERROR #%d\n", errnum++);
			printf("Ciphertext Origin: "); printBlock(Ciphertext_Origin); printf("\n");
			printf("Ciphertext Test  : "); printBlock(Ciphertext_Test);   printf("\n");
			flag = 0;
		}
	}

	if (flag) printf("Sparkle-SCWAEMM Bit Contribution Test SUCCESS!\n");

	//! Free Memories
	if (Ciphertext_Origin != NULL)	free(Ciphertext_Origin);
	if (Ciphertext_Test != NULL)	free(Ciphertext_Test);
	if (buf != NULL)				free(buf);
	if (buf_copy != NULL)			free(buf_copy);
	if (AD != NULL)				    free(AD);
	if (npub != NULL)				free(npub);
}
void BET_Sparkle_SCHWAEMM(uint8_t* Plaintext, size_t size) {
	//! BET for Schwaemm 256-256
	//! Parameters
	uint8_t* Ciphertext_Origin = NULL;	//! Ciphertext of buf
	uint8_t* Ciphertext_Test = NULL;	//! Ciphertext of buf_copy
	uint8_t* buf = NULL;	//! Copy of Plaintext. Not flipped.
	uint8_t* buf_copy = NULL;	//! Copy od Plaintext. Flipped
	uint8_t* AD = NULL; //! Associated Data
	uint8_t* npub = NULL; //! Nonce
	uint8_t mk[32] = { 0, };			//! Master key
	int i = 0, j = 0;	//! Index for for loops
	int errnum = 1;	//! The number of Errors for debugging
	int flag = 1;	//! Flag will be 0 if the test fails
	unsigned long long clen = size + TAGBYTES256; //! Ciphertext size
	unsigned long long* clen_ptr = &clen;	   //! Pointer of clen
	const unsigned char* nsec = NULL;	   //! We will not use nsec

	//! Memory Allocations
	//! Ciphertext buffer size = Plaintext size + Tag size
	//! buf_copy size = size + EXCLUSION_BYTELEN
	Ciphertext_Origin = (uint8_t*)calloc(size + TAGBYTES256, sizeof(uint8_t));
	Ciphertext_Test = (uint8_t*)calloc(size + TAGBYTES256, sizeof(uint8_t));
	buf = (uint8_t*)calloc(size, sizeof(uint8_t));
	buf_copy = (uint8_t*)calloc(size + EXCLUSION_BYTELEN, sizeof(uint8_t)); // 256bit
	AD = (uint8_t*)calloc(size, sizeof(uint8_t));
	npub = (uint8_t*)calloc(size, sizeof(uint8_t));

	assert(Ciphertext_Origin != NULL);
	assert(Ciphertext_Test != NULL);
	assert(buf != NULL);
	assert(buf_copy != NULL);
	assert(AD != NULL);
	assert(npub != NULL);

	//! Key Settings
	for (i = 0; i < 16; i++) mk[i] = i * 0x11;
	for (i = 16; i < 24; i++) mk[i] = (i - 16) * 0x11;


	for (i = 0; i < size; i++) {
		//! Copy 16-bytes from the original Plaintext
		memcpy(buf, Plaintext, i + 1);

		//! Encrypt Original Plaintext
		__sparkle_crypto_aead_encrypt(Ciphertext_Origin, clen_ptr, buf, size, AD, size, nsec, npub, mk);

		for (j = 0; j < EXCLUSION_BYTELEN * 8; j++) { // 128
			//! Flip 
			memcpy(buf_copy, Plaintext, i + 1);
			buf_copy[i + j / 8 + 1] ^= 1 << (j % 8);
			__sparkle_crypto_aead_encrypt(Ciphertext_Test, clen_ptr, buf_copy, size, AD, size, nsec, npub, mk);

			if (memcmp(buf, buf_copy, i + 1)) {
				printf("ERROR #%d\n", errnum++);
				printf("Ciphertext Origin: "); printBlock(Ciphertext_Origin); printf("\n");
				printf("Ciphertext Test  : "); printBlock(Ciphertext_Test);   printf("\n");
				flag = 0;
			}
		}
	}

	if (flag) printf("Sparkle-SCHWAEMM Bit Exclusion Test SUCCESS!\n");

	//! Free memories
	if (Ciphertext_Origin != NULL)	free(Ciphertext_Origin);
	if (Ciphertext_Test != NULL)	free(Ciphertext_Test);
	if (buf != NULL)	free(buf);
	if (buf_copy != NULL)	free(buf_copy);
	if (AD != NULL)	free(AD);
	if (npub != NULL)	free(npub);

	return;
}
void BCT_Sparkle_ESCH(uint8_t* Plaintext, size_t size) {
	//! BCT for Schwaemm 256-256
	//! Parameters
	uint8_t* Ciphertext_Origin = NULL;	//! Ciphertext of buf
	uint8_t* Ciphertext_Test = NULL;	//! Ciphertext of buf_copy
	uint8_t* buf = NULL;	//! Copy of Plaintext. Not flipped.
	uint8_t* buf_copy = NULL;	//! Copy od Plaintext. Flipped
	uint8_t* AD = NULL; //! Associated Data
	uint8_t* npub = NULL; //! Nonce
	uint8_t mk[32] = { 0, };			//! Master key
	int i = 0, j = 0;	//! Index for for loops
	int errnum = 1;	//! The number of Errors for debugging
	int flag = 1;	//! Flag will be 0 if the test fails
	unsigned long long clen = size + TAGBYTES256; //! Ciphertext size
	unsigned long long* clen_ptr = &clen;			//! Pointer of clen
	const unsigned char* nsec = NULL;			//! We will not use nsec

	//! Memory Allocations
	//! Ciphertext buffer size = Plaintext size + Tag size
	Ciphertext_Origin = (uint8_t*)calloc(size + TAGBYTES256, sizeof(uint8_t));
	Ciphertext_Test = (uint8_t*)calloc(size + TAGBYTES256, sizeof(uint8_t));
	buf = (uint8_t*)calloc(size, sizeof(uint8_t));
	buf_copy = (uint8_t*)calloc(size, sizeof(uint8_t));
	AD = (uint8_t*)calloc(size, sizeof(uint8_t));
	npub = (uint8_t*)calloc(size, sizeof(uint8_t));

	assert(Ciphertext_Origin != NULL);
	assert(Ciphertext_Test != NULL);
	assert(buf != NULL);
	assert(buf_copy != NULL);
	assert(AD != NULL);
	assert(npub != NULL);

	//! Key Settings
	for (i = 0; i < 16; i++) mk[i] = i * 0x11;
	for (i = 16; i < 24; i++) mk[i] = (i - 16) * 0x11;

	//! Copy 16-bytes from the original Plaintext
	memcpy(buf, Plaintext, 16);

	//! Encrypt Original Plaintext
	__sparkle_crypto_hash(Ciphertext_Origin, buf, size);

	//! Bit Contribution Test
	for (j = 1; j <= size * 8 - 1; j++) {
		memcpy(buf_copy, Plaintext, 16);

		//! Bit Flipping
		buf_copy[j / 8] ^= 1 << (j % 8);

		//! Encrypt Flipped Plaintext
		__sparkle_crypto_hash(Ciphertext_Test, buf_copy, size);

		//! If two ciphertexts are same 
		if (!memcmp(Ciphertext_Origin, Ciphertext_Test, size)) {
			printf("ERROR #%d\n", errnum++);
			printf("Ciphertext Origin: "); printBlock(Ciphertext_Origin); printf("\n");
			printf("Ciphertext Test  : "); printBlock(Ciphertext_Test);   printf("\n");
			flag = 0;
		}
	}

	if (flag) printf("Sparkle-ESCH Bit Contribution Test SUCCESS!\n");

	//! Free Memories
	if (Ciphertext_Origin != NULL)	free(Ciphertext_Origin);
	if (Ciphertext_Test != NULL)	free(Ciphertext_Test);
	if (buf != NULL)				free(buf);
	if (buf_copy != NULL)			free(buf_copy);
	if (AD != NULL)				    free(AD);
	if (npub != NULL)				free(npub);
}
void BET_Sparkle_ESCH(uint8_t* Plaintext, size_t size) {
	//! Pass
	//! BET for Schwaemm 256-256
	//! Parameters
	uint8_t* Ciphertext_Origin = NULL;	//! Ciphertext of buf
	uint8_t* Ciphertext_Test = NULL;	//! Ciphertext of buf_copy
	uint8_t* buf = NULL;	//! Copy of Plaintext. Not flipped.
	uint8_t* buf_copy = NULL;	//! Copy od Plaintext. Flipped
	uint8_t* AD = NULL; //! Associated Data
	uint8_t* npub = NULL; //! Nonce
	uint8_t mk[32] = { 0, };			//! Master key
	int i = 0, j = 0;	//! Index for for loops
	int errnum = 1;	//! The number of Errors for debugging
	int flag = 1;	//! Flag will be 0 if the test fails
	unsigned long long clen = size + TAGBYTES256; //! Ciphertext size
	unsigned long long* clen_ptr = &clen;	   //! Pointer of clen
	const unsigned char* nsec = NULL;	   //! We will not use nsec

	//! Memory Allocations
	//! Ciphertext buffer size = Plaintext size + Tag size
	//! buf_copy size = size + EXCLUSION_BYTELEN
	Ciphertext_Origin = (uint8_t*)calloc(size + TAGBYTES256, sizeof(uint8_t));
	Ciphertext_Test = (uint8_t*)calloc(size + TAGBYTES256, sizeof(uint8_t));
	buf = (uint8_t*)calloc(size, sizeof(uint8_t));
	buf_copy = (uint8_t*)calloc(size + EXCLUSION_BYTELEN, sizeof(uint8_t)); // 256bit
	AD = (uint8_t*)calloc(size, sizeof(uint8_t));
	npub = (uint8_t*)calloc(size, sizeof(uint8_t));

	assert(Ciphertext_Origin != NULL);
	assert(Ciphertext_Test != NULL);
	assert(buf != NULL);
	assert(buf_copy != NULL);
	assert(AD != NULL);
	assert(npub != NULL);

	//! Key Settings
	for (i = 0; i < 16; i++) mk[i] = i * 0x11;
	for (i = 16; i < 24; i++) mk[i] = (i - 16) * 0x11;


	for (i = 0; i < size; i++) {
		//! Copy 16-bytes from the original Plaintext
		memcpy(buf, Plaintext, i + 1);

		//! Encrypt Original Plaintext
		__sparkle_crypto_hash(Ciphertext_Origin, buf, i + 1);

		for (j = 0; j < EXCLUSION_BYTELEN * 8; j++) { // 128
			//! Flip 
			memcpy(buf_copy, Plaintext, i + 1);
			buf_copy[i + j / 8 + 1] ^= 1 << (j % 8);
			__sparkle_crypto_hash(Ciphertext_Test, buf_copy, i + 1);

			if (memcmp(buf, buf_copy, i + 1)) {
				printf("ERROR #%d\n", errnum++);
				printf("Ciphertext Origin: "); printBlock(Ciphertext_Origin); printf("\n");
				printf("Ciphertext Test  : "); printBlock(Ciphertext_Test);   printf("\n");
				flag = 0;
			}
		}
	}

	if (flag) printf("Sparkle-ESCH Bit Exclusion Test SUCCESS!\n");

	//! Free memories
	if (Ciphertext_Origin != NULL)	free(Ciphertext_Origin);
	if (Ciphertext_Test != NULL)	free(Ciphertext_Test);
	if (buf != NULL)	free(buf);
	if (buf_copy != NULL)	free(buf_copy);
	if (AD != NULL)	free(AD);
	if (npub != NULL)	free(npub);

	return;
}
void UT_Sparkle_ESCH(uint8_t* Plaintext, size_t size) {
	//! ERROR OCCURED
	//! Parameters
	uint8_t* digest1 = NULL;
	uint8_t* digest2 = NULL;	//! Digested message
	uint8_t* msg_frag1 = NULL;
	uint8_t* msg_frag2 = NULL;	//! Message fragment for update test
	uint8_t* buf = NULL;	//! Copy of Plaintext
	uint8_t* buf_copy = NULL;	//! Copy od Plaintext

	int i = 0, j = 0;	//! Index for for loops
	int errnum = 1;	//! The number of Errors for debugging
	int flag = 1;	//! Flag will be 0 if the test fails

	SparkleState state;

	//! Memory Allocations
	digest1 = (uint8_t*)calloc(SPARKLE_DIGESTLEN, sizeof(uint8_t));
	digest2 = (uint8_t*)calloc(SPARKLE_DIGESTLEN, sizeof(uint8_t));
	buf = (uint8_t*)calloc(size * 2, sizeof(uint8_t)); //32

	assert(digest1 != NULL);
	assert(digest2 != NULL);
	assert(buf != NULL);

	//! Copy plaintext to buf
	memcpy(buf, Plaintext, size);
	memcpy(buf + size, Plaintext, size);

	for (i = 1; i <= size; i++) {
		for (j = 1; j <= size; j++) {
			buf_copy = (uint8_t*)calloc(i + j, sizeof(uint8_t));
			msg_frag1 = (uint8_t*)calloc(i, sizeof(uint8_t));
			msg_frag2 = (uint8_t*)calloc(j, sizeof(uint8_t));

			assert(buf_copy != NULL);
			assert(msg_frag1 != NULL);
			assert(msg_frag2 != NULL);

			memcpy(buf_copy, buf, i + j);
			memcpy(msg_frag1, buf, i);
			memcpy(msg_frag2, buf + i, j);

			//! Memory copy check
			if (memcmp(buf_copy, msg_frag1, i)) {
				printf("Frag1 memory copy fail\n");
				return;
			}
			if (memcmp(buf_copy + i, msg_frag2, j)) {
				printf("Frag2 memory copy fail\n");
				return;
			}

			//! Digest original message
			__sparkle_crypto_hash(digest1, buf_copy, i + j);

			//! Digest message fragments
			__sparkle_Initialize(&state);
			__sparkle_ProcessMessage(&state, msg_frag1, i);
			__sparkle_ProcessMessage(&state, msg_frag2, j);
			__sparkle_Finalize(&state, digest2);

			//! Error handling
			//! If digest1 != digest2 -> Error
			if (memcmp(digest1, digest2, SPARKLE_DIGESTLEN)) {
				/*printf("ERROR#%d\n", errnum++);
				printf("Frag1: "); printBlock(msg_frag1);
				printf("Frag2: "); printBlock(msg_frag2);
				printf("buf_copy: "); printBlock(buf_copy);
				printf("digest1: "); printBlock(digest1);
				printf("digest2: "); printBlock(digest2); printf("\n");*/
				flag = 0;
			}
		}
	}

	if (flag) printf("Sparkle-ESCH Update Test Success!\n");
	else printf("Sparkle-ESCH Update Test Failed\n");

	if (digest1)   free(digest1);
	if (digest2)   free(digest2);
	if (msg_frag1) free(msg_frag1);
	if (msg_frag2) free(msg_frag2);
	if (buf)	   free(buf);
	if (buf_copy)  free(buf_copy);
}
void UT_Sparkle_SCHWAEMM(uint8_t* Plaintext, size_t size) {
	//! ERROR OCCURED	
	//! UT for Schwaemm 256-256
	//! Parameters
	uint8_t* digest1 = NULL;
	uint8_t* digest2 = NULL;	//! Digested message
	uint8_t* msg_frag1 = NULL;
	uint8_t* msg_frag2 = NULL;	//! Message fragment for update test
	uint8_t* buf = NULL;	//! Copy of Plaintext
	uint8_t* buf_copy = NULL;	//! Copy od Plaintext
	uint8_t* npub = NULL; //! Nonce
	uint8_t* AD = NULL;   //! Associated Data
	uint8_t* AD_copy = NULL;   //! Associated Data
	uint8_t mk[16] = { 0, };			//! Master key

	int i = 0, j = 0;	//! Index for for loops
	int errnum = 1;	//! The number of Errors for debugging
	int flag = 1;	//! Flag will be 0 if the test fails
	unsigned long long clen_origin = size + TAGBYTES256; //! Ciphertext size
	unsigned long long clen_copy = size + TAGBYTES256; //! Ciphertext size
	unsigned long long* clenptr_origin = &clen_origin;		//! Pointer of clen
	unsigned long long* clenptr_copy = &clen_copy;		//! Pointer of clen
	unsigned long long ADlen = TAGBYTES256;
	const unsigned char* nsec = NULL;			//! We will not use nsec
	SparkleState state;

	//! Memory Allocations

	buf = (uint8_t*)calloc(size * 2, sizeof(uint8_t)); //32
	npub = (uint8_t*)calloc(size, sizeof(uint8_t));
	AD = (uint8_t*)calloc(size, sizeof(uint8_t));
	AD_copy = (uint8_t*)calloc(size, sizeof(uint8_t));


	assert(buf != NULL);
	assert(npub != NULL);
	assert(AD != NULL);
	assert(AD_copy != NULL);

	//! Copy plaintext to buf
	memcpy(buf, Plaintext, size);
	memcpy(buf + size, Plaintext, size);

	for (i = 1; i <= size; i++) {
		for (j = 1; j <= size; j++) {
			buf_copy = (uint8_t*)calloc(i + j, sizeof(uint8_t));
			msg_frag1 = (uint8_t*)calloc(i, sizeof(uint8_t));
			msg_frag2 = (uint8_t*)calloc(j, sizeof(uint8_t));
			digest1 = (uint8_t*)calloc(i + j + TAGBYTES256, sizeof(uint8_t));
			digest2 = (uint8_t*)calloc(i + j + TAGBYTES256, sizeof(uint8_t));

			assert(buf_copy != NULL);
			assert(msg_frag1 != NULL);
			assert(msg_frag2 != NULL);
			assert(digest1 != NULL);
			assert(digest2 != NULL);

			memcpy(buf_copy, buf, i + j);
			memcpy(msg_frag1, buf, i);
			memcpy(msg_frag2, buf + i, j);

			//! Memory copy check
			if (memcmp(buf_copy, msg_frag1, i)) {
				printf("Frag1 memory copy fail\n");
				return;
			}
			if (memcmp(buf_copy + i, msg_frag2, j)) {
				printf("Frag2 memory copy fail\n");
				return;
			}

			//! Digest original message
			__sparkle_crypto_aead_encrypt(digest1, clenptr_origin, buf_copy, i + j, AD, ADlen, nsec, npub, mk);

			//! Digest message fragments
			__sparkle_AEAD_Initialize(&state, mk, npub);
			if (ADlen) __sparkle_AEAD_ProcessAssocData(&state, AD_copy, ADlen);
			__sparkle_AEAD_ProcessPlainText(&state, digest2, msg_frag1, i);
			__sparkle_AEAD_ProcessPlainText(&state, digest2 + i, msg_frag2, j);
			__sparkle_AEAD_Finalize(&state, mk);
			__sparkle_AEAD_GenerateTag(&state, digest2 + i + j);
			*clenptr_copy = i + j;
			*clenptr_copy += TAGBYTES256;

			//! Error handling
			//! If digest1 != digest2 -> Error
			if (memcmp(digest1, digest2, SPARKLE_DIGESTLEN)) {
				//printf("ERROR#%d\n", errnum++);
				//printf("Frag1: "); printBlock(msg_frag1);
				//printf("Frag2: "); printBlock(msg_frag2);
				//printf("buf_copy: "); printBlock(buf_copy);
				//printf("digest1: "); printBlock(digest1);
				//printf("digest2: "); printBlock(digest2); printf("\n");
				flag = 0;
			}
		}
	}

	if (flag) printf("Sparkle-SCHWAEMM Update Test Success!\n");
	else printf("Sparkle-SCHWAEMM Update Test Failed\n");

	if (digest1)   free(digest1);
	if (digest2)   free(digest2);
	if (msg_frag1) free(msg_frag1);
	if (msg_frag2) free(msg_frag2);
	if (buf)	   free(buf);
	if (buf_copy)  free(buf_copy);
}

/***************************TinyJAMBU*******************************/
void BCT_Tinyjambu(uint8_t* Plaintext, size_t size) {

	//! Parameters
	uint8_t* Ciphertext_Origin = NULL;	//! Ciphertext of buf
	uint8_t* Ciphertext_Test = NULL;	//! Ciphertext of buf_copy
	uint8_t* buf = NULL;	//! Copy of Plaintext. Not flipped.
	uint8_t* buf_copy = NULL;	//! Copy od Plaintext. Flipped
	uint8_t* AD = NULL; //! Associated Data
	uint8_t* npub = NULL; //! Nonce
	uint8_t mk[32] = { 0, };			//! Master key
	int i = 0, j = 0;	//! Index for for loops
	int errnum = 1;	//! The number of Errors for debugging
	int flag = 1;	//! Flag will be 0 if the test fails
	unsigned long long clen = size + TAGBYTES; //! Ciphertext size
	unsigned long long* clen_ptr = &clen;			//! Pointer of clen
	const unsigned char* nsec = NULL;			//! We will not use nsec

	//! Memory Allocations
	//! Ciphertext buffer size = Plaintext size + Tag size
	Ciphertext_Origin = (uint8_t*)calloc(size + TAGBYTES, sizeof(uint8_t));
	Ciphertext_Test = (uint8_t*)calloc(size + TAGBYTES, sizeof(uint8_t));
	buf = (uint8_t*)calloc(size, sizeof(uint8_t));
	buf_copy = (uint8_t*)calloc(size, sizeof(uint8_t));
	AD = (uint8_t*)calloc(size, sizeof(uint8_t));
	npub = (uint8_t*)calloc(size, sizeof(uint8_t));

	assert(Ciphertext_Origin != NULL);
	assert(Ciphertext_Test != NULL);
	assert(buf != NULL);
	assert(buf_copy != NULL);
	assert(AD != NULL);
	assert(npub != NULL);

	//! Key Settings
	for (i = 0; i < 16; i++) mk[i] = i * 0x11;
	for (i = 16; i < 24; i++) mk[i] = (i - 16) * 0x11;

	//! Copy 16-bytes from the original Plaintext
	memcpy(buf, Plaintext, 16);

	//! Encrypt Original Plaintext
	__tinyjambu_crypto_aead_encrypt(Ciphertext_Origin, clen_ptr, buf, size, AD, size, nsec, npub, mk);

	//! Bit Contribution Test
	for (j = 1; j <= size * 8 - 1; j++) {
		memcpy(buf_copy, Plaintext, 16);

		//! Bit Flipping
		buf_copy[j / 8] ^= 1 << (j % 8);

		//! Encrypt Flipped Plaintext
		*clen_ptr = size;
		__tinyjambu_crypto_aead_encrypt(Ciphertext_Test, clen_ptr, buf_copy, size, AD, size, nsec, npub, mk);

		//! If two ciphertexts are same 
		if (!memcmp(Ciphertext_Origin, Ciphertext_Test, size)) {
			printf("ERROR #%d\n", errnum++);
			printf("Ciphertext Origin: "); printBlock(Ciphertext_Origin); printf("\n");
			printf("Ciphertext Test  : "); printBlock(Ciphertext_Test);   printf("\n");
			flag = 0;
		}
	}

	if (flag) printf("TinyJAMBU Bit Contribution Test SUCCESS!\n");

	//! Free Memories
	if (Ciphertext_Origin != NULL)	free(Ciphertext_Origin);
	if (Ciphertext_Test != NULL)	free(Ciphertext_Test);
	if (buf != NULL)				free(buf);
	if (buf_copy != NULL)			free(buf_copy);
	if (AD != NULL)				    free(AD);
	if (npub != NULL)				free(npub);
}
void BET_Tinyjambu(uint8_t* Plaintext, size_t size) {

	//! Parameters
	uint8_t* Ciphertext_Origin = NULL;	//! Ciphertext of buf
	uint8_t* Ciphertext_Test = NULL;	//! Ciphertext of buf_copy
	uint8_t* buf = NULL;	//! Copy of Plaintext. Not flipped.
	uint8_t* buf_copy = NULL;	//! Copy od Plaintext. Flipped
	uint8_t* AD = NULL; //! Associated Data
	uint8_t* npub = NULL; //! Nonce
	uint8_t mk[32] = { 0, };			//! Master key
	int i = 0, j = 0;	//! Index for for loops
	int errnum = 1;	//! The number of Errors for debugging
	int flag = 1;	//! Flag will be 0 if the test fails
	unsigned long long clen = size + TAGBYTES; //! Ciphertext size
	unsigned long long* clen_ptr = &clen;	   //! Pointer of clen
	const unsigned char* nsec = NULL;	   //! We will not use nsec

	//! Memory Allocations
	//! Ciphertext buffer size = Plaintext size + Tag size
	//! buf_copy size = size + EXCLUSION_BYTELEN
	Ciphertext_Origin = (uint8_t*)calloc(size + TAGBYTES, sizeof(uint8_t));
	Ciphertext_Test = (uint8_t*)calloc(size + TAGBYTES, sizeof(uint8_t));
	buf = (uint8_t*)calloc(size, sizeof(uint8_t));
	buf_copy = (uint8_t*)calloc(size + EXCLUSION_BYTELEN, sizeof(uint8_t)); // 256bit
	AD = (uint8_t*)calloc(size, sizeof(uint8_t));
	npub = (uint8_t*)calloc(size, sizeof(uint8_t));

	assert(Ciphertext_Origin != NULL);
	assert(Ciphertext_Test != NULL);
	assert(buf != NULL);
	assert(buf_copy != NULL);
	assert(AD != NULL);
	assert(npub != NULL);

	//! Key Settings
	for (i = 0; i < 16; i++) mk[i] = i * 0x11;
	for (i = 16; i < 24; i++) mk[i] = (i - 16) * 0x11;


	for (i = 0; i < size; i++) {
		//! Copy 16-bytes from the original Plaintext
		memcpy(buf, Plaintext, i + 1);

		//! Encrypt Original Plaintext
		__tinyjambu_crypto_aead_encrypt(Ciphertext_Origin, clen_ptr, buf, size, AD, size, nsec, npub, mk);

		for (j = 0; j < EXCLUSION_BYTELEN * 8; j++) { // 128
			//! Flip 
			memcpy(buf_copy, Plaintext, i + 1);
			buf_copy[i + j / 8 + 1] ^= 1 << (j % 8);
			__tinyjambu_crypto_aead_encrypt(Ciphertext_Test, clen_ptr, buf_copy, size, AD, size, nsec, npub, mk);

			if (memcmp(buf, buf_copy, i + 1)) {
				printf("ERROR #%d\n", errnum++);
				printf("Ciphertext Origin: "); printBlock(Ciphertext_Origin); printf("\n");
				printf("Ciphertext Test  : "); printBlock(Ciphertext_Test);   printf("\n");
				flag = 0;
			}
		}
	}

	if (flag) printf("TinyJAMBU Bit Exclusion Test SUCCESS!\n");

	//! Free memories
	if (Ciphertext_Origin != NULL)	free(Ciphertext_Origin);
	if (Ciphertext_Test != NULL)	free(Ciphertext_Test);
	if (buf != NULL)	free(buf);
	if (buf_copy != NULL)	free(buf_copy);
	if (AD != NULL)	free(AD);
	if (npub != NULL)	free(npub);

	return;
}
void UT_Tinyjambu(uint8_t* Plaintext, size_t size) {
	//! ERROR OCCURED	
	//! UT for Tinyjambu
	//! Parameters
	uint8_t* digest1 = NULL;
	uint8_t* digest2 = NULL;	//! Digested message
	uint8_t* msg_frag1 = NULL;
	uint8_t* msg_frag2 = NULL;	//! Message fragment for update test
	uint8_t* buf = NULL;	//! Copy of Plaintext
	uint8_t* buf_copy = NULL;	//! Copy od Plaintext
	uint8_t* npub = NULL; //! Nonce
	uint8_t* AD = NULL;   //! Associated Data
	uint8_t* AD_copy = NULL;   //! Associated Data
	uint8_t mk[16] = { 0, };			//! Master key

	int i = 0, j = 0;	//! Index for for loops
	int errnum = 1;	//! The number of Errors for debugging
	int flag = 1;	//! Flag will be 0 if the test fails
	unsigned long long clen_origin = size + TAGBYTES256; //! Ciphertext size
	unsigned long long clen_copy = size + TAGBYTES256; //! Ciphertext size
	unsigned long long* clenptr_origin = &clen_origin;		//! Pointer of clen
	unsigned long long* clenptr_copy = &clen_copy;		//! Pointer of clen
	unsigned long long ADlen = TAGBYTES256;
	const unsigned char* nsec = NULL;			//! We will not use nsec
	uint32_t state[4];

	//! Memory Allocations

	buf = (uint8_t*)calloc(size * 2, sizeof(uint8_t)); //32
	npub = (uint8_t*)calloc(size, sizeof(uint8_t));
	AD = (uint8_t*)calloc(size, sizeof(uint8_t));
	AD_copy = (uint8_t*)calloc(size, sizeof(uint8_t));


	assert(buf != NULL);
	assert(npub != NULL);
	assert(AD != NULL);
	assert(AD_copy != NULL);

	//! Copy plaintext to buf
	memcpy(buf, Plaintext, size);
	memcpy(buf + size, Plaintext, size);

	for (i = 1; i <= size; i++) {
		for (j = 1; j <= size; j++) {
			buf_copy = (uint8_t*)calloc(i + j, sizeof(uint8_t));
			msg_frag1 = (uint8_t*)calloc(i, sizeof(uint8_t));
			msg_frag2 = (uint8_t*)calloc(j, sizeof(uint8_t));
			digest1 = (uint8_t*)calloc(i + j + TAGBYTES256, sizeof(uint8_t));
			digest2 = (uint8_t*)calloc(i + j + TAGBYTES256, sizeof(uint8_t));

			assert(buf_copy != NULL);
			assert(msg_frag1 != NULL);
			assert(msg_frag2 != NULL);
			assert(digest1 != NULL);
			assert(digest2 != NULL);

			memcpy(buf_copy, buf, i + j);
			memcpy(msg_frag1, buf, i);
			memcpy(msg_frag2, buf + i, j);

			//! Memory copy check
			if (memcmp(buf_copy, msg_frag1, i)) {
				printf("Frag1 memory copy fail\n");
				return;
			}
			if (memcmp(buf_copy + i, msg_frag2, j)) {
				printf("Frag2 memory copy fail\n");
				return;
			}

			//! Digest original message
			__tinyjambu_crypto_aead_encrypt(digest1, clenptr_origin, buf_copy, i + j, AD, ADlen, nsec, npub, mk);

			//! Digest message fragments
			__tinyjambu_aead_Initialize(state, npub, mk);
			__tinyjambu_aead_ADProcess(state, mk, AD, ADlen);
			__tinyjambu_aead_PTProcess(state, msg_frag1, i, digest2, mk);
			__tinyjambu_aead_PTProcess(state, msg_frag2, j, digest2, mk);
			__tinyjambu_aead_Finalize(state, digest2, clenptr_copy, i + j, mk);
			*clenptr_copy = i + j;
			*clenptr_copy += TAGBYTES256;

			//! Error handling
			//! If digest1 != digest2 -> Error
			if (memcmp(digest1, digest2, _msize(digest1))) {
				/*printf("ERROR#%d\n", errnum++);
				printf("Frag1: "); printBlock(msg_frag1);
				printf("Frag2: "); printBlock(msg_frag2);
				printf("buf_copy: "); printBlock(buf_copy);
				printf("digest1: "); printBlock(digest1);
				printf("digest2: "); printBlock(digest2); printf("\n");*/
				flag = 0;
			}
		}
	}

	if (flag) printf("TinyJAMBU Update Test Success!\n");
	else printf("TinyJAMBU Update Test Failed\n");

	if (digest1)   free(digest1);
	if (digest2)   free(digest2);
	if (msg_frag1) free(msg_frag1);
	if (msg_frag2) free(msg_frag2);
	if (buf)	   free(buf);
	if (buf_copy)  free(buf_copy);
}

/****************************Xoodyak********************************/
void BCT_Xoodoo(uint8_t* Plaintext, size_t size) {

	//! Parameters
	uint8_t* Ciphertext_Origin = NULL;	//! Ciphertext of buf
	uint8_t* Ciphertext_Test = NULL;	//! Ciphertext of buf_copy
	uint8_t* buf = NULL;	//! Copy of Plaintext. Not flipped.
	uint8_t* buf_copy = NULL;	//! Copy od Plaintext. Flipped
	uint8_t* AD = NULL; //! Associated Data
	uint8_t* npub = NULL; //! Nonce
	uint8_t mk[32] = { 0, };			//! Master key
	int i = 0, j = 0;	//! Index for for loops
	int errnum = 1;	//! The number of Errors for debugging
	int flag = 1;	//! Flag will be 0 if the test fails
	unsigned long long clen = size + TAGBYTES; //! Ciphertext size
	unsigned long long* clen_ptr = &clen;			//! Pointer of clen
	const unsigned char* nsec = NULL;			//! We will not use nsec

	//! Memory Allocations
	//! Ciphertext buffer size = Plaintext size + Tag size
	Ciphertext_Origin = (uint8_t*)calloc(size + TAGBYTES, sizeof(uint8_t));
	Ciphertext_Test = (uint8_t*)calloc(size + TAGBYTES, sizeof(uint8_t));
	buf = (uint8_t*)calloc(size, sizeof(uint8_t));
	buf_copy = (uint8_t*)calloc(size, sizeof(uint8_t));
	AD = (uint8_t*)calloc(size, sizeof(uint8_t));
	npub = (uint8_t*)calloc(size, sizeof(uint8_t));

	assert(Ciphertext_Origin != NULL);
	assert(Ciphertext_Test != NULL);
	assert(buf != NULL);
	assert(buf_copy != NULL);
	assert(AD != NULL);
	assert(npub != NULL);

	//! Key Settings
	for (i = 0; i < 16; i++) mk[i] = i * 0x11;
	for (i = 16; i < 24; i++) mk[i] = (i - 16) * 0x11;

	//! Copy 16-bytes from the original Plaintext
	memcpy(buf, Plaintext, 16);

	//! Encrypt Original Plaintext
	__Xoodoo_crypto_aead_encrypt(Ciphertext_Origin, clen_ptr, buf, size, AD, size, nsec, npub, mk);

	//! Bit Contribution Test
	for (j = 1; j <= size * 8 - 1; j++) {
		memcpy(buf_copy, Plaintext, 16);

		//! Bit Flipping
		buf_copy[j / 8] ^= 1 << (j % 8);

		//! Encrypt Flipped Plaintext
		*clen_ptr = size;
		__Xoodoo_crypto_aead_encrypt(Ciphertext_Test, clen_ptr, buf_copy, size, AD, size, nsec, npub, mk);

		//! If two ciphertexts are same 
		if (!memcmp(Ciphertext_Origin, Ciphertext_Test, size)) {
			printf("ERROR #%d\n", errnum++);
			printf("Ciphertext Origin: "); printBlock(Ciphertext_Origin); printf("\n");
			printf("Ciphertext Test  : "); printBlock(Ciphertext_Test);   printf("\n");
			flag = 0;
		}
	}

	if (flag) printf("Xoodyak Bit Contribution Test SUCCESS!\n");

	//! Free Memories
	if (Ciphertext_Origin != NULL)	free(Ciphertext_Origin);
	if (Ciphertext_Test != NULL)	free(Ciphertext_Test);
	if (buf != NULL)				free(buf);
	if (buf_copy != NULL)			free(buf_copy);
	if (AD != NULL)				    free(AD);
	if (npub != NULL)				free(npub);
}
void BET_Xoodoo(uint8_t* Plaintext, size_t size) {

	//! Parameters
	uint8_t* Ciphertext_Origin = NULL;	//! Ciphertext of buf
	uint8_t* Ciphertext_Test = NULL;	//! Ciphertext of buf_copy
	uint8_t* buf = NULL;	//! Copy of Plaintext. Not flipped.
	uint8_t* buf_copy = NULL;	//! Copy od Plaintext. Flipped
	uint8_t* AD = NULL; //! Associated Data
	uint8_t* npub = NULL; //! Nonce
	uint8_t mk[32] = { 0, };			//! Master key
	int i = 0, j = 0;	//! Index for for loops
	int errnum = 1;	//! The number of Errors for debugging
	int flag = 1;	//! Flag will be 0 if the test fails
	unsigned long long clen = size + TAGBYTES; //! Ciphertext size
	unsigned long long* clen_ptr = &clen;	   //! Pointer of clen
	const unsigned char* nsec = NULL;	   //! We will not use nsec

	//! Memory Allocations
	//! Ciphertext buffer size = Plaintext size + Tag size
	//! buf_copy size = size + EXCLUSION_BYTELEN
	Ciphertext_Origin = (uint8_t*)calloc(size + TAGBYTES, sizeof(uint8_t));
	Ciphertext_Test = (uint8_t*)calloc(size + TAGBYTES, sizeof(uint8_t));
	buf = (uint8_t*)calloc(size, sizeof(uint8_t));
	buf_copy = (uint8_t*)calloc(size + EXCLUSION_BYTELEN, sizeof(uint8_t));
	AD = (uint8_t*)calloc(size, sizeof(uint8_t));
	npub = (uint8_t*)calloc(size, sizeof(uint8_t));

	assert(Ciphertext_Origin != NULL);
	assert(Ciphertext_Test != NULL);
	assert(buf != NULL);
	assert(buf_copy != NULL);
	assert(AD != NULL);
	assert(npub != NULL);

	//! Key Settings
	for (i = 0; i < 16; i++) mk[i] = i * 0x11;
	for (i = 16; i < 24; i++) mk[i] = (i - 16) * 0x11;


	for (i = 1; i <= size; i++) {
		//! Copy 16-bytes from the original Plaintext
		memcpy(buf, Plaintext, i);

		//! Encrypt Original Plaintext
		__Xoodoo_crypto_aead_encrypt(Ciphertext_Origin, clen_ptr, buf, i, AD, i, nsec, npub, mk);

		for (j = 0; j < EXCLUSION_BYTELEN * 8; j++) { // 128
			//! Flip 
			memcpy(buf_copy, Plaintext, i + 1);
			buf_copy[i + j / 8] ^= 1 << (j % 8);
			__Xoodoo_crypto_aead_encrypt(Ciphertext_Test, clen_ptr, buf_copy, i, AD, i, nsec, npub, mk);

			if (memcmp(Ciphertext_Origin, Ciphertext_Test, i)) {
				printf("ERROR #%d\n", errnum++);
				printf("Ciphertext Origin: "); printBlock(Ciphertext_Origin); printf("\n");
				printf("Ciphertext Test  : "); printBlock(Ciphertext_Test);   printf("\n");
				flag = 0;
			}
		}
	}

	if (flag) printf("Xoodyak Bit Exclusion Test SUCCESS!\n");

	//! Free memories
	if (Ciphertext_Origin != NULL)	free(Ciphertext_Origin);
	if (Ciphertext_Test != NULL)	free(Ciphertext_Test);
	if (buf != NULL)	free(buf);
	if (buf_copy != NULL)	free(buf_copy);
	if (AD != NULL)	free(AD);
	if (npub != NULL)	free(npub);

	return;
}
void UT_Xoodoo_Hash(uint8_t* Plaintext, size_t size) {
	//! ERROR OCCURED
	//! Parameters
	uint8_t* digest1 = NULL;
	uint8_t* digest2 = NULL;	//! Digested message
	uint8_t* msg_frag1 = NULL;
	uint8_t* msg_frag2 = NULL;	//! Message fragment for update test
	uint8_t* buf = NULL;	//! Copy of Plaintext
	uint8_t* buf_copy = NULL;	//! Copy od Plaintext

	int i = 0, j = 0;	//! Index for for loops
	int errnum = 1;	//! The number of Errors for debugging
	int flag = 1;	//! Flag will be 0 if the test fails

	Xoodyak_Instance state;

	//! Memory Allocations
	digest1 = (uint8_t*)calloc(DIGESTLEN, sizeof(uint8_t));
	digest2 = (uint8_t*)calloc(DIGESTLEN, sizeof(uint8_t));
	buf = (uint8_t*)calloc(size * 2, sizeof(uint8_t)); //32

	assert(digest1 != NULL);
	assert(digest2 != NULL);
	assert(buf != NULL);

	//! Copy plaintext to buf
	memcpy(buf, Plaintext, size);
	memcpy(buf + size, Plaintext, size);

	for (i = 1; i <= size; i++) {
		for (j = 1; j <= size; j++) {
			buf_copy = (uint8_t*)calloc(i + j, sizeof(uint8_t));
			msg_frag1 = (uint8_t*)calloc(i, sizeof(uint8_t));
			msg_frag2 = (uint8_t*)calloc(j, sizeof(uint8_t));

			assert(buf_copy != NULL);
			assert(msg_frag1 != NULL);
			assert(msg_frag2 != NULL);

			memcpy(buf_copy, buf, i + j);
			memcpy(msg_frag1, buf, i);
			memcpy(msg_frag2, buf + i, j);

			//! Memory copy check
			if (memcmp(buf_copy, msg_frag1, i)) {
				printf("Frag1 memory copy fail\n");
				return;
			}
			if (memcmp(buf_copy + i, msg_frag2, j)) {
				printf("Frag2 memory copy fail\n");
				return;
			}

			//! Digest original message
			__Xoodoo_crypto_hash(digest1, buf_copy, i + j);

			//! Digest message fragments
			Xoodyak_Initialize(&state, NULL, 0, NULL, 0, NULL, 0);
			Xoodyak_Absorb(&state, msg_frag1, i);
			Xoodyak_Absorb(&state, msg_frag2, j);
			Xoodyak_Squeeze(&state, digest2, 32);

			//! Error handling
			//! If digest1 != digest2 -> Error
			if (memcmp(digest1, digest2, DIGESTLEN)) {
				//printf("ERROR#%d\n", errnum++);
				//printf("Frag1: "); printBlock(msg_frag1);
				//printf("Frag2: "); printBlock(msg_frag2);
				//printf("buf_copy: "); printBlock(buf_copy);
				//printf("digest1: "); printBlock(digest1);
				//printf("digest2: "); printBlock(digest2); printf("\n");
				flag = 0;
			}
		}
	}

	if (flag) printf("Update Test Success!\n");
	else printf("Xoodyak Update Test Failed\n");

	if (digest1)   free(digest1);
	if (digest2)   free(digest2);
	if (msg_frag1) free(msg_frag1);
	if (msg_frag2) free(msg_frag2);
	if (buf)	   free(buf);
	if (buf_copy)  free(buf_copy);
}
