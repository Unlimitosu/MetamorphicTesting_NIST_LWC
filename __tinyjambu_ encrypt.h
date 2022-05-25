
int __tinyjambu_crypto_aead_encrypt(
	unsigned char* c, unsigned long long* clen,
	const unsigned char* m, unsigned long long mlen,
	const unsigned char* ad, unsigned long long adlen,
	const unsigned char* nsec,
	const unsigned char* npub,
	const unsigned char* k
);

int __tinyjambu_crypto_aead_decrypt(
	unsigned char* c, unsigned long long* clen,
	const unsigned char* m, unsigned long long mlen,
	const unsigned char* ad, unsigned long long adlen,
	const unsigned char* nsec,
	const unsigned char* npub,
	const unsigned char* k
);
void __tinyjambu_aead_Initialize(unsigned int* state, const unsigned char* npub, const unsigned char* k);
void __tinyjambu_aead_ADProcess(unsigned int* state, const unsigned char* k, const unsigned char* ad, unsigned long long adlen);
void __tinyjambu_aead_PTProcess(unsigned int* state, const unsigned char* m,
	unsigned long long mlen, unsigned char* c, const unsigned char* k);
void __tinyjambu_aead_Finalize(unsigned int* state, unsigned char* c, unsigned long long* clen,
	unsigned long long mlen, const unsigned char* k);