/*
GIFT-128 implementation
Written by: Siang Meng Sim
Email: crypto.s.m.sim@gmail.com
Date: 08 Feb 2019
*/

#include <stdint.h>

void giftb128(uint8_t P[16], const uint8_t K[16], uint8_t C[16]);
void __gift_cofb_encrypt(unsigned char* c, unsigned char* k, unsigned char* n,
    unsigned char* a, unsigned abytes,
    unsigned char* p, unsigned pbytes);
int __gift_cofb_decrypt(unsigned char* p, unsigned char* k, unsigned char* n,
    unsigned char* a, unsigned abytes,
    unsigned char* c, unsigned cbytes);
int __gift_crypto_aead_encrypt(
    unsigned char* c, unsigned long long* clen,
    const unsigned char* m, unsigned long long mlen,
    const unsigned char* ad, unsigned long long adlen,
    const unsigned char* nsec,
    const unsigned char* npub,
    const unsigned char* k
);

int __gift_crypto_aead_decrypt(
    unsigned char* m, unsigned long long* mlen,
    unsigned char* nsec,
    const unsigned char* c, unsigned long long clen,
    const unsigned char* ad, unsigned long long adlen,
    const unsigned char* npub,
    const unsigned char* k
);