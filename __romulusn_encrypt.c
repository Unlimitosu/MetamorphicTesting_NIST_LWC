/*
 * Date: 21 April 2021
 * Contact: Romulus Team (Mustafa Khairallah - mustafa.khairallah@ntu.edu.sg)
 * Romulus-N as compliant with the Romulus v1.3 specifications. 
 * This file icludes crypto_aead_encrypt()
 * It superseeds earlier versions developed by Mustafa Khairallah and maintained
 * by Mustafa Khairallah, Thomas Peyrin and Kazuhiko Minematsu
 */

//#include "crypto_aead.h"
#include "__romulusn_api.h"
#include "__romulusn_variant.h"
#include "__romulusn_skinny.h"
#include "__romulusn_romulus_n.h"


int __romulusn_crypto_aead_encrypt (
			 unsigned char* c, unsigned long long* clen,
			 const unsigned char* m, unsigned long long mlen,
			 const unsigned char* ad, unsigned long long adlen,
			 const unsigned char* nsec,
			 const unsigned char* npub,
			 const unsigned char* k
			 )
{
  return romulus_n_encrypt(c,clen,m,mlen,ad,adlen,nsec,npub,k);
}

