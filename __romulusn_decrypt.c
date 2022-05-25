/*
 * Date: 21 April 2021
 * Contact: Romulus Team (Mustafa Khairallah - mustafa.khairallah@ntu.edu.sg)
 * Romulus-N as compliant with the Romulus v1.3 specifications. 
 * This file icludes crypto_aead_decrypt()
 * It superseeds earlier versions developed by Mustafa Khairallah and maintained
 * by Mustafa Khairallah, Thomas Peyrin and Kazuhiko Minematsu
 */

//#include "crypto_aead.h"
#include "__romulusn_api.h"
#include "__romulusn_variant.h"
#include "__romulusn_skinny.h"
#include "__romulusn_romulus_n.h"

int __romulusn_crypto_aead_decrypt(
unsigned char *m,unsigned long long *mlen,
unsigned char *nsec,
const unsigned char *c,unsigned long long clen,
const unsigned char *ad,unsigned long long adlen,
const unsigned char *npub,
const unsigned char *k
)
{

  return romulus_n_decrypt(m,mlen,nsec,c,clen,ad,adlen,npub,k);
  
}
