#include "__ascon_api.h"
#include "__ascon_ascon.h"
//#include "__ascon_crypto_hash.h"
#include "__ascon_permutations.h"
#include "__ascon_printstate.h"
#include "__ascon_word.h"

int __ascon_crypto_hash(unsigned char* out, const unsigned char* in,
                unsigned long long len) {
  /* initialize */
  state_t s;
  s.x0 = ASCON_HASH_IV;
  s.x1 = 0;
  s.x2 = 0;
  s.x3 = 0;
  s.x4 = 0;
  P12(&s);
  printstate("initialization", &s);

  /* absorb full plaintext blocks */
  while (len >= ASCON_HASH_RATE) {
    s.x0 ^= LOADBYTES(in, 8);
    P12(&s);
    in += ASCON_HASH_RATE;
    len -= ASCON_HASH_RATE;
  }
  /* absorb final plaintext block */
  s.x0 ^= LOADBYTES(in, len);
  s.x0 ^= PAD(len);
  P12(&s);
  printstate("absorb plaintext", &s);

  /* squeeze full output blocks */
  len = CRYPTO_BYTES;
  while (len > ASCON_HASH_RATE) {
    STOREBYTES(out, s.x0, 8);
    P12(&s);
    out += ASCON_HASH_RATE;
    len -= ASCON_HASH_RATE;
  }
  /* squeeze final output block */
  STOREBYTES(out, s.x0, len);
  printstate("squeeze output", &s);

  return 0;
}
