#include <ascon_api.h>

void ascon_init(ascon_ctx_t *c) {
  c->x[0] = ASCON_XOF_IV;
  c->x[1] = 0;
  c->x[2] = 0;
  c->x[3] = 0;
  c->x[4] = 0;

#ifdef SLOTH
  ascon_p12(c);
#else
  P12(c);
#endif
}

void ascon_absorb(ascon_ctx_t *c, const uint8_t *in, uint64_t inlen) {
  while (inlen >= ASCON_HASH_RATE) {
    c->x[0] ^= LOADBYTES(in, 8);
#ifdef SLOTH
    ascon_p12(c);
#else
    P12(c);
#endif
    in += ASCON_HASH_RATE;
    inlen -= ASCON_HASH_RATE;
  }
  /* absorb final plaintext block */
  c->x[0] ^= LOADBYTES(in, inlen);
  c->x[0] ^= PAD(inlen);
#ifdef SLOTH
  ascon_p12(c);
#else
  P12(c);
#endif
}

void ascon_squeeze(ascon_ctx_t *c, uint8_t *out, uint64_t outlen) {
  while (outlen > ASCON_HASH_RATE) {
    STOREBYTES(out, c->x[0], 8);
#ifdef SLOTH
    ascon_p12(c);
#else
    P12(c);
#endif
    out += ASCON_HASH_RATE;
    outlen -= ASCON_HASH_RATE;
  }
  /* squeeze final output block */
  STOREBYTES(out, c->x[0], outlen);
}
int crypto_hash(unsigned char *out, const unsigned char *in,
                unsigned long long len) {
  /* initialize */
  ascon_ctx_t s;
  s.x[0] = ASCON_XOF_IV;
  s.x[1] = 0;
  s.x[2] = 0;
  s.x[3] = 0;
  s.x[4] = 0;
#ifdef SLOTH
  ascon_p12(&s);
#else
  P12(&s);
#endif

  /* absorb full plaintext blocks */
  while (len >= ASCON_HASH_RATE) {
    s.x[0] ^= LOADBYTES(in, 8);
#ifdef SLOTH
    ascon_p12(&s);
#else
    P12(&s);
#endif
    in += ASCON_HASH_RATE;
    len -= ASCON_HASH_RATE;
  }
  /* absorb final plaintext block */
  s.x[0] ^= LOADBYTES(in, len);
  s.x[0] ^= PAD(len);
#ifdef SLOTH
  ascon_p12(&s);
#else
  P12(&s);
#endif

  /* squeeze full output blocks */
  len = CRYPTO_BYTES;
  while (len > ASCON_HASH_RATE) {
    STOREBYTES(out, s.x[0], 8);
#ifdef SLOTH
    ascon_p12(&s);
#else
    P12(&s);
#endif
    out += ASCON_HASH_RATE;
    len -= ASCON_HASH_RATE;
  }
  /* squeeze final output block */
  STOREBYTES(out, s.x[0], len);

  return 0;
}
