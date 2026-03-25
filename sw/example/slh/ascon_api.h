//  ascon_api.h
//  Carlos Fernández-García
//  SP800-232

#ifndef _ASCON_API_H_
#define _ASCON_API_H_

#include <stdint.h>

#define CRYPTO_BYTES 64
#define ASCON_HASH_BYTES 0 /* XOF */
#define ASCON_HASH_ROUNDS 12
#define ASCON_VARIANT 3

#define ASCON_XOF_VARIANT 3
#define ASCON_PA_ROUNDS 12
#define ASCON_HASH_PB_ROUNDS 12
#define ASCON_HASH_RATE 8
#define ASCON_XOF_IV                                                           \
  (((uint64_t)(ASCON_XOF_VARIANT) << 0) |                                      \
   ((uint64_t)(ASCON_PA_ROUNDS) << 16) |                                       \
   ((uint64_t)(ASCON_HASH_PB_ROUNDS) << 20) |                                  \
   ((uint64_t)(ASCON_HASH_RATE) << 40))

typedef struct {
  uint64_t x[5];
} ascon_ctx_t;
//---------------------------------------------
// Ascon Round Function Code
//---------------------------------------------
static inline uint64_t ROR(uint64_t x, int n) {
  return x >> n | x << (-n & 63);
}
static inline void ROUND(ascon_ctx_t *s, uint8_t C) {
  ascon_ctx_t t;
  /* addition of round constant */
  s->x[2] ^= C;
  /* printstate(" round constant", s); */
  /* substitution layer */
  s->x[0] ^= s->x[4];
  s->x[4] ^= s->x[3];
  s->x[2] ^= s->x[1];
  /* start of keccak s-box */
  t.x[0] = s->x[0] ^ (~s->x[1] & s->x[2]);
  t.x[1] = s->x[1] ^ (~s->x[2] & s->x[3]);
  t.x[2] = s->x[2] ^ (~s->x[3] & s->x[4]);
  t.x[3] = s->x[3] ^ (~s->x[4] & s->x[0]);
  t.x[4] = s->x[4] ^ (~s->x[0] & s->x[1]);
  /* end of keccak s-box */
  t.x[1] ^= t.x[0];
  t.x[0] ^= t.x[4];
  t.x[3] ^= t.x[2];
  t.x[2] = ~t.x[2];
  /* printstate(" substitution layer", &t); */
  /* linear diffusion layer */
  s->x[0] = t.x[0] ^ ROR(t.x[0], 19) ^ ROR(t.x[0], 28);
  s->x[1] = t.x[1] ^ ROR(t.x[1], 61) ^ ROR(t.x[1], 39);
  s->x[2] = t.x[2] ^ ROR(t.x[2], 1) ^ ROR(t.x[2], 6);
  s->x[3] = t.x[3] ^ ROR(t.x[3], 10) ^ ROR(t.x[3], 17);
  s->x[4] = t.x[4] ^ ROR(t.x[4], 7) ^ ROR(t.x[4], 41);
}
//---------------------------------------------
//---------------------------------------------
//---------------------------------------------
// Ascon Permutations Code
//---------------------------------------------
static inline void P12(ascon_ctx_t *s) {
  ROUND(s, 0xf0);
  ROUND(s, 0xe1);
  ROUND(s, 0xd2);
  ROUND(s, 0xc3);
  ROUND(s, 0xb4);
  ROUND(s, 0xa5);
  ROUND(s, 0x96);
  ROUND(s, 0x87);
  ROUND(s, 0x78);
  ROUND(s, 0x69);
  ROUND(s, 0x5a);
  ROUND(s, 0x4b);
}

static inline void P8(ascon_ctx_t *s) {
  ROUND(s, 0xb4);
  ROUND(s, 0xa5);
  ROUND(s, 0x96);
  ROUND(s, 0x87);
  ROUND(s, 0x78);
  ROUND(s, 0x69);
  ROUND(s, 0x5a);
  ROUND(s, 0x4b);
}

static inline void P6(ascon_ctx_t *s) {
  ROUND(s, 0x96);
  ROUND(s, 0x87);
  ROUND(s, 0x78);
  ROUND(s, 0x69);
  ROUND(s, 0x5a);
  ROUND(s, 0x4b);
}
//---------------------------------------------
//---------------------------------------------
//---------------------------------------------
// Ascon Byte/Word Manage Code
//---------------------------------------------
/* get byte from 64-bit Ascon word */
#define GETBYTE(x, i) ((uint8_t)((uint64_t)(x) >> (8 * (i))))

/* set byte in 64-bit Ascon word */
#define SETBYTE(b, i) ((uint64_t)(b) << (8 * (i)))

/* set padding byte in 64-bit Ascon word */
#define PAD(i) SETBYTE(0x01, i)

/* define domain separation bit in 64-bit Ascon word */
#define DSEP() SETBYTE(0x80, 7)

/* load bytes into 64-bit Ascon word */
static inline uint64_t LOADBYTES(const uint8_t* bytes, int n) {
  int i;
  uint64_t x = 0;
  for (i = 0; i < n; ++i) x |= SETBYTE(bytes[i], i);
  return x;
}

/* store bytes from 64-bit Ascon word */
static inline void STOREBYTES(uint8_t* bytes, uint64_t x, int n) {
  int i;
  for (i = 0; i < n; ++i) bytes[i] = GETBYTE(x, i);
}

/* clear bytes in 64-bit Ascon word */
static inline uint64_t CLEARBYTES(uint64_t x, int n) {
  int i;
  for (i = 0; i < n; ++i) x &= ~SETBYTE(0xff, i);
  return x;
}
//---------------------------------------------
//Ascon XOF components functions prototype declaration
//---------------------------------------------
void ascon_init(ascon_ctx_t *c);
void ascon_absorb(ascon_ctx_t *c, const uint8_t *in, uint64_t inlen);
void ascon_squeeze(ascon_ctx_t *c, uint8_t *out, uint64_t outlen);
//---------------------------------------------
//---------------------------------------------
// Ascon XOF function prototype declaration
//---------------------------------------------
int crypto_hash(unsigned char *out, const unsigned char *in,
                unsigned long long inlen);
//---------------------------------------------
#endif // !_ASCON_API_H_
