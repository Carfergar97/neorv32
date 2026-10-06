//  slh_ascon.c
//  Carlos Fernández-García

//  === SLotH: Accelerated functions for instantiation of SLH-DSA with Ascon-XOF

#ifdef SLOTH_ASCON

#include "slh_ctx.h"
#include "slh_adrs.h"
#include "ascon_api.h"
#include "sloth_hal.h"
#include <string.h>

//  compression function instatiation for ascon_api.c

void ascon_p12(void *v)
{
    uint32_t *v32 = (uint32_t *) v;
    volatile uint32_t   *r32 = (volatile uint32_t *) ASCON_BASE_ADDR;
    int i;

    for (i = 0; i < 10; i++) {              //  actually slow part 1
        r32[i] = v32[i];
    }
    r32[ASCON_STOP] = 0x4b;                  //  stop position
    r32[ASCON_TRIG] = 0xF0;                  //  start it 0xf0 --> 12 rounds
    ASCON_WAIT

    for (i = 0; i < 10; i++) {              //  actually slow part 2
        v32[i] = r32[i];
    }
}

//  === 10.1.   SLH-DSA Using ASCON-XOF128

//  Hmsg(R, PK.seed, PK.root, M) = ASCON-XOF128(R || PK.seed || PK.root || M, 8m)

static void ascon_h_msg( slh_ctx_t *ctx,
                            uint8_t *h,
                            const uint8_t *r,
                            const uint8_t *m, size_t m_sz)
{
    ascon_ctx_t ascon;
    size_t  n = ctx->prm->n;

    ascon_init(&ascon);
    ascon_absorb(&ascon, r, n);
    ascon_absorb(&ascon, ctx->pk_seed, n);
    ascon_absorb(&ascon, ctx->pk_root, n);
    ascon_absorb(&ascon, m, m_sz);

    ascon_squeeze(&ascon, h, ctx->prm->m);
}

//  F(PK.seed, ADRS, M1 ) = ASCON-XOF128(PK.seed || ADRS || M1, 8n)

static void ascon_f_16( slh_ctx_t *ctx,
                            uint8_t *h,
                            const uint8_t *m1)
{
    volatile uint32_t   *r32 = (volatile uint32_t *) ASCON_BASE_ADDR;

    block_copy_16(r32, m1);

    r32[ASCON_CHNS]  =   1;                  //  one iteration
    ASCON_WAIT

    block_copy_16(h, (const void *) r32);
}

//  PRF(PK.seed, SK.seed, ADRS) = ASCON-XOF128(PK.seed || ADRS || SK.seed, 8n)

static void ascon_prf_16(slh_ctx_t *ctx, uint8_t *h)
{
    volatile uint32_t   *r32 = (volatile uint32_t *) ASCON_BASE_ADDR;

    //  PRF
    r32[ASCON_CHNS]  =   0x40;
    ASCON_WAIT
    block_copy_16(h, r32);
}

//  PRFmsg (SK.prf, opt_rand, M) = ASCON-XOF128(SK.prf || opt_rand || M, 8n)

static void ascon_prf_msg(  slh_ctx_t *ctx,
                                uint8_t *h,
                                const uint8_t *opt_rand,
                                const uint8_t *m, size_t m_sz)
{
    ascon_ctx_t ascon;
    size_t  n = ctx->prm->n;

    ascon_init(&ascon);
    ascon_absorb(&ascon, ctx->sk_prf, n);
    ascon_absorb(&ascon, opt_rand, n);
    ascon_absorb(&ascon, m, m_sz);

    ascon_squeeze(&ascon, h, n);
}

//  T_l(PK.seed, ADRS, M ) = ASCON-XOF128(PK.seed || ADRS || Ml, 8n)

static void ascon_t( slh_ctx_t *ctx, uint8_t *h,
                        const uint8_t *m, size_t m_sz)
{
    const uint32_t rblk = (320 - 2 * 128) / 32;    //  ASCON-XOF128 block size
    const uint32_t *m32 = (const uint32_t *) m;
    volatile uint32_t   *r32 = (volatile uint32_t *) ASCON_BASE_ADDR;
    size_t  i, j, n = ctx->prm->n;

    m_sz /= 4;

    for (i = 0; i < n / 4; i++) {
        r32[i] = *m32++;
    }
    m_sz -= i;
    r32[ASCON_CHNS]  =   0x80;               //  generate the padding only
    ASCON_WAIT

    i += 8 + n / 4;

    //  initial block (no need to xor)
    while (i < rblk && m_sz > 0) {
        r32[i++] = *m32++;
        m_sz--;
    }
    if (i >= rblk) {
        r32[ASCON_TRIG] = 0xF0;              //  absorb
        ASCON_WAIT
        i = 0;
    }

    //  full blocks
    while (m_sz > rblk) {
        for (j = 0; j < rblk; j++) {
            r32[j] ^= m32[j];
        }
        r32[ASCON_TRIG] = 0xF0;              //  absorb
        ASCON_WAIT
        m32 += rblk;
        m_sz -= rblk;
    }

    //  last part
    while (m_sz > 0) {
        r32[i++] ^= *m32++;
        if (i >= rblk) {
            r32[ASCON_TRIG] = 0xF0;          //  absorb
            ASCON_WAIT
            i = 0;
        }
        m_sz--;
    }
    r32[i] ^= 0x01;                         //  ascon256 padding
    r32[rblk - 1] ^= 1 << 31;
    r32[ASCON_TRIG] = 0xF0;                  //  squeeze
    ASCON_WAIT

    for (i = 0; i < n / 4; i++) {
        ((uint32_t *) h)[i] = r32[i];
    }
}

//  H(PK.seed, ADRS, M2 ) = ASCON-XOF128(PK.seed || ADRS || M2, 8n)

static void ascon_h_16( slh_ctx_t *ctx, uint8_t *h,
                            const uint8_t *m1, const uint8_t *m2)
{
    volatile uint32_t   *r32 = (volatile uint32_t *) ASCON_BASE_ADDR;

    block_copy_16(r32, m1);

    r32[ASCON_CHNS]  =   0x80;               //  generate the padding only
    ASCON_WAIT

    block_copy_16(&r32[16], m2);            //  after PK_seed, ADRS, and m1
    r32[20]         =   0x01;               //  ascon padding

    r32[ASCON_TRIG]  =   0xFO;               //  start it
    ASCON_WAIT

    block_copy_16(h, r32);
}

//  create a context

static void ascon_mk_ctx(slh_ctx_t *ctx,
                         const uint8_t *pk, const uint8_t *sk,
                         const slh_param_t *prm)
{
    size_t n = prm->n;

    ctx->prm = prm;     //  store fixed parameters
    if (sk != NULL) {
        memcpy( ctx->sk_seed,   sk,         n );
        memcpy( ctx->sk_prf,    sk + n,     n );
        memcpy( ctx->pk_seed,   sk + 2*n,   n );
        memcpy( ctx->pk_root,   sk + 3*n,   n );
    } else  if (pk != NULL) {
        memcpy( ctx->pk_seed,   pk,         n );
        memcpy( ctx->pk_root,   pk + n,     n );
    }

    volatile uint32_t   *r32 = (volatile uint32_t *) ASCON_BASE_ADDR;

    //  load keys in hardware
    r32[ASCON_SECN]  =   n;
    for (int j = 0; j < n/4; j++) {
        r32[ASCON_SEED + j] = ((uint32_t *) ctx->pk_seed)[j];
        r32[ASCON_SKSD + j] = ((uint32_t *) ctx->sk_seed)[j];
    }
    ctx->adrs = (volatile adrs_t *) &r32[ASCON_ADRS];
}

//  === Chaining function used in WOTS+
//  Algorithm 4: chain(X, i, s, PK.seed, ADRS)

static void ascon_chain_16( slh_ctx_t *ctx, uint8_t *tmp,
                            const uint8_t *x, uint32_t i, uint32_t s)
{
    volatile uint32_t   *r32 = (volatile uint32_t *) ASCON_BASE_ADDR;

    if (s == 0) {                           //  no-op
        block_copy_16(tmp, x);
        return;
    }
    block_copy_16(r32, x);
    ctx->adrs->u8[31] = i;                  //  set_hash_address(i)
    r32[ASCON_CHNS]  =   s;                  //  auto-chain ..
    ASCON_WAIT

    block_copy_16(tmp, r32);
}

//  Combination WOTS PRF + Chain

static void ascon_wots_chain_16( slh_ctx_t *ctx, uint8_t *tmp, uint32_t s)
{
    //  PRF secret key
    adrs_set_type(ctx, ADRS_WOTS_PRF);
    adrs_set_tree_index(ctx, 0);

    //  Unmasked PRF + Chain
    volatile uint32_t   *r32 = (volatile uint32_t *) ASCON_BASE_ADDR;
    r32[ASCON_CHNS]  =   0x40 + s;
    ASCON_WAIT
    block_copy_16(tmp, r32);
}

//  Combination FORS PRF + F (if s == 1)

static void ascon_fors_hash_16( slh_ctx_t *ctx, uint8_t *tmp, uint32_t s)
{
    adrs_set_type(ctx, ADRS_FORS_PRF);
    adrs_set_tree_height(ctx, 0);

    volatile uint32_t   *r32 = (volatile uint32_t *) ASCON_BASE_ADDR;

    //  Unmasked PRF + F
    r32[ASCON_CHNS]  =   0x40 + s;
    ASCON_WAIT
    block_copy_16(tmp, r32);
}

//  parameter sets

const slh_param_t slh_dsa_ascon_128s = {    .alg_id ="SLH-DSA-ascon-128s",
    .n= 16, .h= 63, .d= 7, .hp= 9, .a= 12, .k= 14, .lg_w= 4, .m= 30,
    .mk_ctx= ascon_mk_ctx, .chain= ascon_chain_16,
    .wots_chain= ascon_wots_chain_16, .fors_hash= ascon_fors_hash_16,
    .h_msg= ascon_h_msg, .prf= ascon_prf_16, .prf_msg= ascon_prf_msg,
    .h_f= ascon_f_16, .h_h= ascon_h_16, .h_t= ascon_t
};

const slh_param_t slh_dsa_ascon_128_24 = {    .alg_id ="SLH-DSA-ascon-128-24s",
    .n= 16, .h= 22, .d= 1, .hp= 22, .a= 24, .k= 6, .lg_w= 2, .m= 21,
    .mk_ctx= ascon_mk_ctx, .chain= ascon_chain_16,
    .wots_chain= ascon_wots_chain_16, .fors_hash= ascon_fors_hash_16,
    .h_msg= ascon_h_msg, .prf= ascon_prf_16, .prf_msg= ascon_prf_msg,
    .h_f= ascon_f_16, .h_h= ascon_h_16, .h_t= ascon_t
};

const slh_param_t slh_dsa_ascon_128f = {    .alg_id ="SLH-DSA-ascon-128f",
    .n= 16, .h= 66, .d= 22, .hp= 3, .a= 6, .k= 33, .lg_w= 4, .m= 34,
    .mk_ctx= ascon_mk_ctx, .chain= ascon_chain_16,
    .wots_chain= ascon_wots_chain_16, .fors_hash= ascon_fors_hash_16,
    .h_msg= ascon_h_msg, .prf= ascon_prf_16, .prf_msg= ascon_prf_msg,
    .h_f= ascon_f_16, .h_h= ascon_h_16, .h_t= ascon_t
};
//  SLOTH_ASCON
#endif
