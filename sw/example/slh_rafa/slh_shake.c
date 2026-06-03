//  slh_shake.c
//  Markku-Juhani O. Saarinen <mjos@iki.fi>.  See LICENSE.

//  === Portable C code: Functions for instantiation of SLH-DSA with SHAKE

#include "plat_local.h"
#ifndef SLOTH_KECCAK

#include "slh_ctx.h"
#include "sha3_api.h"
#include "slh_adrs.h"
#include <stdio.h>
#include "log.h"

char buffer[512] = {0};

static void kat_hex(const char *label,
                    const uint8_t *x, size_t xlen)
{
  #ifdef DEBUG_LOG
    size_t i;
    printf("%s = ", label);
    for (i = 0; i < xlen; i++) {
        printf("%02X", x[i]);
    }
    printf("\n"); 
  #endif /* ifdef DEBUG_LOG */

}

static void print_addr(slh_ctx_t *ctx){
  #ifdef DEBUG_LOG
  printf("----------------------\n");
  printf("ADDR:\n");
  printf("----------------------\n");
  printf("|Layer address: %d   \n",rev8_be32(ctx->adrs->u32[0]));
  printf("|Tree address: %lu   \n",rev8_be64(*((uint64_t*)(ctx->adrs->u32 + 2))));
  printf("|Type: %d   \n",rev8_be32(ctx->adrs->u32[4]));
  printf("|Key pair address: %d   \n",rev8_be32(ctx->adrs->u32[5]));
  printf("|Chain address: %d   \n",rev8_be32(ctx->adrs->u32[6]));
  printf("|Hash address: %d   \n",rev8_be32(ctx->adrs->u32[7]));
  printf("----------------------\n\n"); 
  #endif /* ifdef DEBUG_LOG */
}

//  === 10.1.   SLH-DSA Using SHAKE

//  Hmsg(R, PK.seed, PK.root, M) = SHAKE256(R || PK.seed || PK.root || M, 8m)

static void shake_h_msg( slh_ctx_t *ctx,
                            uint8_t *h,
                            const uint8_t *r,
                            const uint8_t *m, size_t m_sz)
{
    sha3_ctx_t sha3;
    size_t  n = ctx->prm->n;

    shake256_init(&sha3);
    shake_update(&sha3, r, n);
    shake_update(&sha3, ctx->pk_seed, n);
    shake_update(&sha3, ctx->pk_root, n);
    shake_update(&sha3, m, m_sz);

    shake_out(&sha3, h, ctx->prm->m);
}

//  F(PK.seed, ADRS, M1 ) = SHAKE256(PK.seed || ADRS || M1, 8n)

static void shake_f( slh_ctx_t *ctx,
                        uint8_t *h,
                        const uint8_t *m1)
{
    sha3_ctx_t sha3;
    size_t  n = ctx->prm->n;

    shake256_init(&sha3);
    shake_update(&sha3, ctx->pk_seed, n);
    shake_update(&sha3, (const uint8_t *) ctx->adrs->u8, 32);
    shake_update(&sha3, m1, n);

    shake_out(&sha3, h, n);
}

//  PRF(PK.seed, SK.seed, ADRS) = SHAKE256(PK.seed || ADRS || SK.seed, 8n)

static void shake_prf(slh_ctx_t *ctx, uint8_t *h)
{
    shake_f(ctx, h, ctx->sk_seed);
}


//  PRFmsg (SK.prf, opt_rand, M) = SHAKE256(SK.prf || opt_rand || M, 8n)

static void shake_prf_msg(  slh_ctx_t *ctx,
                                uint8_t *h, const uint8_t *opt_rand,
                                const uint8_t *m, size_t m_sz)
{
    sha3_ctx_t sha3;
    size_t  n = ctx->prm->n;

    shake256_init(&sha3);
    shake_update(&sha3, ctx->sk_prf, n);
    shake_update(&sha3, opt_rand, n);
    shake_update(&sha3, m, m_sz);

    shake_out(&sha3, h, n);
}

//  T_l(PK.seed, ADRS, M ) = SHAKE256(PK.seed || ADRS || Ml, 8n)

static void shake_t( slh_ctx_t *ctx,
                        uint8_t *h, const uint8_t *m, size_t m_sz)
{
    sha3_ctx_t sha3;
    size_t  n = ctx->prm->n;

    shake256_init(&sha3);
    shake_update(&sha3, ctx->pk_seed, n);
    shake_update(&sha3, (const uint8_t *) ctx->adrs->u8, 32);
    shake_update(&sha3, m, m_sz);

    shake_out(&sha3, h, n);
}


//  H(PK.seed, ADRS, M2 ) = SHAKE256(PK.seed || ADRS || M2, 8n)

static void shake_h( slh_ctx_t *ctx,
                        uint8_t *h,
                        const uint8_t *m1, const uint8_t *m2)
{
    sha3_ctx_t sha3;
    size_t  n = ctx->prm->n;

    shake256_init(&sha3);
    shake_update(&sha3, ctx->pk_seed, n);
    shake_update(&sha3, (const uint8_t *) ctx->adrs->u8, 32);
    shake_update(&sha3, m1, n);
    shake_update(&sha3, m2, n);

    shake_out(&sha3, h, n);
}

//  create a context

static void shake_mk_ctx(slh_ctx_t *ctx,
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

    //  local ADRS buffer
    ctx->adrs = &ctx->t_adrs;
}

//  === Chaining function used in WOTS+
//  Algorithm 4: chain(X, i, s, PK.seed, ADRS)

//  chaining by processor (some optimizations)

static void shake_chain( slh_ctx_t *ctx, uint8_t *tmp, const uint8_t *x,
                            uint32_t i, uint32_t s)
{
    uint32_t j, k;
    uint64_t ks[25];
    size_t n = ctx->prm->n;

    if (s == 0) {                           //  no-op
        memcpy(tmp, x, n);
        return;
    }

    const uint32_t r = (1600-256*2)/64;     //  SHAKE256 rate
    uint32_t n8 = n / 8;                    //  number of words
    uint32_t h = n8 + (32 / 8);             //  static part len
    uint32_t l = h + n8;                    //  input length

    memcpy(ks + h, x, n);                   //  start node
    for (j = 0; j < s; j++) {
        if (j > 0) {
            memcpy(ks + h, ks, n);          //  chaining
        }
        memcpy(ks, ctx->pk_seed, n);        //  PK.seed
        #ifdef DEBUG_LOG
        FIPS_REF(6, 7, "Se incrementa el campo HASH_ADDRES de la estructura ADDR");
        print_addr(ctx);
        #endif
        adrs_set_hash_address(ctx, i + j);  //  address
        memcpy(ks + n8, (const uint8_t *) ctx->adrs->u8, 32);

        //  padding
        ks[l] = 0x1F;                       //  shake padding
        for (k = l + 1; k < r - 1; k++) {
            ks[k] = 0;
        }
        ks[r - 1] = UINT64_C(1) << 63;      //  rate padding
        for (k = r; k < 25; k++) {
            ks[k] = 0;
        }

        keccak_f1600(ks);                   //  permutation
    }
    memcpy(tmp, ks, n);
}

//  Combination WOTS PRF + Chain

static void shake_wots_chain( slh_ctx_t *ctx, uint8_t *tmp, uint32_t s)
{
    //  PRF secret key
    #ifdef DEBUG_LOG
    FIPS_REF(6, 2, "Se establece el campo TYPE de ADDRS a WOTS_PRF.");
    #endif
    adrs_set_type(ctx, ADRS_WOTS_PRF);
    #ifdef DEBUG_LOG
    FIPS_REF(6, 2, "Se establece el campo HASH_ADDRES a 0 (Esto seria el clear de la funcion setTypeAndClear de la especificacion)");
    #endif
    adrs_set_tree_index(ctx, 0);
    print_addr(ctx);
    #ifdef DEBUG_LOG
    FIPS_REF(6, 6, "Se calcula sk_i = PRF(...)");
    #endif
    shake_prf(ctx, tmp);
    //sprintf(buffer, "sk_%d", rev8_be32(ctx->adrs->u32[6]));
    kat_hex(buffer, tmp, ctx->prm->n);

    //  chain
    #ifdef DEBUG_LOG
    FIPS_REF(9, 2, "Se establece el campo TYPE de ADDR a WOTS_HASH (En el codigo es diferente a la especificacion)");
    #endif
    adrs_set_type(ctx, ADRS_WOTS_HASH);
    print_addr(ctx);
    #ifdef DEBUG_LOG
    FIPS_REF(6, 8, "Se calcula pk_i = chain(...,sk_i)");
    #endif
    shake_chain( ctx, tmp, tmp, 0, s);
    //sprintf(buffer, "pk_%d", rev8_be32(ctx->adrs->u32[6]));
    kat_hex(buffer, tmp, ctx->prm->n);
}

//  Combination FORS PRF + F (if s == 1)

static void shake_fors_hash( slh_ctx_t *ctx, uint8_t *tmp, uint32_t s)
{
    //  PRF secret key
    #ifdef DEBUG_LOG
    FIPS_REF(14,2,"Se establece el campo type de la estructura ADDR a FORS_PRF\n");
    #endif
    adrs_set_type(ctx, ADRS_FORS_PRF);
    adrs_set_tree_height(ctx, 0);
    #ifdef DEBUG_LOG
    FIPS_REF(14,5,"Se calcula el valor de sk_i_m_i\n");
    #endif
    shake_prf(ctx, tmp);

    //  hash it again
    if (s == 1) {
      #ifdef DEBUG_LOG
        FIPS_REF(19,12,"Se vuelve a establecer el campo TYPE de la estructura ADDR a FORS_TREE\n");
      #endif
        adrs_set_type(ctx, ADRS_FORS_TREE);
        //sprintf(buffer, "Se esta calculando el nodo F_%d = F(PK.SEED,ADRS,sk_k_%d)",adrs_get_tree_index(ctx) ,adrs_get_tree_index(ctx));
      #ifdef DEBUG_LOG
        FIPS_REF(15, 5, buffer);
      #endif
        shake_f(ctx, tmp, tmp);
    }
}

//  parameter sets

const slh_param_t slh_dsa_shake_128s = {    .alg_id ="SLH-DSA-SHAKE-128s",
    .n= 16, .h= 63, .d= 7, .hp= 9, .a= 12, .k= 14, .lg_w= 4, .m= 30,
    .mk_ctx= shake_mk_ctx, .chain= shake_chain,
    .wots_chain= shake_wots_chain, .fors_hash= shake_fors_hash,
    .h_msg= shake_h_msg, .prf= shake_prf, .prf_msg= shake_prf_msg,
    .h_f= shake_f, .h_h= shake_h, .h_t= shake_t
};

const slh_param_t slh_dsa_shake_128f = {    .alg_id ="SLH-DSA-SHAKE-128f",
    .n= 16, .h= 66, .d= 22, .hp= 3, .a= 6, .k= 33, .lg_w= 4, .m= 34,
    .mk_ctx= shake_mk_ctx, .chain= shake_chain,
    .wots_chain= shake_wots_chain, .fors_hash= shake_fors_hash,
    .h_msg= shake_h_msg, .prf= shake_prf, .prf_msg= shake_prf_msg,
    .h_f= shake_f, .h_h= shake_h, .h_t= shake_t
};

const slh_param_t slh_dsa_shake_192s = {    .alg_id ="SLH-DSA-SHAKE-192s",
    .n= 24, .h= 63, .d= 7, .hp= 9, .a= 14, .k= 17, .lg_w= 4, .m= 39,
    .mk_ctx= shake_mk_ctx, .chain= shake_chain,
    .wots_chain= shake_wots_chain, .fors_hash= shake_fors_hash,
    .h_msg= shake_h_msg, .prf= shake_prf, .prf_msg= shake_prf_msg,
    .h_f= shake_f, .h_h= shake_h, .h_t= shake_t
};

const slh_param_t slh_dsa_shake_192f = {    .alg_id ="SLH-DSA-SHAKE-192f",
    .n= 24, .h= 66, .d= 22, .hp= 3, .a= 8, .k= 33, .lg_w= 4, .m= 42,
    .mk_ctx= shake_mk_ctx, .chain= shake_chain,
    .wots_chain= shake_wots_chain, .fors_hash= shake_fors_hash,
    .h_msg= shake_h_msg, .prf= shake_prf, .prf_msg= shake_prf_msg,
    .h_f= shake_f, .h_h= shake_h, .h_t= shake_t
};

const slh_param_t slh_dsa_shake_256s = {    .alg_id ="SLH-DSA-SHAKE-256s",
    .n= 32, .h= 64, .d= 8, .hp= 8, .a= 14, .k= 22, .lg_w= 4, .m= 47,
    .mk_ctx= shake_mk_ctx, .chain= shake_chain,
    .wots_chain= shake_wots_chain, .fors_hash= shake_fors_hash,
    .h_msg= shake_h_msg, .prf= shake_prf, .prf_msg= shake_prf_msg,
    .h_f= shake_f, .h_h= shake_h, .h_t= shake_t
};

const slh_param_t slh_dsa_shake_256f = {    .alg_id ="SLH-DSA-SHAKE-256f",
    .n= 32, .h= 68, .d= 17, .hp= 4, .a= 9, .k= 35, .lg_w= 4, .m= 49,
    .mk_ctx= shake_mk_ctx, .chain= shake_chain,
    .wots_chain= shake_wots_chain, .fors_hash= shake_fors_hash,
    .h_msg= shake_h_msg, .prf= shake_prf, .prf_msg= shake_prf_msg,
    .h_f= shake_f, .h_h= shake_h, .h_t= shake_t
};

//  no SLOTH_KECCAK
#endif
