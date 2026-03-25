#include "plat_local.h"
#ifndef SLOTH_ASCON

#include "slh_ctx.h"
#include "ascon_api.h"
#include "slh_adrs.h"
#include <stdio.h>
#include "log.h"

extern char buffer[512];
static void kat_hex(const char *label,
                    const uint8_t *x, size_t xlen)
{
  #ifdef DEBUG_LOG
    size_t i;
    neorv32_uart0_printf("%s = ", label);
    for (i = 0; i < xlen; i++) {
        neorv32_uart0_printf("%02X", x[i]);
    }
    neorv32_uart0_printf("\n"); 
  #endif /* ifdef DEBUG_LOG */

}

static void print_addr(slh_ctx_t *ctx){
  #ifdef DEBUG_LOG
  neorv32_uart0_printf("----------------------\n");
  neorv32_uart0_printf("ADDR:\n");
  neorv32_uart0_printf("----------------------\n");
  neorv32_uart0_printf("|Layer address: %d   \n",rev8_be32(ctx->adrs->u32[0]));
  neorv32_uart0_printf("|Tree address: %lu   \n",rev8_be64(*((uint64_t*)(ctx->adrs->u32 + 2))));
  neorv32_uart0_printf("|Type: %d   \n",rev8_be32(ctx->adrs->u32[4]));
  neorv32_uart0_printf("|Key pair address: %d   \n",rev8_be32(ctx->adrs->u32[5]));
  neorv32_uart0_printf("|Chain address: %d   \n",rev8_be32(ctx->adrs->u32[6]));
  neorv32_uart0_printf("|Hash address: %d   \n",rev8_be32(ctx->adrs->u32[7]));
  neorv32_uart0_printf("----------------------\n\n"); 
  #endif /* ifdef DEBUG_LOG */
}
//  === 10.1.   SLH-DSA Using ascon

//  Hmsg(R, PK.seed, PK.root, M) = ascon256(R || PK.seed || PK.root || M, 8m)

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

//  F(PK.seed, ADRS, M1 ) = ascon256(PK.seed || ADRS || M1, 8n)

static void ascon_f( slh_ctx_t *ctx,
                        uint8_t *h,
                        const uint8_t *m1)
{
    ascon_ctx_t ascon;
    size_t  n = ctx->prm->n;

    ascon_init(&ascon);
    ascon_absorb(&ascon, ctx->pk_seed, n);
    ascon_absorb(&ascon, (const uint8_t *) ctx->adrs->u8, 32);
    ascon_absorb(&ascon, m1, n);

    ascon_squeeze(&ascon, h, n);
}

//  PRF(PK.seed, SK.seed, ADRS) = ascon256(PK.seed || ADRS || SK.seed, 8n)

static void ascon_prf(slh_ctx_t *ctx, uint8_t *h)
{
    ascon_f(ctx, h, ctx->sk_seed);
}


//  PRFmsg (SK.prf, opt_rand, M) = ascon256(SK.prf || opt_rand || M, 8n)

static void ascon_prf_msg(  slh_ctx_t *ctx,
                                uint8_t *h, const uint8_t *opt_rand,
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

//  T_l(PK.seed, ADRS, M ) = ascon256(PK.seed || ADRS || Ml, 8n)

static void ascon_t( slh_ctx_t *ctx,
                        uint8_t *h, const uint8_t *m, size_t m_sz)
{
    ascon_ctx_t ascon;
    size_t  n = ctx->prm->n;

    ascon_init(&ascon);
    ascon_absorb(&ascon, ctx->pk_seed, n);
    ascon_absorb(&ascon, (const uint8_t *) ctx->adrs->u8, 32);
    ascon_absorb(&ascon, m, m_sz);

    ascon_squeeze(&ascon, h, n);
}


//  H(PK.seed, ADRS, M2 ) = ascon256(PK.seed || ADRS || M2, 8n)

static void ascon_h( slh_ctx_t *ctx,
                        uint8_t *h,
                        const uint8_t *m1, const uint8_t *m2)
{
    ascon_ctx_t ascon;
    size_t  n = ctx->prm->n;

    ascon_init(&ascon);
    ascon_absorb(&ascon, ctx->pk_seed, n);
    ascon_absorb(&ascon, (const uint8_t *) ctx->adrs->u8, 32);
    ascon_absorb(&ascon, m1, n);
    ascon_absorb(&ascon, m2, n);

    ascon_squeeze(&ascon, h, n);
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

    //  local ADRS buffer
    ctx->adrs = &ctx->t_adrs;
}

//  === Chaining function used in WOTS+
//  Algorithm 4: chain(X, i, s, PK.seed, ADRS)

//  chaining by processor (some optimizations)

static void ascon_chain( slh_ctx_t *ctx, uint8_t *tmp, const uint8_t *x,
                            uint32_t i, uint32_t s)
{
    uint32_t j;
    uint8_t as[64];
    size_t n = ctx->prm->n;
    ascon_ctx_t c;

    if (s == 0) {                           //  no-op
        memcpy(tmp, x, n);
        return;
    }
    //
    // uint32_t n8 = n / 8;                    //  number of words
    // uint32_t h = n8 + (32 / 8);             //  static part len
    uint32_t n8 = n;                    //  number of words
    uint32_t h = n8 + (32);             //  static part len
    memcpy(as + h, x, n);                   //  start node
    for (j = 0; j < s; j++) {
        if (j > 0) {
            memcpy(as + h, tmp, n);          //  chaining
        }
        memcpy(as, ctx->pk_seed, n);        //  PK.seed
        #ifdef DEBUG_LOG
        // FIPS_REF(6, 7, "Se incrementa el campo HASH_ADDRES de la estructura ADDR");
        // print_addr(ctx);
        #endif
        adrs_set_hash_address(ctx, i + j);  //  address
        memcpy(as + n8, (const uint8_t *) ctx->adrs->u8, 32);
        ascon_init(&c);
        ascon_absorb(&c,as,n + 32 + n);
        ascon_squeeze(&c, tmp, n);
        //  padding
        // ks[l] = 0x1F;                       //  ascon padding
        // for (k = l + 1; k < r - 1; k++) {
        //     ks[k] = 0;
        // }
        // ks[r - 1] = UINT64_C(1) << 63;      //  rate padding
        // for (k = r; k < 25; k++) {
        //     ks[k] = 0;
        // }
        //
        // keccak_f1600(ks);                   //  permutation
    }
    // uint32_t j, k;
    // uint64_t ks[25];
    // size_t n = ctx->prm->n;
    //
    // if (s == 0) {                           //  no-op
    //     memcpy(tmp, x, n);
    //     return;
    // }
    //
    // const uint32_t r = (1600-256*2)/64;     //  ascon256 rate
    // uint32_t n8 = n / 8;                    //  number of words
    // uint32_t h = n8 + (32 / 8);             //  static part len
    // uint32_t l = h + n8;                    //  input length
    //
    // memcpy(ks + h, x, n);                   //  start node
    // for (j = 0; j < s; j++) {
    //     if (j > 0) {
    //         memcpy(ks + h, ks, n);          //  chaining
    //     }
    //     memcpy(ks, ctx->pk_seed, n);        //  PK.seed
    //     #ifdef DEBUG_LOG
    //     FIPS_REF(6, 7, "Se incrementa el campo HASH_ADDRES de la estructura ADDR");
    //     print_addr(ctx);
    //     #endif
    //     adrs_set_hash_address(ctx, i + j);  //  address
    //     memcpy(ks + n8, (const uint8_t *) ctx->adrs->u8, 32);
    //
    //     //  padding
    //     ks[l] = 0x1F;                       //  ascon padding
    //     for (k = l + 1; k < r - 1; k++) {
    //         ks[k] = 0;
    //     }
    //     ks[r - 1] = UINT64_C(1) << 63;      //  rate padding
    //     for (k = r; k < 25; k++) {
    //         ks[k] = 0;
    //     }
    //
    //     keccak_f1600(ks);                   //  permutation
    // }
    // memcpy(tmp, ks, n);
}

//  Combination WOTS PRF + Chain

static void ascon_wots_chain( slh_ctx_t *ctx, uint8_t *tmp, uint32_t s)
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
    ascon_prf(ctx, tmp);
    //sneorv32_uart0_printf(buffer, "sk_%d", rev8_be32(ctx->adrs->u32[6]));
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
    ascon_chain( ctx, tmp, tmp, 0, s);
    //sneorv32_uart0_printf(buffer, "pk_%d", rev8_be32(ctx->adrs->u32[6]));
    kat_hex(buffer, tmp, ctx->prm->n);
}

//  Combination FORS PRF + F (if s == 1)

static void ascon_fors_hash( slh_ctx_t *ctx, uint8_t *tmp, uint32_t s)
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
    ascon_prf(ctx, tmp);

    //  hash it again
    if (s == 1) {
      #ifdef DEBUG_LOG
        FIPS_REF(19,12,"Se vuelve a establecer el campo TYPE de la estructura ADDR a FORS_TREE\n");
      #endif
        adrs_set_type(ctx, ADRS_FORS_TREE);
        //sneorv32_uart0_printf(buffer, "Se esta calculando el nodo F_%d = F(PK.SEED,ADRS,sk_k_%d)",adrs_get_tree_index(ctx) ,adrs_get_tree_index(ctx));
      #ifdef DEBUG_LOG
        FIPS_REF(15, 5, buffer);
      #endif
        ascon_f(ctx, tmp, tmp);
    }
}


const slh_param_t slh_dsa_ascon_128s = {    .alg_id ="SLH-DSA-ASCONXOF-128s",
    .n= 16, .h= 63, .d= 7, .hp= 9, .a= 12, .k= 14, .lg_w= 4, .m= 30,
    .mk_ctx= ascon_mk_ctx, .chain= ascon_chain,
    .wots_chain= ascon_wots_chain, .fors_hash= ascon_fors_hash,
    .h_msg= ascon_h_msg, .prf= ascon_prf, .prf_msg= ascon_prf_msg,
    .h_f= ascon_f, .h_h= ascon_h, .h_t= ascon_t
};

#endif
