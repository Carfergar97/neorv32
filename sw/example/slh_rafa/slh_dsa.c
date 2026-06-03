//  slh_dsa.c
//  Markku-Juhani O. Saarinen <mjos@iki.fi>.  See LICENSE.

//  === FIPS 205 (ipd) Stateless Hash-Based Digital Signature Standard

#include "slh_dsa.h"
#include "plat_local.h"
#include "slh_ctx.h"
#include "slh_adrs.h"
#include "slh_param.h"
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include "log.h"
#include <neorv32.h>

extern char buffer[512]; // Buffer used to print debug information 

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
    #endif
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
  #endif

}
//  === Internal

//  helper functions to compute "len = len1 + len2"

static inline uint32_t get_len1(const slh_param_t *prm)
{
    return ((8 * prm->n + prm->lg_w - 1) / prm->lg_w);
}

static inline uint32_t get_len2(const slh_param_t *prm)
{
#ifdef NDEBUG
    (void) prm;
#endif
    //  Appedix B:
    //  "When lg_w = 4 and 9 <= n <= 136, the value of len2 will be 3."
    assert(prm->lg_w == 4 && prm->n >= 9 && prm->n <= 136);
    return 3;
}
static inline uint32_t get_len(const slh_param_t *prm)
{
    return  get_len1(prm) + get_len2(prm);
}

//  Return signature size in bytes for parameter set *prm.
size_t slh_sig_sz(const slh_param_t *prm)
{
    return  (1 + prm->k*(1 + prm->a) + prm->h + prm->d * get_len(prm)) * prm->n;
}

//  === Compute the base 2**b representation of X.
//  Algorithm 3: base_2b(X, b, out_len)

static inline size_t base_2b(   uint32_t *v, const uint8_t *x,
                                uint32_t b, size_t v_len)
{
    size_t i, j;
    uint32_t l, t, m;

    j = 0;
    l = 0;
    t = 0;
    m = (1 << b) - 1;
    for (i = 0; i < v_len; i++) {
        while (l < b) {
            t = (t << 8) + x[j++];
            l += 8;
        }
        l -= b;
        v[i] = (t >> l) & m;
    }
    return j;
}

//  little bit faster version for b = 4

static inline size_t base_16(   uint32_t *v, const uint8_t *x, int v_len)
{
    int i, j, l, t;

    j = 0;
    for (i = 0; i < v_len - 2; i += 2) {
        t = x[j++];
        v[i]     = t >> 4;
        v[i + 1] = t & 0xF;
    }

    l = 0;
    t = 0;
    for (; i < v_len; i++) {
        while (l < 4) {
            t = (t << 8) + x[j++];
            l += 8;
        }
        l -= 4;
        v[i] = (t >> l) & 0xF;
    }
    return j;
}

//  === Chaining function used in WOTS+
//  Algorithm 4: chain(X, i, s, PK.seed, ADRS)
//  (see prm->chain)

//  === Generate a WOTS+ public key.
//  Algorithm 5: wots_PKgen(SK.seed, PK.seed, ADRS)
//  (see xmms_node)

//  === Generate a WOTS+ signature on an n-byte message.
//  Algorithm 6: wots_sign(M, SK.seed, PK.seed, ADRS)

//  (wots_csum is a shared helper function for algorithms 6 and 7)
static void wots_csum(uint32_t *vm, const uint8_t *m, const slh_param_t *prm)
{
    uint32_t csum, i, t;
    uint32_t len1, len2;
    uint8_t buf[4];

    len1 = get_len1(prm);
    len2 = get_len2(prm);

    //base_2b(vm, m, prm->lg_w, len1);
    base_16(vm, m, len1);

    csum = 0;
    t = (1 << prm->lg_w) - 1;
    for (i = 0; i < len1; i++) {
        csum += t - vm[i];
    }
    csum <<= (8 - ((len2 * prm->lg_w) & 7)) & 7;

    t = (len2 * prm->lg_w + 7) / 8;
    memset(buf, 0, sizeof(buf));
    slh_tobyte(buf, csum, t);

    //base_2b(&vm[len1], buf, prm->lg_w, len2);
    base_16(&vm[len1], buf, len2);
}

static size_t wots_sign(slh_ctx_t *ctx, uint8_t *sig, const uint8_t *m)
{
    const slh_param_t *prm = ctx->prm;
    uint32_t i, len;
    uint32_t vm[SLH_MAX_LEN];
    size_t n = prm->n;

    len = get_len(prm);
    wots_csum(vm, m, prm);

    for (i = 0; i < len; i++) {
        adrs_set_chain_address(ctx, i);
        prm->wots_chain(ctx, sig, vm[i]);
        sig += n;
    }
    return n * len;
}

//  === Compute a WOTS+ public key from a message and its signature.
//  Algorithm 7: wots_PKFromSig(sig, M, PK.seed, ADRS)

static void wots_pk_from_sig(   slh_ctx_t *ctx, uint8_t *pk,
                                const uint8_t *sig,
                                const uint8_t *m)
{
    const slh_param_t *prm = ctx->prm;
    uint32_t i, t, len;
    static uint32_t vm[SLH_MAX_LEN];
    static uint8_t tmp[SLH_MAX_LEN * SLH_MAX_N];
    size_t n = prm->n;
    size_t tmp_sz;

    wots_csum(vm, m, prm);

    len = get_len(prm);
    t = 15; // (1 << prm->lg_w) - 1;
    tmp_sz = 0;
    for (i = 0; i < len; i++) {
        adrs_set_chain_address(ctx, i);
        prm->chain( ctx, tmp + tmp_sz, sig + tmp_sz, vm[i], t - vm[i]);
        tmp_sz += n;
    }

    adrs_set_type_and_clear_not_kp(ctx, ADRS_WOTS_PK);
    prm->h_t(ctx, pk, tmp, tmp_sz);
}

//  === Compute the root of a Merkle subtree of WOTS+ public keys.
//  Algorithm 8: xmss_node(SK.seed, i, z, PK.seed, ADRS)

static void xmss_node(  slh_ctx_t *ctx, uint8_t *node,
                        uint32_t i, uint32_t z, uint32_t flag)
{
    const slh_param_t *prm = ctx->prm;
    uint32_t j, k;
    int p;
    static uint8_t *h0, h[SLH_MAX_HP][SLH_MAX_N];//modificado para almacenar los nodos de cada nivel del arbol, se ha hecho static para no saturar la pila con un array tan grande
    static uint8_t tmp[SLH_MAX_LEN * SLH_MAX_N];
    uint8_t *sk;
    size_t n = prm->n;
    size_t len = get_len(prm);

    p = -1;
    i <<= z;
    if (!flag) {
      #ifdef DEBUG_LOG
      LOG("Se comienza a calcular las claves publicas (WOTS) de las hojas del arbol xmss en la capa %d", prm->d - 1);
      #endif
    }
    for (j = 0; j < (1u << z); j++) {
        if (!flag) {
          #ifdef DEBUG_LOG
          LOG("Se esta calculando la clave publica WOTS de la hoja %d", j);
          #endif
        }
        adrs_set_key_pair_address(ctx, i);
        #ifdef DEBUG_LOG
        FIPS_REF(9, 3, "Se establece el campo Key Pair Address de la estructura ADDR.");
        #endif
        //print_addr(ctx);
        //  === Generate a WOTS+ public key.
        //  Algorithm 5: wots_PKgen(SK.seed, PK.seed, ADRS)
        sk  = tmp;
        #ifdef DEBUG_LOG
        FIPS_REF(6, 4, "");
        #endif
        for (k = 0; k < len; k++) {
            #ifdef DEBUG_LOG
            FIPS_REF(6, 5, "Se establece el campo Chain Address de la estructura ADDR.");
            #endif
            adrs_set_chain_address(ctx, k);
            if (!flag) {
                #ifdef DEBUG_LOG
                  LOG("Se va a generar el par sk_%d-pk_%d (WOTS)", k, k);
                #endif
            }
            print_addr(ctx);
            #ifdef DEBUG_LOG
            FIPS_REF(6, 8, "Se procede a calcular sk_i= PRF(...) y pk_I = chain(...,sk_i)");
            #endif
            prm->wots_chain(ctx, sk, 15);   //  w-1 =  (1 << prm->lg_w) - 1;
            sk += n;
        }
        
        #ifdef DEBUG_LOG
        FIPS_REF(6, 11, "Se establece el campo TYPE de ADDR a WOTS_PRF");
        #endif
        adrs_set_type_and_clear_not_kp(ctx, ADRS_WOTS_PK);
        //print_addr(ctx);
        h0 = p >= 0 ? h[p] : node;
        p++;
        #ifdef DEBUG_LOG
        FIPS_REF(6, 13, "Se calcula la comprension de las claves publicas usando Tlen");
        #endif
        #ifdef DEBUG_LOG
        LOG("Se calcula PK_%d = Tlen(pk_0||...||pk_{len-1})",j);
        #endif
        prm->h_t(ctx, h0, tmp, len * n);
        if (!flag) {
            //sprintf(buffer, "PK_%d", j); 
            //kat_hex(buffer, h0, prm->n);
        }

        //  this xmss_node() implementation is non-recursive
        for (k = 0; (j >> k) & 1; k++) {
            #ifdef DEBUG_LOG
            FIPS_REF(9, 8, "Se establece el campo TYPE de ADDR a TREE");
            #endif
            adrs_set_type_and_clear(ctx, ADRS_TREE);
            #ifdef DEBUG_LOG
            FIPS_REF(9, 9, "Se actualiza el campo TREE_HEIGHT de ADDR");
            #endif
            adrs_set_tree_height(ctx, k + 1);
            #ifdef DEBUG_LOG
            FIPS_REF(9, 10, "Se actualiza el campo TREE_HEIGHT de ADDR");
            #endif
            adrs_set_tree_index(ctx, i >> (k + 1));
            print_addr(ctx);
            #ifdef DEBUG_LOG
            LOG("Se esta calculando H_%d%d\n", rev8_be32(ctx->adrs->u32[6]), adrs_get_tree_index(ctx));
            #endif
            p--;
            h0 = p >= 1 ? h[p - 1] : node;
            prm->h_h(ctx, h0, h0, h[p]);
            //sprintf(buffer, "H_%d%d", rev8_be32(ctx->adrs->u32[6]), adrs_get_tree_index(ctx));
            //kat_hex(buffer, h0, ctx->prm->n);
        }
        i++;        //  advance index
    }
}

//  === Generate an XMSS signature.
//  Algorithm 9: xmss_sign(M, SK.seed, idx, PK.seed, ADRS)

static size_t xmss_sign(slh_ctx_t *ctx, uint8_t *sx, const uint8_t *m,
                        uint32_t idx)
{

    const slh_param_t *prm = ctx->prm;
    uint32_t j, k;
    uint8_t *auth;
    size_t sx_sz = 0;
    size_t n = prm->n;

    sx_sz = get_len(prm) * n;
    auth = sx + sx_sz;
    //sprintf(buffer,"Se procede a determinar el camino de autenticacion para la hoja %d\n", idx);
    FIPS_REF(10, 1, buffer);
    for (j = 0; j < prm->hp; j++) {
        k = (idx >> j) ^ 1;
        //sprintf(buffer,"Se va a proceder a calcular el nodo %d del nivel %d del arbol %lu XMSS en el nivel %d del hiperarbol.\n",k, j, rev8_be64(*((uint64_t *)(ctx->adrs->u32 + 2))), rev8_be32(ctx->adrs->u32[0]));
        FIPS_REF(10, 3, buffer);
        xmss_node(ctx, auth, k, j, 1);
        //sprintf(buffer, "El nodo n_%d_%d es ", j, k);
        kat_hex(buffer, auth, prm->n);
        auth += n;
    }
    sx_sz += prm->hp * n;

    adrs_set_type_and_clear_not_kp(ctx, ADRS_WOTS_HASH);
    adrs_set_key_pair_address(ctx, idx);
    //sprintf(buffer,"Se procede a calcular la firma WOTS usando la hoja %d del arbol %d del nivel %d del hiperarbol", idx, adrs_get_tree_index(ctx), rev8_be32(ctx->adrs->u32[0]));
    FIPS_REF(10, 7, buffer);
    wots_sign(ctx, sx, m);
    //sprintf(buffer, "La firma WOTS usando la hoja %d del arbol %d del nivel %d del hiperarbol es", idx, adrs_get_tree_index(ctx), rev8_be32(ctx->adrs->u32[0]));
    kat_hex(buffer, sx, get_len(prm) * n);

    return sx_sz;
}

//  === Compute an XMSS public key from an XMSS signature.
//  Algorithm 10: xmss_PKFromSig(idx, SIGXMSS, M, PK.seed, ADRS)

static void xmss_pk_from_sig(   slh_ctx_t *ctx, uint8_t *root, uint32_t idx,
                                const uint8_t *sig, const uint8_t *m)
{

    const slh_param_t *prm = ctx->prm;
    uint32_t k;
    const uint8_t *auth;
    size_t n = prm->n;

    FIPS_REF(11,1,"Se establece el campo TYPE de la estructura ADDR a WOTS_HASH ya que se va a calcular la clave publica WOTS a partir de la firma WOTS.");
    adrs_set_type_and_clear_not_kp(ctx, ADRS_WOTS_HASH);
    FIPS_REF(11, 2, "Se establece el campo KEY_PAIR_ADDRESS de la estructura ADDR para calcular la clave publica del esquema WOTS correspondiente.");
    adrs_set_key_pair_address(ctx, idx);
    //sprintf(buffer,"Se va a proceder a calcular la clave publica PK_%d del esquema WOTS empleado en la capa 0 del arbol XMSS", idx);
    FIPS_REF(11, 5, buffer); 
    wots_pk_from_sig(ctx, root, sig, m);
    //sprintf(buffer, "La clave publica WOTS PK_%d=Tlen[pk_0,...,pl_len-1]", idx);
    kat_hex(buffer, root, prm->n);
    FIPS_REF(11, 6, "Se establece el campo TYPE de la estructura ADDR ya que se va a resolver el arbol para obtener la raiz del mismo.");
    adrs_set_type_and_clear(ctx, ADRS_TREE);

    auth = sig + (get_len(prm) * n);
    FIPS_REF(11, 8, "Se va a usar un bucle for para obtener la raiz del arbol a partir de la clave publica WOTS y el camino de autenticacion de la firma XMSS");
    for (k = 0; k < prm->hp; k++) {
        FIPS_REF(11,9,"Se establece el campo TREE_HEIGHT de la estructura ADDR.");
        adrs_set_tree_height(ctx, k + 1);
        FIPS_REF(11, 11, "Se establece el campo TREE_INDEX de la estructura ADDR");
        adrs_set_tree_index(ctx, idx >> (k + 1));
        
        if (((idx >> k) & 1) == 0) {
            //sprintf(buffer,"Se va a calcular el nodo n_%d_%d=H(PK.SEED,ADRS, n_%d_%d||n_%d_%d)",  k+1, idx>>(k+1),k,idx>>k,k,(idx>>k)+1);
            FIPS_REF(11, 12, buffer);
            prm->h_h(ctx, root, root, auth);
            
        } else {
            //sprintf(buffer,"Se va a calcular el nodo n_%d_%d=H(PK.SEED,ADRS, n_%d_%d||n_%d_%d)",  k+1, idx>>(k+1),k,(idx>>k)-1,k,(idx>>k));
            FIPS_REF(11, 15, buffer);
            prm->h_h(ctx, root, auth, root);
        }
        //sprintf(buffer,"n_%d_%d",k+1,idx>>k);
        kat_hex(buffer, root, prm->n);
        auth += n;
    }
    //sprintf(buffer, "La clave publica del arbol %lu del nivel %d es ", rev8_be64(*((uint64_t *)(ctx->adrs->u32 + 2))), rev8_be32(ctx->adrs->u32[0]));
    kat_hex(buffer, root, prm->n);

}


//  === Generate a hypertree signature.
//  Algorithm 11: ht_sign(M, SK.seed, PK.seed, idx_tree, idx_leaf )

static size_t ht_sign(  slh_ctx_t *ctx, uint8_t *sh, uint8_t *m,
                        uint64_t i_tree, uint32_t i_leaf)
{

    const slh_param_t *prm = ctx->prm;
    uint32_t j;
    size_t sx_sz;

    //FIPS_REF(12, 2, "Se establece el campo TREE_ADDRESS de la estructura ADDR con la dirección del arbol que contiene la hoja con la que se firmara la clave publica FORS.");
    adrs_zero(ctx);
    adrs_set_tree_address(ctx, i_tree);
    //sprintf(buffer,"Se firma la clave publica FORS con la hoja %d del arbol %lu del nivel 0 del hiperarbol",i_leaf, i_tree);
    //FIPS_REF(12, 3, buffer);
    sx_sz = xmss_sign(ctx, sh, m, i_leaf);
    //kat_hex("La firma de la clave publica FORS", sh, (get_len(prm)+ prm->hp)*prm->n); 
    //FIPS_REF(12, 6, "Se comienza el a realizar la firma de las raices de los arboles XMSS con el siguiente arbol del hiperarbol");
    for (j = 1; j < prm->d; j++) {
        //sprintf(buffer,"Se obtiene la clave publica del arbol XMSS(tree_index = %lu) del nivel %d a partir de la firma generada\n", i_tree, j-1);    
        //FIPS_REF(12, 14, buffer);
        xmss_pk_from_sig(ctx, m, i_leaf, sh, m);
        neorv32_gpio_pin_set(3,1);
        neorv32_gpio_pin_set(4,0);
        sh += sx_sz;
        //sprintf(buffer,"Se calcula el indice de la hoja con la que se va a firmar la clave publica del arbol %lu del nivel %d\n", i_tree, j-1);
        //FIPS_REF(12, 7, buffer);
        i_leaf = i_tree & ((1 << prm->hp) - 1);
        //sprintf(buffer,"Se calculan el indice del arbol con la que se va a firmar la clave publica del arbol %lu del nivel %d\n", i_tree, j-1);
        //FIPS_REF(12, 8, buffer);
        i_tree >>= prm->hp;
        //LOG("La clave publica del nivel %d se firmara con la hoja %d del arbol %lu\n", j-1, i_leaf, i_tree);
        //FIPS_REF(12, 9, "Se establece el campo LAYER_ADDR de la estructura ADDR");
        adrs_set_layer_address(ctx, j);
        neorv32_gpio_pin_toggle(3);
        neorv32_gpio_pin_toggle(4);
        //FIPS_REF(12, 10, "Se establece el campo TREE_ADDR de la estructura ADDR");
        adrs_set_tree_address(ctx, i_tree);
        neorv32_gpio_pin_toggle(3);
        neorv32_gpio_pin_toggle(4);
        //sprintf(buffer, "Se firma la clave publica del nivel %d se firmara con la hoja %d del nivel %d", j-1,i_leaf,j);
        //FIPS_REF(12, 11, buffer);
        xmss_sign( ctx, sh, m, i_leaf);
        neorv32_gpio_pin_toggle(3);
        neorv32_gpio_pin_toggle(4);
        neorv32_gpio_pin_toggle(2);
        //sprintf(buffer, "La firma de la clave publica del arbol XMSS del nivel %d, con la hoja %d del arbol %lu del nivel %d, es",j-1, i_leaf, i_tree,j );
        //kat_hex(buffer, sh, (get_len(prm)+ prm->hp)*prm->n);
    }
    neorv32_gpio_pin_set(6,1);
    return sx_sz * prm->d;
}


//  === Verify a hypertree signature.
//  Algorithm 12: ht_verify(M, SIG_HT, PK.seed, idx_tree, idx_leaf, PK.root)

static bool ht_verify(  slh_ctx_t *ctx, const uint8_t *m,
                        const uint8_t *sig_ht,
                        uint64_t i_tree, uint32_t i_leaf)
{
    const slh_param_t *prm = ctx->prm;
    uint32_t i, j;
    uint8_t node[SLH_MAX_N];
    size_t st_sz;

    adrs_zero(ctx);
    adrs_set_tree_address(ctx, i_tree);

    xmss_pk_from_sig(ctx, node, i_leaf, sig_ht, m);

    st_sz = (prm->hp + get_len(prm)) * prm->n;
    for (j = 1; j < prm->d; j++) {
        i_leaf = i_tree & ((1 << prm->hp) - 1);
        i_tree >>= prm->hp;
        adrs_set_layer_address(ctx, j);
        adrs_set_tree_address(ctx, i_tree);
        sig_ht += st_sz;
        xmss_pk_from_sig(ctx, node, i_leaf, sig_ht, node);
    }
    FIPS_REF(13, 13, "Se compara el nodo PK.ROOT calculado a partir de la firma con el valor PK.ROOT\n");
    kat_hex("node", node, prm->n);
    kat_hex("PK.ROOT",ctx->pk_root,prm->n);
    uint8_t t;
    t = 0;
    for (i = 0; i < prm->n; i++) {
        //sprintf(buffer, "node[%d]", i);
        kat_hex(buffer,node+i,1);
        //sprintf(buffer, "PK.ROOT[%d]", i);
        kat_hex(buffer,(ctx->pk_root)+i,1);
        t |= node[i] ^ ctx->pk_root[i];
    }
    return t == 0;
}

//  === Generate a FORS private-key value.
//  Algorithm 13: fors_SKgen(SK.seed, PK.seed, ADRS, idx)

//  ( see prm->fors_hash() )

//  === Compute the root of a Merkle subtree of FORS public values.
//  Algorithm 14: fors_node(SK.seed, i, z, PK.seed, ADRS)

static void fors_node(  slh_ctx_t *ctx, uint8_t *node,
                        uint32_t i, uint32_t z)
{
    const slh_param_t *prm = ctx->prm;
    uint8_t h[SLH_MAX_A][SLH_MAX_N], *h0;
    uint32_t j, k;
    int p;

    p = -1;
    i <<= z;
    for (j = 0; j < (1u << z); j++) {
        neorv32_gpio_pin_toggle(0);

        //  fors_SKgen() + hash
        //FIPS_REF(15, 4, "Se establece el campo TREE_INDEX de la estructura ADDR.");
        adrs_set_tree_index(ctx, i);
        LOG("El indice del nodo, en el nivel 0, del camino de autenticacion calculado actualmente es TREE_INDEX=%d", adrs_get_tree_index(ctx));
        h0 = p >= 0 ? h[p] : node;
        p++;
        prm->fors_hash(ctx, h0, 1);

        //  this fors_node() implementation is non-recursive
        for (k = 0; (j >> k) & 1; k++) {
            //FIPS_REF(15, 9, "Se establece el campo TREE_HEIGHT de la estructura ADDR");
            adrs_set_tree_height(ctx, k + 1);
            //FIPS_REF(15, 10, "Se establece el campo TREE_INDEX de la estructura ADDR");
            adrs_set_tree_index(ctx, i >> (k + 1));
            //LOG("El indice del nodo, del nivel %d, del camino de autenticacion calculado actualmente es %d\n", rev8_be32(ctx->adrs->u32[6]),adrs_get_tree_index(ctx));
            p--;
            h0 = p > 0 ? h[p - 1] : node;
            //sprintf(buffer, "Se esta calculando el nodo H_%d(nivel%d) = H(PK.SEED,ADRS,H_%d(nivel %d)||H_%d(nivel %d))", adrs_get_tree_index(ctx), k+1, adrs_get_tree_index(ctx)*2,k, adrs_get_tree_index(ctx)*2 + 1,k);
            //FIPS_REF(15, 11, buffer);
            prm->h_h(ctx, h0, h0, h[p]);
        }
        i++;        //  advance index
    }
}


//  === Generate a FORS signature.
//  Algorithm 15: fors_sign(md, SK.seed, PK.seed, ADRS)

static size_t fors_sign(slh_ctx_t *ctx, uint8_t *sf, const uint8_t *md)
{
    const slh_param_t *prm = ctx->prm;
    uint32_t i, j, s;
    uint32_t vi[SLH_MAX_K];
    size_t  n = prm->n;

    assert(SLH_MAX_K >= prm->k);
    FIPS_REF(16, 2, "Se calculan los k indices de 12 (a) bits que forman md = [m_0,...,m_k-1].");
    base_2b(vi, md, prm->a, prm->k);
    FIPS_REF(16, 3, "Se van a calcular las k componentes de la firma FORS.");
    LOG("Sig_FORS = [(sk_0_m_0,AUTH(0)),...,sk_k-1_m_k-1,AUTH(k-1)]");
    for (i = 0; i < prm->k; i++) {
        LOG("Se comienza a calcular el componente Sig_FORS(%d)=sk_%d_%d,AUTH(%d)",i,i,vi[i],i);
        //  fors_SKgen()
        FIPS_REF(14, 4, "Se establece el campo TREE_INDEX de la estructura ADDR con la direccion de la hoja con la que se realizara la firma FORS.");
        adrs_set_tree_index(ctx, (i << prm->a) + vi[i]);
        LOG("El nodo al que apunta m_%d es: %d\n", i, adrs_get_tree_index(ctx));
        prm->fors_hash(ctx, sf, 0);
        //sprintf(buffer, "sk_%d", adrs_get_tree_index(ctx));
        kat_hex(buffer, sf, prm->n);
        sf += n;
        //sprintf(buffer, "Se va a proceder a calcular el camino de autenticacion AUTH(%d) para la clave privada FORS sk_%d_%d", i, i, vi[i]);
        FIPS_REF(16,5,buffer);
        for (j = 0; j < prm->a; j++) {
            LOG("Se esta calculando el nodo H_%d(Este indice hace referencia al nodo dentro del arbol k. No se corresponde con TREE_INDEX) del camnio de autenticacion del arbol %d en el nivel %d", vi[i]>>j ^ 1, i, j);
            FIPS_REF(16, 6, "Se determina el indice del siguiente nodo a calcular en el camino de autenticacion.");
            s = (vi[i] >> j) ^ 1;
            FIPS_REF(16, 7, "Se procede a calcular el siguiente nodo del camino de autenticacion.");
            fors_node(  ctx, sf, (i << (prm->a - j)) + s, j);
            //sprintf(buffer, "H_%d(nivel %d)", (i << (prm->a - j)) + s, j);
            kat_hex(buffer, sf, prm->n); 
            sf += n;
        }
    }
    return n * prm->k * (1 + prm->a);
}

//  === Compute a FORS public key from a FORS signature.
//  Algorithm 16: fors_pkFromSig(SIGFORS , md, PK.seed, ADRS)

static void fors_pk_from_sig(   slh_ctx_t *ctx, uint8_t *pk,
                                const uint8_t *sf, const uint8_t *md)
{

    const slh_param_t *prm = ctx->prm;
    uint32_t i, j, idx;
    uint32_t vi[SLH_MAX_K];
    uint8_t root[SLH_MAX_K * SLH_MAX_N];
    uint8_t *node;
    size_t  n = prm->n;

    FIPS_REF(17,1,"Se calculan los indices de md.");

    base_2b(vi, md, prm->a, prm->k);

    node = root;
    for (i = 0; i < prm->k; i++) {
        //sprintf(buffer, "Se establece el campo TREE_HEIGHT de ADDR a 0 ya que se va a calcular F=(PK.SEED,ADRS,sk_%d)", i);
        FIPS_REF(17, 4, buffer);
        adrs_set_tree_height(ctx, 0);

        idx = (i << prm->a) + vi[i];
        //sprintf(buffer, "Se establece el campo TREE_INDEX de la estructura ADDR a %d", idx);
        FIPS_REF(17,5, buffer);
        adrs_set_tree_index(ctx, idx);
        //sprintf(buffer, "Se calcula F_%d = (PK.SEED,ADRS,sk_%d_%d)", idx, i, idx);
        FIPS_REF(17, 6, buffer);
        prm->h_f(ctx, node, sf);
        sf += n;
        //sprintf(buffer, "Se va a utilizar un bucle for para el calculo de la raiz del arbol %d del esquema FORS",i);
        FIPS_REF(17, 8, buffer);
        for (j = 0; j < prm->a; j++) {
            LOG("Se va a calcular el nodo H_%d(nivel %d) del arbol %d del esquema FORS", idx >> (j+1), j+1, i);
            FIPS_REF(17, 9, "Se establece el campo TREE_HEIGHT de la estructura ADDR.");
            adrs_set_tree_height(ctx, j + 1);
            FIPS_REF(17,11, "Se establece el campo TREE_INDEX de la estructura ADDR.");
            adrs_set_tree_index(ctx, idx >> (j + 1));
            //sprintf(buffer, "Se va a calcular el nodo H_%d(nivel %d) = H(PK.SEED,ADRS,H_%d(nivel %d)||H_%d(nivel %d))", idx >> (j+1), j+1, idx >> j,j,(idx >> j)+1,j);
            FIPS_REF(17, 10, buffer);
            if (((vi[i] >> j) & 1) == 0) {
                prm->h_h(ctx, node, node, sf);
            } else {
                prm->h_h(ctx, node, sf, node);
            }
            sf += n;
        }
        //sprintf(buffer, "La clave publica FORS pk_%d", i);
        kat_hex(buffer, node, prm->n);
        node += n;
    }

    adrs_set_type_and_clear_not_kp(ctx, ADRS_FORS_ROOTS);
    prm->h_t(ctx, pk, root, prm->k * n);
}

//  === Public API

//  Return standard identifier string for parameter set *prm, or NULL.
const char *slh_alg_id(const slh_param_t *prm)
{
    return prm->alg_id;
}

//  Return public (verification) key size in bytes for parameter set *prm.
size_t slh_pk_sz(const slh_param_t *prm)
{
    return 2 * prm->n;
}

//  Return private (signing) key size in bytes for parameter set *prm.
size_t slh_sk_sz(const slh_param_t *prm)
{
    return 4 * prm->n;
}

//  === Generate an SLH-DSA key pair.
//  Algorithm 17: slh_keygen()

int slh_keygen(uint8_t *pk, uint8_t *sk,
               int (*rbg)(uint8_t *x, size_t xlen), const slh_param_t *prm)
{

    slh_ctx_t   ctx;
    uint8_t     pk_root[SLH_MAX_N];
    size_t      n = prm->n;

    #ifdef DEBUG_LOG
    printf("--------------------------------------------------------------\n");
    printf("------Se generan SK.SEED, SK.PRF y PK.SEED usando el DBRG-----\n");
    printf("--------------------------------------------------------------\n\n");
    printf("[FILE]->[FUNCTION]:[LINE] %s->%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
    #endif
    rbg(sk, 3 * n);                     //  SK.seed || SK.prf || PK.seed
    kat_hex("SK.SEED", sk, prm->n);
    kat_hex("SK.PRF", sk + 1*prm->n, prm->n);
    kat_hex("PK.SEED", sk + 2*prm->n, prm->n);
    memcpy(pk, sk + 2 * n, n);          //  PK.seed
    memset(sk + 3 * n, 0x00, n);        //  PK.root not generated yet
    kat_hex("PK", pk, slh_pk_sz(prm));
    kat_hex("SK", sk, slh_sk_sz(prm));
    printf("\n");
    prm->mk_ctx(&ctx, NULL, sk, prm);   //  fill in partial

    #ifdef DEBUG_LOG
    printf("--------------------------------------------------------------\n");
    printf("--------------------Generacion de PK.ROOT---------------------\n");
    printf("--------------------------------------------------------------\n\n");
    printf("--------------------------------------------------------------\n");
    printf("------------Inicializacion de la estructura ADDRS-------------\n");
    printf("--------------------------------------------------------------\n\n");
    #endif
    FIPS_REF(18, 0, "Se inicializa la estructutra ADDR");
    adrs_zero(&ctx);
    adrs_set_layer_address(&ctx, prm->d - 1);
    print_addr(&ctx);
    xmss_node(&ctx, pk_root, 0, prm->hp, 0);
    #ifdef DEBUG_LOG
    printf("--------------------------------------------------------------\n\n");
    #endif
    kat_hex("PK.ROOT", pk_root, prm->n);
    //  fill pk_root
    memcpy(sk + 3 * n, pk_root, n);
    memcpy(pk + n, pk_root, n);
    return 0;
}

//  === Generate an SLH-DSA signature.
//  Algorithm 18: slh_sign(M, SK)

//  (Shared helper function for algorithms 18 and 19.)

static void split_digest(uint64_t *i_tree, uint32_t *i_leaf,
                         const uint8_t *digest, const slh_param_t *prm)
{
    size_t      md_sz       = (prm->k * prm->a + 7) / 8;
    const uint8_t *pi_tree  = digest + md_sz;
    size_t      i_tree_sz   = (prm->h - prm->hp + 7) / 8;
    *i_tree     = slh_toint(pi_tree, i_tree_sz);
    size_t      i_leaf_sz   = (prm->hp + 7) / 8;
    const uint8_t *pi_leaf  = pi_tree + i_tree_sz;
    *i_leaf     = slh_toint(pi_leaf, i_leaf_sz);
    if ((prm->h - prm->hp) != 64) {
        *i_tree     &= (UINT64_C(1) << (prm->h - prm->hp)) - UINT64_C(1);
    }
    *i_leaf     &= (1 << prm->hp) - 1;
}

//  Core signing function that just takes in "digest" and an already
//  initialized secret key context. *sig points to signature after randomizer.
//  Returns the length of |SIG_FORS + SIG_HT| written at *sig.

size_t slh_do_sign( slh_ctx_t *ctx, uint8_t *sig, const uint8_t *digest)
{
    const uint8_t   *md = digest;
    uint64_t i_tree = 0;
    uint32_t i_leaf = 0;
    uint8_t pk_fors[SLH_MAX_N];
    size_t sig_sz;

    //FIPS_REF(19, 6, "Se calcula md, idx_tree e idx_leaf.");
    split_digest(&i_tree, &i_leaf, digest, ctx->prm);
    //LOG("idx_tree = %lu \nidx_leaf = %d\n", i_tree, i_leaf);
    //kat_hex("md", md, (ctx->prm->k * ctx->prm->a)/8);
    adrs_zero(ctx);
    //FIPS_REF(19, 11, "Se asignan los campos TREE_ADDRESS, KEY_PAIR_ADDRESS y TYPE de la estructura ADDR");
    adrs_set_tree_address(ctx, i_tree);
    adrs_set_type_and_clear_not_kp(ctx, ADRS_FORS_TREE);
    adrs_set_key_pair_address(ctx, i_leaf);
    //  SIG_FORS
    //FIPS_REF(19, 14, "Se va a proceder a realizar la firma FORS de md.");
    sig_sz  = fors_sign(ctx, sig, md);
    //FIPS_REF(19, 16, "Se va a proceder a obtener la clave publica FORS, a partir de la firma FORS previa.\n Esta clave publica sera la que se firme usando el hiperarbol de SLH-DSA.");
    fors_pk_from_sig(ctx, pk_fors, sig, md);
    //kat_hex("La clave pública del esquema FORS PK=T_k(PK.SEED,ADDR,pk)", pk_fors, ctx->prm->n); 
    //  SIG_HT
    sig +=  sig_sz;
    //FIPS_REF(19, 17, "Se genera el resto de la firma mediante la firma de la clave publica FORS con el hiperarbol");
    sig_sz  += ht_sign(ctx, sig, pk_fors, i_tree, i_leaf);
    neorv32_gpio_pin_set(7,1); 
    return sig_sz;
}

size_t slh_sign(uint8_t *sig, const uint8_t *m, size_t m_sz,
                const uint8_t *sk, int (*rbg)(uint8_t *x, size_t xlen),
                const slh_param_t *prm)
{
    static slh_ctx_t   ctx;
    static uint8_t opt_rand[SLH_MAX_N];
    static uint8_t digest[SLH_MAX_M];

    //  set up secret key etc
    prm->mk_ctx(&ctx, NULL, sk, prm); 

#ifdef SLH_DETERMINISTIC
    memcpy(opt_rand, ctx.pk_seed, prm->n);
#else
    rbg(opt_rand, prm->n);
     
#endif
    //LOG("Se va a firmar el mensaje Msg.");
    //kat_hex("Msg", m, m_sz);
    //  randomized hashing; R
    uint8_t *r  = sig;
    size_t  sig_sz = prm->n;
    //FIPS_REF(19, 3, "Se va a calcular el Randomizer. R = PRF_msg(...,Msg)"); 
  
    prm->prf_msg(&ctx, r, opt_rand, m, m_sz);    
    //kat_hex("R", r, sig_sz);
    //FIPS_REF(19, 5, "Se calcula el digest. digest = H_msg(...,Msg)");
    prm->h_msg(&ctx, digest, r, m, m_sz);
    //kat_hex("digest", digest, prm->m);
    neorv32_gpio_pin_set(2,1);     
    //  create FORS and HT signature parts
    sig_sz += slh_do_sign(&ctx, sig + sig_sz, digest);
    neorv32_gpio_pin_set(4,1);
    return sig_sz;
}

//  === Verify an SLH-DSA signature.
//  Algorithm 19: slh_verify(M, SIG, PK)

bool slh_verify(const uint8_t *m, size_t m_sz,
                const uint8_t *sig, const uint8_t *pk,
                const slh_param_t *prm)
{

    slh_ctx_t   ctx;
    uint8_t digest[SLH_MAX_M];
    uint8_t pk_fors[SLH_MAX_N];

    const uint8_t   *r          = sig;
    const uint8_t   *sig_fors   = sig + prm->n;
    const uint8_t   *sig_ht     = sig + ((1 + prm->k*(1 + prm->a)) * prm->n);

    prm->mk_ctx(&ctx, pk, NULL, prm);
    prm->h_msg(&ctx, digest, r, m, m_sz);

    const uint8_t   *md = digest;
    uint64_t        i_tree = 0;
    uint32_t        i_leaf = 0;
    split_digest(&i_tree, &i_leaf, digest, prm);

    adrs_zero(&ctx);
    adrs_set_tree_address(&ctx, i_tree);
    adrs_set_type_and_clear_not_kp(&ctx, ADRS_FORS_TREE);
    adrs_set_key_pair_address(&ctx, i_leaf);

    fors_pk_from_sig(&ctx, pk_fors, sig_fors, md);

    bool sig_ok = ht_verify(&ctx, pk_fors, sig_ht, i_tree, i_leaf);
    return sig_ok;
}

