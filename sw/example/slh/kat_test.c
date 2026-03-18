//  kat_test.c
//  Markku-Juhani O. Saarinen <mjos@iki.fi>.  See LICENSE.

//  === KAT Testing for SLH-DSA

#include "neorv32_uart.h"
#ifndef SLOTH

// #include <stdio.h>
#include <string.h>
// #include <stdlib.h>
// #include <assert.h>
#include <neorv32.h>

#include "slh_dsa.h" // Aquí se puede encontrar toda la lógica necesaria para la implementeación de SLH-DSA.
#include "kat_drbg.h" // Aquí se encuentra la lógica necesaria para la implementación de los números "pseudoaleatorios" empleados para la generación de los test.
#include "log.h"

#ifndef KATNUM
#define KATNUM 1
#endif
#define BAUD_RATE 19200

//  fake test drbg state
//aes_256_ctr_drbg_t kat_drbg, iut_drbg;// kat_drbg es utilizado para la generación de valores pseudoaleatorios del test. 
//                                      iut_drbg es utilizado para la generación de valores pseudoaleatorios del esquemas de firmas.

//  for the callback interface
int iut_randombytes(uint8_t *x, size_t xlen)
{
    //aes_256ctr_xof(&iut_drbg, x, xlen);
    return 0;
}
// Función empleada para imprimir los valores de las cadenas de caracteres en el fichero fh.
static void kat_hex(const char *label,
                    const uint8_t *x, size_t xlen)
{
    size_t i;
    neorv32_uart0_printf("%s = ", label);
    for (i = 0; i < xlen; i++) {
        neorv32_uart0_printf("%X", x[i]);
    }
    neorv32_uart0_printf("\n");
}

int kat_test(const slh_param_t *iut, int katnum)
{
    neorv32_uart0_printf("DBG0\n");
    int fail = 0;


    uint8_t seed[48] = {0x06,0x15,0x50,0x23,0x4D,0x15,0x8C,0x5E,0xC9,0x55,0x95,0xFE,\
                        0x04,0xEF,0x7A,0x25,0x76,0x7F,0x2E,0x24,0xCC,0x2B,0xC4,0x79,\
                        0xD0,0x9D,0x86,0xDC,0x9A,0xBC,0xFD,0xE7,0x05,0x6A,0x8C,0x26,\
                        0x6F,0x9E,0xF9,0x7E,0xD0,0x85,0x41,0xDB,0xD2,0xE1,0xFF,0xA1};
    uint8_t msg[33 * KATNUM] = {0xD8,0x1C,0x4D,0x8D,0x73,0x4F,0xCB,0xFB,0xEA,0xDE,0x3D,\
                                0x3F,0x8A,0x03,0x9F,0xAA,0x2A,0x2C,0x99,0x57,0xE8,0x35,\
                                0xAD,0x55,0xB2,0x2E,0x75,0xBF,0x57,0xBB,0x55,0x6A,0xC8};
    size_t msg_sz= 0, pk_sz = 0, sk_sz = 0, sig_sz = 0, sm_sz = 0;

    uint8_t pk[2 * 32] = { 0 };
    uint8_t sk[4 * 32] = {0x7C,0x99,0x35,0xA0,0xB0,0x76,0x94,0xAA,0x0C,0x6D,0x10,0xE4,0xDB,0x6B,0x1A,0xDD,\
                          0x2F,0xD8,0x1A,0x25,0xCC,0xB1,0x48,0x03,0x2D,0xCD,0x73,0x99,0x36,0x73,0x7F,0x2D,\
                          0xB5,0x05,0xD7,0xCF,0xAD,0x1B,0x49,0x74,0x99,0x32,0x3C,0x86,0x86,0x32,0x5E,0x47,\
                          0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,\
                          0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,\
                          0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,\
                          0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,\
                          0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
    uint8_t sm[50000 + 33 * KATNUM];

    // snneorv32_uart0_printf(fn, sizeof(fn), "%s-%d.rsp", slh_alg_id(iut), katnum);
    // fh = fopen(fn, "w");// Abrimos el fichero con el nombre "%s-%d.rsp"
    // if (fh == NULL) {
    //     perror(fn);
    //     fail++;
    //     return fail;
    // }
    //
    // fneorv32_uart0_printf(fh, "# SPHINCS+\n\n");

    //  initialize kat seed drbg
    // for (int i = 0; i < 48; i++) {
    //     seed[i] = i;
    // }
    // //aes_256ctr_xof_init(&kat_drbg, seed);
    neorv32_uart0_printf("DBG1\n");
    pk_sz = slh_pk_sz(iut);
    // assert(sizeof(pk) >= pk_sz);
    sk_sz = slh_sk_sz(iut);
    // assert(sizeof(sk) >= sk_sz);
    sig_sz = slh_sig_sz(iut);

    for (int count = 0; count < katnum; count++) {

        // neorv32_uart0_printf("[KAT] (%d) %s\n", count, fn);
        // fflush(stdout);
        //
        // fneorv32_uart0_printf(fh, "count = %d\n", count);
        // Con este código se inicializa el drbg para generar los datos del test.
        //aes_256ctr_xof(&kat_drbg, seed, 48);
        kat_hex("seed", seed, 48);
        //---------------------------------------------------------------------------------------------------------
        msg_sz = (count + 1) * 33;
        neorv32_uart0_printf("mlen = %zu\n", msg_sz);
        // assert(sizeof(sm) >= sig_sz + msg_sz);
        // Con la llamada a esta función se genera de manare "pseudoaleatoria" el mensaje a firmar.
        //aes_256ctr_xof(&kat_drbg, msg, msg_sz);
        kat_hex("msg", msg, msg_sz);
        //---------------------------------------------------------------------------------------------------------
        //  initialize target drbg
        //aes_256ctr_xof_init(&iut_drbg, seed);
        // Generación de la clave privada pk y pública sk.
        #ifdef DEBUG_LOG
        neorv32_uart0_printf("**************************************************************\n");
        neorv32_uart0_printf("*******************Key Generation Process*********************\n");
        neorv32_uart0_printf("**************************************************************\n\n");
        #endif /* ifdef DEBUG_LOG */

        neorv32_uart0_printf("slh_keygen entry point\n");
        slh_keygen(pk, sk, &iut_randombytes, iut);
        neorv32_uart0_printf("Exit slh_keygen\n");
        kat_hex("pk", pk, 2*32);

        #ifdef DEBUG_LOG
        neorv32_uart0_printf("**************************************************************\n");
        neorv32_uart0_printf("**************************************************************\n\n");
        #endif /* ifdef DEBUG_LOG */

        #ifdef DEBUG_LOG
        kat_hex(stdout, "pk", pk, pk_sz);
        kat_hex(stdout, "sk", sk, sk_sz);
        #endif /* ifdef DEBUG_LOG */
        // kat_hex(fh, "pk", pk, pk_sz);
        // kat_hex(fh, "sk", sk, sk_sz);
        #ifdef DEBUG_LOG
        neorv32_uart0_printf("**************************************************************\n");
        neorv32_uart0_printf("*****************Digital Signature Process********************\n");
        neorv32_uart0_printf("**************************************************************\n\n");      
        #endif /* ifdef DEBUG_LOG */

        #ifdef DEBUG_LOG
        FIPS_REF(19, 0, "Begining of a the digital signature process.");
        #endif /* ifdef DEBUG_LOG */
        neorv32_uart0_printf("slh_sign entry point\n");
        sm_sz = slh_sign(sm, msg, msg_sz, sk, &iut_randombytes, iut);
        neorv32_uart0_printf("exit slh_sign\n");
        #ifdef DEBUG_LOG
        neorv32_uart0_printf("**************************************************************\n");
        neorv32_uart0_printf("**************************************************************\n\n");
        #endif /* ifdef DEBUG_LOG */

        memcpy(sm + sm_sz, msg, msg_sz);
        sm_sz += msg_sz;
        neorv32_uart0_printf("smlen = %zu\n", sm_sz);

        kat_hex("sm", sm, sm_sz);
        neorv32_uart0_printf("\n");
        // assert(sm_sz == sig_sz + msg_sz);
        #ifdef DEBUG_LOG
        neorv32_uart0_printf("**************************************************************\n");
        neorv32_uart0_printf("****************Digital Signature Verification****************\n");
        neorv32_uart0_printf("**************************************************************\n\n");       
        #endif /* ifdef DEBUG_LOG */
        if (!slh_verify(sm + sig_sz, msg_sz, sm, pk, iut)) {
            fail++;
            neorv32_uart0_printf("[FAIL] slh_verify() fails.\n");
        }
        #ifdef DEBUG_LOG
        neorv32_uart0_printf("**************************************************************\n");
        neorv32_uart0_printf("**************************************************************\n\n");       
        #endif /* ifdef DEBUG_LOG */

        #ifdef DEBUG_LOG
        neorv32_uart0_printf("**************************************************************\n");
        neorv32_uart0_printf("****************Digital Signature Verification****************\n");
        neorv32_uart0_printf("**************************(Forgery)***************************\n");
        neorv32_uart0_printf("**************************************************************\n\n");       
        #endif /* ifdef DEBUG_LOG */
        //  flip random bit
        uint32_t xbit = ((uint32_t) seed[4]) +
                        (((uint32_t) seed[5]) <<  8) +
                        (((uint32_t) seed[6]) << 16) +
                        (((uint32_t) seed[7]) << 24);
        xbit %= (8 * sm_sz);
        sm[xbit >> 3] ^= 1 << (xbit & 7);
        if (slh_verify(sm + sig_sz, msg_sz, sm, pk, iut)) {
            fail++;
            // neorv32_uart0_printf("[FAIL] slh_verify() forgery bit= %u.\n", xbit);
        }
        #ifdef DEBUG_LOG
        neorv32_uart0_printf("**************************************************************\n");
        neorv32_uart0_printf("**************************************************************\n\n");       
        #endif /* ifdef DEBUG_LOG */
    }
    // fclose(fh);

    return fail;
}

//  test targets

const slh_param_t *test_iut[] = {
    &slh_dsa_shake_128s,
    &slh_dsa_shake_128f,
    &slh_dsa_shake_192s,
    &slh_dsa_shake_192f,
    &slh_dsa_shake_256s,
    &slh_dsa_shake_256f,
    NULL
};

int main(void)
{
    neorv32_rte_setup();
    neorv32_uart0_setup(BAUD_RATE, 0);
    neorv32_uart0_puts("SLH-DSA in NEORV32\n");
    int fail = 0;
    int iut_n = 0;

    // if  (argc == 2 &&
    //     (iut_n = atoi(argv[1])) >= 0 &&
    //     iut_n < 12) {
    neorv32_uart0_printf("kat_test entry point\n");
  neorv32_uart0_printf("SLH-DSA algorithm: %s\n", slh_alg_id(test_iut[iut_n]));
    fail += kat_test(test_iut[iut_n], 1);
    // } else {
    //     for (iut_n = 0; test_iut[iut_n] != NULL; iut_n++) {
    //         fail += kat_test(test_iut[iut_n], KATNUM);
    //     }
    // }

    neorv32_uart0_printf("[INFO] test_slh_dsa() fail= %d\n", fail);

    return fail;
}

#endif
