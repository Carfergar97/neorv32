
//  kat_test.c
//  Markku-Juhani O. Saarinen <mjos@iki.fi>.  See LICENSE.

//  === KAT Testing for SLH-DSA

#ifndef SLOTH


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <neorv32.h>
#include "slh_dsa.h" // Aquí se puede encontrar toda la lógica necesaria para la implementeación de SLH-DSA.
#include "kat_drbg.h" // Aquí se encuentra la lógica necesaria para la implementación de los números "pseudoaleatorios" empleados para la generación de los test.
#include "log.h"

#ifndef KATNUM
#define KATNUM 1 //defino para 1, solo copila 128s
#endif

//----------------------------------------------------------------------------
//Variables globales para el calculo de tiempo de ejecución de los test.
//----------------------------------------------------------------------------
static uint64_t end_time, sign_time,key_gen_time, verify_time;
static uint32_t sign_time_s = 0, key_gen_time_s = 0, verify_time_s = 0, end_time_s = 0;
//----------------------------------------------------------------------------

static uint8_t sm[7889];//SE HA CAMBIADO 2 veces ha saltado un assert al no caber el mensaje a firmar en el array. Se ha cambiado a 8856 porque es el tamaño del mensaje más grande que se puede generar con el 128s, que es el único que se va a probar de momento.
//  fake test drbg state
aes256_ctr_drbg_t kat_drbg, iut_drbg;// kat_drbg es utilizado para la generación de valores pseudoaleatorios del test. 
//                                      iut_drbg es utilizado para la generación de valores pseudoaleatorios del esquemas de firmas.

//  for the callback interface
int iut_randombytes(uint8_t *x, size_t xlen)
{
    //Para realizar un prueba sin DRBG, lo quito y añade "manualmente" valores.
    for (size_t i = 0; i < xlen; i++) {
        x[i] = (uint8_t)(i & 0xFF);
    }
    //aes256ctr_xof(&iut_drbg, x, xlen);//Se prueba quitando el drgb y añadiendo el trgb de la placa siendo el primer acelerado hardware
    return 0;
}
// Función empleada para imprimir los valores de las cadenas de caracteres en el fichero fh.
static void kat_hex(const char *label,
                    const uint8_t *x, size_t xlen)
{
    size_t i;
    neorv32_uart0_printf("%s = ", label);
    for (i = 0; i < xlen; i++) {
        neorv32_uart0_printf("%02X", x[i]);
    }
    neorv32_uart0_printf("\r\n");
}

int kat_test(const slh_param_t *iut, int katnum)
{
    int fail = 0;

    char fn[256];

    uint8_t seed[48] = { 0 };
    uint8_t msg[33 * KATNUM] = { 0 };
    size_t msg_sz= 0, pk_sz = 0, sk_sz = 0, sig_sz = 0, sm_sz = 0;

    uint8_t pk[2 * 32] = { 0 };
    uint8_t sk[4 * 32] = { 0 };
    
//CON ESTO SE CREA EL FICHERO DONDE SE GUARDARAN LOS RESULTADOS DE LOS TESTS. EL NOMBRE DEL FICHERO SE CREA A PARTIR DEL NOMBRE DEL ESQUEMA DE FIRMA Y EL NUMERO DE TEST QUE SE ESTA REALIZANDO.
    //snprintf(fn, sizeof(fn), "%s-%d.rsp", slh_alg_id(iut), katnum);
    //fh = fopen(fn, "w");// Abrimos el fichero con el nombre "%s-%d.rsp"
    //if (fh == NULL) {
    //    perror(fn);
    //    fail++;
    //    return fail;
    //}
//PARA PONER LOS FICHEROS POR UAR SE AÑADE ESTE CODIGO
//SE INICIA PROCESADOR Y UART
neorv32_rte_setup();
neorv32_uart0_setup(19200, 0);
//IMPRIME PRIMER MENSAJE
neorv32_uart0_printf("--- INICIO DE PRUEBA: %s-%d ---\r\n", slh_alg_id(iut), katnum);

//    fprintf(fh, "# SPHINCS+\n\n");
neorv32_uart0_printf("# SPHINCS+\n\n");
    //  initialize kat seed drbg
    for (int i = 0; i < 48; i++) {
        seed[i] = i;
    }
    aes256ctr_xof_init(&kat_drbg, seed);

    pk_sz = slh_pk_sz(iut);
    assert(sizeof(pk) >= pk_sz);
    sk_sz = slh_sk_sz(iut);
    assert(sizeof(sk) >= sk_sz);
    sig_sz = slh_sig_sz(iut);
    for (int count = 0; count < katnum; count++) {

        //printf("[KAT] (%d) %s\n", count, fn);
        neorv32_uart0_printf("[KAT] (%d) %s\r\n", count, fn);
        fflush(stdout);
        //fprintf(fh, "count = %d\n", count);
        neorv32_uart0_printf("count = %d\r\n", count);
        // Con este código se inicializa el drbg para generar los datos del test.
        aes256ctr_xof(&kat_drbg, seed, 48);
        kat_hex(stdout, "seed", seed, 48);//fh
        //---------------------------------------------------------------------------------------------------------
        msg_sz = (count + 1) * 33;
        //fprintf(fh, "mlen = %zu\n", msg_sz);
        //neorv32_uart0_printf("mlen = %zu\r\n", msg_sz);
        neorv32_uart0_printf("\r");
        neorv32_uart0_printf("mlen = %u\r\n", (unsigned int)msg_sz);
        assert(sizeof(sm) >= sig_sz + msg_sz);
        // Con la llamada a esta función se genera de manare "pseudoaleatoria" el mensaje a firmar.
        aes256ctr_xof(&kat_drbg, msg, msg_sz);
        kat_hex("msg", msg, msg_sz);
        //---------------------------------------------------------------------------------------------------------
        //  initialize target drbg
        aes256ctr_xof_init(&iut_drbg, seed);
        // Generación de la clave privada pk y pública sk.
        neorv32_uart0_printf("\r\n");
        neorv32_uart0_printf("**************************************************************\r\n");
        neorv32_uart0_printf("*******************Key Generation Process*********************\r\n");
        neorv32_uart0_printf("**************************************************************\r\n\r\n");
        #ifdef DEBUG_LOG
        printf("**************************************************************\n");
        printf("*******************Key Generation Process*********************\n");
        printf("**************************************************************\n\n");
        #endif /* ifdef DEBUG_LOG */
        //--------------------------------------------------------------------------
        key_gen_time = neorv32_cpu_get_cycle();
        //--------------------------------------------------------------------------
        slh_keygen(pk, sk, &iut_randombytes, iut);
// Copiamos los 32 bytes de la clave pública (pk) que generó el DRBG
//uint8_t pk_fija[32] = {
  //  0xB5, 0x05, 0xD7, 0xCF, 0xAD, 0x1B, 0x49, 0x74, 0x99, 0x32, 0x3C, 0x86, 0x86, 0x32, 0x5E, 0x47,
  //  0xAC, 0x52, 0x49, 0x02, 0xFC, 0x81, 0xF5, 0x03, 0x2B, 0xC2, 0x7B, 0x17, 0xD9, 0x26, 0x1E, 0xBD
//};
//for(int i = 0; i < 32; i++) pk[i] = pk_fija[i];

// Copiamos los 64 bytes de la clave privada (sk) que generó el DRBG
//uint8_t sk_fija[64] = {
  //  0x7C, 0x99, 0x35, 0xA0, 0xB0, 0x76, 0x94, 0xAA, 0x0C, 0x6D, 0x10, 0xE4, 0xDB, 0x6B, 0x1A, 0xDD,
  //  0x2F, 0xD8, 0x1A, 0x25, 0xCC, 0xB1, 0x48, 0x03, 0x2D, 0xCD, 0x73, 0x99, 0x36, 0x73, 0x7F, 0x2D,
  //  0xB5, 0x05, 0xD7, 0xCF, 0xAD, 0x1B, 0x49, 0x74, 0x99, 0x32, 0x3C, 0x86, 0x86, 0x32, 0x5E, 0x47,
  //  0xAC, 0x52, 0x49, 0x02, 0xFC, 0x81, 0xF5, 0x03, 0x2B, 0xC2, 0x7B, 0x17, 0xD9, 0x26, 0x1E, 0xBD
//};
//for(int i = 0; i < 64; i++) sk[i] = sk_fija[i];


        #ifdef DEBUG_LOG
        printf("**************************************************************\n");
        printf("**************************************************************\n\n");
        #endif /* ifdef DEBUG_LOG */

        #ifdef DEBUG_LOG
        kat_hex(stdout, "pk", pk, pk_sz);
        kat_hex(stdout, "sk", sk, sk_sz);
        #endif /* ifdef DEBUG_LOG */
        kat_hex(stdout, "pk", pk, pk_sz);//fh
        kat_hex(stdout, "sk", sk, sk_sz);
        //--------------------------------------------------------------------------
        key_gen_time = neorv32_cpu_get_cycle()-key_gen_time;
        key_gen_time_s = (uint32_t)(key_gen_time / 100000000);
        neorv32_uart0_printf("\r\n");
        neorv32_uart0_printf("Key generation time: %u s\r\n", key_gen_time_s);
        neorv32_uart0_printf("\r\n");
        //----------------------------------------------------------------------------
        
        neorv32_uart0_printf("**************************************************************\r\n");
        neorv32_uart0_printf("*****************Digital Signature Process********************\r\n");
        neorv32_uart0_printf("**************************************************************\r\n\r\n");
        sign_time = neorv32_cpu_get_cycle();
        #ifdef DEBUG_LOG
        printf("**************************************************************\n");
        printf("*****************Digital Signature Process********************\n");
        printf("**************************************************************\n\n");      
        #endif /* ifdef DEBUG_LOG */

        #ifdef DEBUG_LOG
        FIPS_REF(19, 0, "Begining of a the digital signature process.");
        #endif /* ifdef DEBUG_LOG */
        sm_sz = slh_sign(sm, msg, msg_sz, sk, &iut_randombytes, iut);
        #ifdef DEBUG_LOG
        printf("**************************************************************\n");
        printf("**************************************************************\n\n");
        #endif /* ifdef DEBUG_LOG */
        neorv32_uart0_putc('\n');
        neorv32_gpio_pin_toggle(2);
        neorv32_uart0_printf("Signature generated. Signature length = %u bytes\r\n", (unsigned int)sm_sz);//Se cambia %zu por %u porque el tamaño del mensaje se ha cambiado a uint32_t para evitar el error de formato que se producía al imprimir un size_t con %zu.
        memcpy(sm + sm_sz, msg, msg_sz);
        sm_sz += msg_sz;
        //fprintf(fh, "smlen = %zu\n", sm_sz);
        neorv32_uart0_printf("smlen = %u\r\n", (unsigned int)sm_sz); //Se cambia %zu por %u porque el tamaño del mensaje se ha cambiado a uint32_t para evitar el error de formato que se producía al imprimir un size_t con %zu.
        neorv32_uart0_printf("\r\n");
        kat_hex(stdout, "sm", sm, sm_sz);//fh
        //fprintf(fh, "\n");
        //--------------------------------------------------------------------------
        sign_time = neorv32_cpu_get_cycle()-sign_time;
        sign_time_s = (uint32_t)(sign_time / 100000000);
        neorv32_uart0_printf("\r\n");
        neorv32_uart0_printf("Signature generation time: %u s\r\n", sign_time_s);
        //----------------------------------------------------------------------------  
        neorv32_uart0_printf("\r\n");
        assert(sm_sz == sig_sz + msg_sz);
        neorv32_uart0_printf("**************************************************************\r\n");
        neorv32_uart0_printf("****************Digital Signature Verification****************\r\n");
        neorv32_uart0_printf("**************************************************************\r\n\r\n");
        #ifdef DEBUG_LOG
        printf("**************************************************************\n");
        printf("****************Digital Signature Verification****************\n");
        printf("**************************************************************\n\n");       
        #endif /* ifdef DEBUG_LOG */
        verify_time = neorv32_cpu_get_cycle();
        if (!slh_verify(sm + sig_sz, msg_sz, sm, pk, iut)) {
            fail++;
            //fprintf(stderr, "[FAIL] slh_verify() fails.\n");
            neorv32_uart0_printf("[FAIL] slh_verify() fails.\r\n");
        }
        #ifdef DEBUG_LOG
        printf("**************************************************************\n");
        printf("**************************************************************\n\n");       
        #endif /* ifdef DEBUG_LOG */
        //--------------------------------------------------------------------------
        verify_time = neorv32_cpu_get_cycle()-verify_time;
        verify_time_s = (uint32_t)(verify_time / 100000000);
        neorv32_uart0_printf("Signature verification time: %u s\r\n", verify_time_s);
        neorv32_uart0_printf("\r\n");
        //----------------------------------------------------------------------------  

        neorv32_uart0_printf("**************************************************************\r\n");
        neorv32_uart0_printf("***********Digital Signature Verification (Forgery)***********\r\n");
        neorv32_uart0_printf("**************************************************************\r\n\r\n");
        #ifdef DEBUG_LOG
        printf("**************************************************************\n");
        printf("****************Digital Signature Verification****************\n");
        printf("**************************(Forgery)***************************\n");
        printf("**************************************************************\n\n");       
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
            //fprintf(stderr, "[FAIL] slh_verify() forgery bit= %u.\n", xbit);
            neorv32_uart0_printf("[FAIL] slh_verify() forgery bit= %u.\r\n", xbit);
        }

        #ifdef DEBUG_LOG
        printf("**************************************************************\n");
        printf("**************************************************************\n\n");       
        #endif /* ifdef DEBUG_LOG */
    }
    //fclose(fh);

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
    //&slh_dsa_sha2_128s,
    //&slh_dsa_sha2_128f,
    //&slh_dsa_sha2_192s,
    //&slh_dsa_sha2_192f,
    //&slh_dsa_sha2_256s,
    //&slh_dsa_sha2_256f,
    NULL
};

int main(int argc, char **argv)
{

    int fail = 0;
    int iut_n = 0;
    neorv32_wdt_disable();//Se desactiva el Watchdog Timer para evitar que el procesador se reinicie durante la ejecución de los test.
    if  (argc == 2 &&
        (iut_n = atoi(argv[1])) >= 0 &&
        iut_n < 12) {
        fail += kat_test(test_iut[iut_n], 1);
    } else {
        // Encendemos el LED 1 (Procesando el Test)
        // neorv32_gpio_pin_set(1,1);
        fail += kat_test(test_iut[0], KATNUM);
        }
    printf("[INFO] test_slh_dsa() fail= %d\n", fail);
    neorv32_uart0_printf("\r\n");
    //--------------------------------------------------------------------------
    end_time = sign_time + verify_time+key_gen_time;
    end_time_s = (uint32_t)(end_time / 100000000);
    neorv32_uart0_printf("|-----------------------------------------------------------|\r\n");
    neorv32_uart0_printf("|                      TIME SUMMARY:                        |\r\n");
    neorv32_uart0_printf("|-----------------------------------------------------------|\r\n");
    neorv32_uart0_printf("|                 Key generation time: %u s                  |\r\n", key_gen_time_s);
    neorv32_uart0_printf("|          Signature generation time: %u s                |\r\n", sign_time_s);
    neorv32_uart0_printf("|         Signature verification time: %u s                  |\r\n", verify_time_s);
    neorv32_uart0_printf("|               Total execution time: %u s                |\r\n", end_time_s);
    neorv32_uart0_printf("|-----------------------------------------------------------|\r\n");
    //----------------------------------------------------------------------------  

    neorv32_gpio_pin_set(1,0);
    return fail;
}

#endif
