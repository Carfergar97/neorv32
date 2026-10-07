//  test_sloth.c
//  Markku-Juhani O. Saarinen <mjos@iki.fi>.  See LICENSE.

//  === some basic health test for sloth modules

#include <stdint.h>
#include <string.h>
#include "neorv32_uart.h"
#include "plat_local.h"
#include "test_rvkat.h"
#include "sloth_hal.h"
#include "neorv32.h"

#include "sha2_api.h"
#include "sha3_api.h"
#include "ascon_api.h"
#include "slh_dsa.h"
#include "slh_ctx.h"

//  basic permutation tests

void perf_ticks(const char *lab, uint32_t cc)
{
    neorv32_uart0_printf("[CLK]\t");
    // sio_put_dec(cc);
    neorv32_uart0_tx_put('\t');
    neorv32_uart0_printf(lab);
    neorv32_uart0_tx_put('\n');
}

#ifdef SLOTH_KECTI3
int test_kecti3()
{
    int fail = 0;
    uint8_t buf[200];

    memset(buf, 0x00, 200);
    memcpy(buf, "abc\x1F", 4);              //  pad: 0x1F=SHAKE, 0x06=SHA-3
    buf[200 - 2*32 - 1] = 0x80;             //  rate/capacity for 256

    uint32_t *v32 = (uint32_t *) buf;
    volatile uint32_t   *r32 = (volatile uint32_t *) KECTI3_BASE_ADDR;
    int i;
    uint32_t t, u;

    t = 0;
    u = 0;

    for (i = 0; i < 50; i++) {
        t += 0xDEADBEEF + u;                //  "random masks"
        u += 0x01234567 + t;

        r32[KTI3_MEMA + i] = v32[i] ^ t ^ u;
        r32[KTI3_MEMB + i] = t;
        r32[KTI3_MEMC + i] = u;
    }
    r32[KTI3_STOP] = 0x74;                  //  stop position
    r32[KTI3_TRIG] = 0x01;                  //  start it
    KTI3_WAIT

    uint32_t a, b, c, x;
    for (i = 0; i < 50; i++) {
        a = r32[KTI3_MEMA + i];
        b = r32[KTI3_MEMB + i];
        c = r32[KTI3_MEMC + i];
        x = a ^ b ^ c;                      //  collapse
        v32[i] = x;
    }

    //  SHAKE256("abc") =
    //  483366601360A8771C6863080CC4114D8DB44530F8F1E1EE4F94EA37E78B5739
    fail += rvkat_chku32("kecti3", 0x07C97065, rvkat_cksum(buf, 32));

    return fail;
}
#endif

int test_sloth()
{
    int fail = 0;

    const uint8_t sha2_iv[8][8] = {
        {   0x6A, 0x09, 0xE6, 0x67, 0xF3, 0xBC, 0xC9, 0x08  },
        {   0xBB, 0x67, 0xAE, 0x85, 0x84, 0xCA, 0xA7, 0x3B  },
        {   0x3C, 0x6E, 0xF3, 0x72, 0xFE, 0x94, 0xF8, 0x2B  },
        {   0xA5, 0x4F, 0xF5, 0x3A, 0x5F, 0x1D, 0x36, 0xF1  },
        {   0x51, 0x0E, 0x52, 0x7F, 0xAD, 0xE6, 0x82, 0xD1  },
        {   0x9B, 0x05, 0x68, 0x8C, 0x2B, 0x3E, 0x6C, 0x1F  },
        {   0x1F, 0x83, 0xD9, 0xAB, 0xFB, 0x41, 0xBD, 0x6B  },
        {   0x5B, 0xE0, 0xCD, 0x19, 0x13, 0x7E, 0x21, 0x79  }
    };

    uint8_t buf[200];
    uint32_t cc;
    int i;

#ifdef SLOTH_KECTI3
    fail += test_kecti3();
#endif

    //  SHA2-256
    #ifdef SLOTH_SHA2
      // memset(buf, 0x00, 96);
      // for (i = 0; i < 8; i++) {
      //     memcpy(buf + 4 * i, sha2_iv[i], 4);
      // }
      // memcpy(buf + 32, "abc\x80", 4);
      // buf[95] = 3 * 8;
      //
      // cc = get_clk_ticks();
      // sha256_compress(buf);
      // cc = get_clk_ticks() - cc;
      // perf_ticks("sha256_compress()", cc);
      //
      // //  SHA2-256("abc") =
      // //  BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD
      // fail += rvkat_chku32("sha256", 0x55F39AFA, rvkat_cksum(buf, 32));
      //
      // //  SHA2-512
      // memset(buf, 0x00, 192);
      // memcpy(buf, sha2_iv, 64);
      // memcpy(buf + 64, "abc\x80", 4);
      // buf[191] = 3 * 8;
      //
      // cc = get_clk_ticks();
      // sha512_compress(buf);
      // cc = get_clk_ticks() - cc;
      // perf_ticks("sha512_compress()", cc);
      //
      // //  SHA2-512("abc") =
      // //  DDAF35A193617ABACC417349AE20413112E6FA4E89A97EA20A9EEEE64B55D39A
      // //  2192992A274FC1A836BA3C23A3FEEBBD454D4423643CE80E2A9AC94FA54CA49F
      // fail += rvkat_chku32("sha512", 0x1F59A287, rvkat_cksum(buf, 64));
    #endif /* ifdef SHA2 */

    //  SHAKE256
    memset(buf, 0x00, 200);
    memcpy(buf, "abc\x1F", 4);              //  pad: 0x1F=SHAKE, 0x06=SHA-3
    buf[200 - 2*32 - 1] = 0x80;             //  rate/capacity for 256

    // cc = get_clk_ticks();
    keccak_f1600(buf);
    // cc = get_clk_ticks() - cc;
    // perf_ticks("keccak_f1600()", cc);
    //  SHAKE256("abc") =
    //  483366601360A8771C6863080CC4114D8DB44530F8F1E1EE4F94EA37E78B5739
    fail += rvkat_chku32("shake256", 0x07C97065, rvkat_cksum(buf, 32));

  uint8_t asconBuf[16];
  uint8_t ascon_msg[3] = {0x00,0x01,0x02};
  memset(asconBuf, 0x00, 16);
  memcpy(asconBuf,ascon_msg,3); 
  crypto_hash(asconBuf,asconBuf,3);
  neorv32_uart0_printf("The asconxof128 digest is: 0x");
  for (uint8_t i = 0; i<16; i++) {
    neorv32_uart0_printf("%X", asconBuf[i]); 
  }
  neorv32_uart0_printf("\n");
  fail += rvkat_chku32("asconxof-128", 0x4116e853, rvkat_cksum(asconBuf, 16));

  neorv32_uart0_printf("TEST de las funciones de ASCON para comprobar que la implementación sea correcta en el NEORV32\n");

  slh_ctx_t ctx;
  ctx.prm = &slh_dsa_ascon_128s;
  uint8_t pk_test[2*32] = {0};
  uint8_t sk_test[4*32] = {0};
  ctx.prm->mk_ctx(&ctx, pk_test, sk_test, ctx.prm);
  uint8_t m1[16]={0};
  uint8_t h[16]={0};

  slh_dsa_ascon_128s.h_f(&ctx, h, m1);

  neorv32_uart0_printf("ascon_f output is 0x");
  for (size_t i=0; i<16; i++) {
    neorv32_uart0_printf("%X",h[i]);
  }
  neorv32_uart0_printf("\n");
return fail;
}
