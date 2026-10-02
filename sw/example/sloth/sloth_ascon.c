//  slh_ascon.c
//  Carlos Fernández-García

//  === SLotH: Accelerated functions for instantiation of SLH-DSA with Ascon-XOF

#ifdef SLOTH_ASCON

#include "ascon_api.h"
#include "sloth_hal.h"

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
    r32[ASCON_TRIG] = 0xf0;                  //  start it
    ASCON_WAIT

    for (i = 0; i < 10; i++) {              //  actually slow part 2
        v32[i] = r32[i];
    }
}

//  SLOTH_ASCON
#endif
