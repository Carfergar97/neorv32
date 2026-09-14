// ================================================================================ //
// The NEORV32 RISC-V Processor - https://github.com/stnolting/neorv32              //
// Copyright (c) NEORV32 contributors.                                              //
// Copyright (c) 2020 - 2025 Stephan Nolting. All rights reserved.                  //
// Licensed under the BSD-3-Clause license, see LICENSE for details.                //
// SPDX-License-Identifier: BSD-3-Clause                                            //
// ================================================================================ //


/**********************************************************************//**
 * @file hello_world/main.c
 * @author Stephan Nolting
 * @brief Classic 'hello world' demo program.
 **************************************************************************/

#include <neorv32.h>
#include "aes.h"
#include "neorv32_aes128_v2.h"


/**********************************************************************//**
 * @name User configuration
 **************************************************************************/
/**@{*/
/** UART BAUD rate */
#define BAUD_RATE 19200
/**@}*/



/**********************************************************************//**
 * Main function; prints some fancy stuff via UART.
 *
 * @note This program requires the UART interface to be synthesized.
 *
 * @return 0 if execution was successful
 **************************************************************************/
int main() {

  // capture all exceptions and give debug info via UART
  // this is not required, but keeps us safe
  neorv32_rte_setup();

  // setup UART at default baud rate, no interrupts
  neorv32_uart0_setup(BAUD_RATE, 0);

neorv32_uart0_printf("\n\nInicio Prueba de Medida de Ciclos de Reloj (Version 2)\n\n");

    /*Definición PlainText y Key Ejemplo NIST*/
	uint8_t in[4*Nb] = {0x32,0x43,0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 
			    0xa2, 0xe0, 0x37, 0x07, 0x34};
 	uint8_t key[4*Nk] = {0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,
			     0x09,0xcf,0x4f,0x3c};
	char hex[] = "0123456789abcdef";
	neorv32_uart0_printf("PLAINTEXT: Ox"); // Impresión plaintext
	for(int i = 0; i < 16; i++){
		neorv32_uart0_putc(hex[(in[i] >> 4) & 0xF]); // nibble alto
		neorv32_uart0_putc(hex[in[i] & 0xF]); // nibble bajo
	}
	neorv32_uart0_printf("\n\n");
        neorv32_uart0_printf("KEY: Ox"); // Impresión key
        for(int i = 0; i < 16; i++){
                neorv32_uart0_putc(hex[(key[i] >> 4) & 0xF]); // nibble alto
                neorv32_uart0_putc(hex[key[i] & 0xF]); // nibble bajo
        }
        neorv32_uart0_printf("\n\n");
    /*Fin Definición PlainText y Key*/

 	uint32_t w[44]; // Variable KeySchedule
	uint8_t out[4*Nb]; // Variable Salida
	neorv32_uart0_printf("\n\n-- Cifrado AES-128 con Subextensiones Zknd y Zkne (Version 2) --\n");

     /*-- Key Schedule --*/
        KeyExpansionV2(key,w); // Cálculo KeySchedule
     /*-- Fin Key Schedule --*/

     /*-- Cifrado AES Version 2 --*/
	/*Medida Ciclos de Reloj para Cifrado con Subextensiones Zknd y Zknd*/
        // uint32_t ini = neorv32_cpu_csr_read(CSR_MCYCLE); // Lectura ciclos de reloj antes del cifrado
  uint64_t ini = neorv32_cpu_get_cycle();
	CipherV2(in,out,w); // Cifrado
   	// uint32_t fin = neorv32_cpu_csr_read(CSR_MCYCLE); // Lectura ciclos de reloj después del cifrado
  uint64_t fin = neorv32_cpu_get_cycle();
   	uint64_t ciclos = fin - ini; // Cálculo ciclos de reloj cifrado
        neorv32_uart0_printf("El numero de ciclos de reloj ha sido: %u\n",ciclos); // Impresión ciclos de reloj
        /*Fin Medida Ciclos de Reloj para Cifrado con Subextensiones Zknd y Zknd*/
     /*-- Fin Cifrado AES Version 2 --*/

     /*-- Descifrado AES Version 2 --*/
	neorv32_uart0_printf("\n\n-- Descifrado AES-128 con Subextensiones Zknd y Zkne (Version 2) --\n");
        /*Medida Ciclos de Reloj para Descifrado con Subextensiones Zknd y Zknd*/
        // ini = neorv32_cpu_csr_read(CSR_MCYCLE); // Lectura ciclos de reloj antes del cifrado
  ini = neorv32_cpu_get_cycle();
        InvCipherV2(out,out,w); // Cifrado
        // fin = neorv32_cpu_csr_read(CSR_MCYCLE); // Lectura ciclos de reloj después del cifrado
  fin = neorv32_cpu_get_cycle();
        ciclos = fin - ini; // Cálculo ciclos de reloj cifrado
        neorv32_uart0_printf("El numero de ciclos de reloj ha sido: %u\n",ciclos); // Impresión ciclos de reloj
        /*Fin Medida Ciclos de Reloj para Descifrado con Subextensiones Zknd y Zknd*/
     /*-- Fin Descifrado AES Version 2 --*/

     /*-- Cifrado AES Tiny AES --*/
        neorv32_uart0_printf("\n\n-- Cifrado AES-128 con Tiny-AES-128 --\n");
	/*Medida Ciclos de reloj para Cifrado con Librería Tiny-AES-C*/
	struct AES_ctx ctx; // Definición estructura para keyschedule
        AES_init_ctx(&ctx,key); // Cálculo keyschedule
        // ini = neorv32_cpu_csr_read(CSR_MCYCLE); // Lectura ciclos de reloj antes de cifrado
  ini = neorv32_cpu_get_cycle();
	AES_ECB_encrypt(&ctx,in); // Cifrado
        // fin = neorv32_cpu_csr_read(CSR_MCYCLE); // Lectura ciclos de reloj después de cifrado
  fin = neorv32_cpu_get_cycle();
        ciclos = fin - ini; // Cálculo cilos de reloj cifrado
        neorv32_uart0_printf("El numero de ciclos de reloj ha sido: %u\n",ciclos); // Impresión ciclos de reloj
        /*Fin Medida Ciclos de reloj para Cifrado con Librería Tiny-AES-C*/
     /*-- Fin Cifrado AES Tiny AES --*/

     /*-- Descifrado AES Tiny AES --*/
	neorv32_uart0_printf("\n-- Descifrado AES-128 con Tiny-AES-128 --\n");
        // ini = neorv32_cpu_csr_read(CSR_MCYCLE); // Lectura ciclos antes       
  ini = neorv32_cpu_get_cycle();
        AES_ECB_decrypt(&ctx, in); // <--- ESTA ES LA FUNCIÓN CLAVE        
        // fin = neorv32_cpu_csr_read(CSR_MCYCLE); // Lectura ciclos después        
  fin = neorv32_cpu_get_cycle();
        ciclos = fin - ini; // Cálculo ciclos        
        neorv32_uart0_printf("El numero de ciclos de reloj ha sido: %u\n", ciclos);
     /*-- Fin Descifrado AES Tiny AES --*/

  	return 0;

  return 0;
}
