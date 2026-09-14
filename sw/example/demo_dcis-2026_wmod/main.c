/*******************************************************************************
 * Archivo:     main.c
 * Autor:       Juan Manuel Delgado Romero
 * Fecha:       Febrero 2026
 *
 * Institución: Universidad de Sevilla - Escuela Politécnica Superior
 * Titulación:  Grado en Ingeniería Electrónica Industrial
 * Proyecto:    Trabajo Fin de Grado (TFG)
 * Licencia:    MIT (Ver archivo LICENSE)
 *
 * Descripción: 
 * Código de aplicación para la validación de la versión 3 del algoritmo AES-128
 * con las extensiones Zkne y Zknd de RISC-V. Se lleva a cabo la medición de ci-
 * clos de reloj para el cifrado de un bloque de 128 bits.
 ******************************************************************************/

#include <neorv32.h>
#include <stdio.h>
#include <stdint.h>
#include "aes.h" // librería Tiny-AES-C
#include "neorv32_aes128_v3.h" // código fuente AES-128 con Zknd y Zkne

#define BAUD_RATE 19200


int main(){

  	neorv32_rte_setup();
  	neorv32_uart0_setup(BAUD_RATE,0);
	neorv32_uart0_printf("\n\nInicio Prueba de Medida de Ciclos de Reloj\n\n");

    /*-- Definición PlainText y Key Ejemplo NIST --*/
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
     /*-- Fin Definición PlainText y Key --*/
 	uint32_t w[44]; // Variable KeySchedule
	uint8_t out[4*Nb]; // Variable Salida

     /*-- Key Schedule --*/
        KeyExpansionV3(key,w); // Cálculo KeySchedule
     /*-- Fin Key Schedule --*/
	
     /*-- Cifrado AES Version 3 --*/
	neorv32_uart0_printf("\n\n-- Cifrado AES-128 con Subextensiones Zknd y Zkne (Version 3)--\n");
	/*Medida Ciclos de Reloj para Cifrado con Subextensiones Zknd y Zknd*/
        uint32_t ini = neorv32_cpu_csr_read(CSR_MCYCLE); // Lectura ciclos de reloj antes del cifrado
	CipherV3(in,out,w); // Cifrado
   	uint32_t fin = neorv32_cpu_csr_read(CSR_MCYCLE); // Lectura ciclos de reloj después del cifrado
   	uint32_t ciclos = fin - ini; // Cálculo ciclos de reloj cifrado
        neorv32_uart0_printf("El numero de ciclos de reloj ha sido: %u\n",ciclos); // Impresión ciclos de reloj
     /*-- Fin Cifrado AES Version 3 --*/

     /*-- Descifrado AES Version 3 --*/
        neorv32_uart0_printf("\n\n-- Descifrado AES-128 con Subextensiones Zknd y Zkne (Version 3)--\n");
        /*Medida Ciclos de Reloj para Descifrado con Subextensiones Zknd y Zknd*/
        ini = neorv32_cpu_csr_read(CSR_MCYCLE); // Lectura ciclos de reloj antes del cifrado
        InvCipherV3(out,out,w); // Cifrado
        fin = neorv32_cpu_csr_read(CSR_MCYCLE); // Lectura ciclos de reloj después del cifrado
        ciclos = fin - ini; // Cálculo ciclos de reloj cifrado
        neorv32_uart0_printf("El numero de ciclos de reloj ha sido: %u\n",ciclos); // Impresión ciclos de reloj
        /*Fin Medida Ciclos de Reloj para Descifrado con Subextensiones Zknd y Zknd*/
     /*-- Fin Descifrado AES Version 3 --*/

     /*-- Cifrado AES Tiny AES --*/
        neorv32_uart0_printf("\n\n-- Cifrado AES-128 con Tiny-AES-128 --\n");
	/*Medida Ciclos de reloj para Cifrado con Librería Tiny-AES-C*/
	struct AES_ctx ctx; // Definición estructura para keyschedule
        AES_init_ctx(&ctx,key); // Cálculo keyschedule
        ini = neorv32_cpu_csr_read(CSR_MCYCLE); // Lectura ciclos de reloj antes de cifrado
	AES_ECB_encrypt(&ctx,in); // Cifrado
        fin = neorv32_cpu_csr_read(CSR_MCYCLE); // Lectura ciclos de reloj después de cifrado
        ciclos = fin - ini; // Cálculo cilos de reloj cifrado
        neorv32_uart0_printf("El numero de ciclos de reloj ha sido: %u\n",ciclos); // Impresión ciclos de reloj
        /*Fin Medida Ciclos de reloj para Cifrado con Librería Tiny-AES-C*/
     /*-- Fin Cifrado AES Tiny AES --*/

     /*-- Descifrado AES Tiny AES --*/
	neorv32_uart0_printf("\n-- Descifrado AES-128 con Tiny-AES-128 --\n");
        ini = neorv32_cpu_csr_read(CSR_MCYCLE); // Lectura ciclos antes
        AES_ECB_decrypt(&ctx, in); // <--- ESTA ES LA FUNCIÓN CLAVE        
        fin = neorv32_cpu_csr_read(CSR_MCYCLE); // Lectura ciclos después        
        ciclos = fin - ini; // Cálculo ciclos       
        neorv32_uart0_printf("El numero de ciclos de reloj ha sido: %u\n", ciclos);
     /*-- Fin Descifrado AES Tiny AES --*/

  	return 0;
}
