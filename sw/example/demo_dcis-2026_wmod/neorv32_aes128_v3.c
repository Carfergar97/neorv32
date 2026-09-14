/*******************************************************************************
 * Archivo:     neorv32_aes128_v3.c
 * Autor:       Juan Manuel Delgado Romero
 * Fecha:       Febrero 2026
 *
 * Institución: Universidad de Sevilla - Escuela Politécnica Superior
 * Titulación:  Grado en Ingeniería Electrónica Industrial
 * Proyecto:    Trabajo Fin de Grado (TFG)
 * Licencia:    MIT (Ver archivo LICENSE)
 *
 * Descripción:
 * Librería para el uso del algoritmo AES-128 acelerado con el uso de las exten-
 * siones Zkne y Zknd de RISC-V (versión 3). Se optimizan las funciones Cipher e
 * InvCipher con bloques de ensamblador en línea con las instrucciones: 
 * aes32esmi, aes32esi, aes32dsmi, aes32dsi y la instrucción modificada
 * AES32DSMI_MOD.
 ******************************************************************************/


#include <stdio.h>
#include <stdint.h>
#include <neorv32.h>

//#define BAUD_RATE	19200


/*Definiciones de las constantes para el AES-128*/
enum {
     Nk = 4,    //Número de palabras copiadas de la clave original en la clave expandida para AES-128
     Nb = 4,    //Número de columnas de 32 bits de cada estado, siempre 4 en el estándar NIST
     Nr = 10    //Número de rondas a ejecutar en el cifrado, 10 para AES-128
};
/*Fin declaración*/

/*Declaración de la SBox para el estándar AES*/
static const uint8_t sbox[16][16] = {
    {0x63,0x7C,0x77,0x7B,0xF2,0x6B,0x6F,0xC5,0x30,0x01,0x67,0x2B,0xFE,0xD7,0xAB,0x76},
    {0xCA,0x82,0xC9,0x7D,0xFA,0x59,0x47,0xF0,0xAD,0xD4,0xA2,0xAF,0x9C,0xA4,0x72,0xC0},
    {0xB7,0xFD,0x93,0x26,0x36,0x3F,0xF7,0xCC,0x34,0xA5,0xE5,0xF1,0x71,0xD8,0x31,0x15},
    {0x04,0xC7,0x23,0xC3,0x18,0x96,0x05,0x9A,0x07,0x12,0x80,0xE2,0xEB,0x27,0xB2,0x75},
    {0x09,0x83,0x2C,0x1A,0x1B,0x6E,0x5A,0xA0,0x52,0x3B,0xD6,0xB3,0x29,0xE3,0x2F,0x84},
    {0x53,0xD1,0x00,0xED,0x20,0xFC,0xB1,0x5B,0x6A,0xCB,0xBE,0x39,0x4A,0x4C,0x58,0xCF},
    {0xD0,0xEF,0xAA,0xFB,0x43,0x4D,0x33,0x85,0x45,0xF9,0x02,0x7F,0x50,0x3C,0x9F,0xA8},
    {0x51,0xA3,0x40,0x8F,0x92,0x9D,0x38,0xF5,0xBC,0xB6,0xDA,0x21,0x10,0xFF,0xF3,0xD2},
    {0xCD,0x0C,0x13,0xEC,0x5F,0x97,0x44,0x17,0xC4,0xA7,0x7E,0x3D,0x64,0x5D,0x19,0x73},
    {0x60,0x81,0x4F,0xDC,0x22,0x2A,0x90,0x88,0x46,0xEE,0xB8,0x14,0xDE,0x5E,0x0B,0xDB},
    {0xE0,0x32,0x3A,0x0A,0x49,0x06,0x24,0x5C,0xC2,0xD3,0xAC,0x62,0x91,0x95,0xE4,0x79},
    {0xE7,0xC8,0x37,0x6D,0x8D,0xD5,0x4E,0xA9,0x6C,0x56,0xF4,0xEA,0x65,0x7A,0xAE,0x08},
    {0xBA,0x78,0x25,0x2E,0x1C,0xA6,0xB4,0xC6,0xE8,0xDD,0x74,0x1F,0x4B,0xBD,0x8B,0x8A},
    {0x70,0x3E,0xB5,0x66,0x48,0x03,0xF6,0x0E,0x61,0x35,0x57,0xB9,0x86,0xC1,0x1D,0x9E},
    {0xE1,0xF8,0x98,0x11,0x69,0xD9,0x8E,0x94,0x9B,0x1E,0x87,0xE9,0xCE,0x55,0x28,0xDF},
    {0x8C,0xA1,0x89,0x0D,0xBF,0xE6,0x42,0x68,0x41,0x99,0x2D,0x0F,0xB0,0x54,0xBB,0x16}
};
/*Fin declaración*/

/*Definicón del vector Rcon*/
  const uint32_t Rcon[Nr+1] = {
    0x00000000,
    0x01000000,
    0x02000000,
    0x04000000,
    0x08000000,
    0x10000000,
    0x20000000,
    0x40000000,
    0x80000000,
    0x1B000000,
    0x36000000
};
/*Fin declaración*/

/*
 * uint32_t RotWordV3(uint32_t word)
 * ---------------------------------------------------------------
 * Recibe una palabra de 32 bits de entrada y devuelve la palabra
 * tras realizar una rotación a la izquierda.
 * [a0 a1 a2 a3] ---> [a1 a2 a3 a0]
 * ---------------------------------------------------------------
 * Entradas:
 * - word: palabra de 32 bits a tratar.
 * ---------------------------------------------------------------
 * Salidas:
 * Se devuelve la palabra rotada byte a byte a la izquierda.
 */
  uint32_t RotWordV3(uint32_t word){
    uint32_t out;
    out = (word << 8) | (word >> 24);
    return out;
  } 
/* Fin RotWordV3*/

/*
 * uint32_t SubWordV3(uint32_t word)
 * -----------------------------------------------------------------
 * Recibe 4 bytes a los cuales le aplica la Sbox y devuelve los 4 
 * bytes tras dicha operación.
 * Para ello se usará el nibble alto del byte a tratar como índice
 * para las filas de la Sbox y el nibble bajo para las columnas.
 * ---------------------------------------------------------------
 *
 */
  uint32_t SubWordV3(uint32_t word){
     
   uint32_t temp = 0; // variable temporal
   int fil,col; // ïndices filas y columnas
   for(int i = 3; i >= 0; i--){
     uint8_t byte = (word >> 8*i) & 0xFF; // Byte 
     fil = (byte >> 4) & 0x0F;  // Nibble alto
     col = byte & 0x0F;         // Nibble bajo
     temp |= ((uint32_t)sbox[fil][col]) << (8*i); // Hacemos la sustitución de los bytes usando Sbox
   }
   return temp;
  }
/*
 * void KeyExpansionV3 (uint8_t key[4*Nk], uint32_t w[Nb*(Nr+1)])
 * ----------------------------------------------------------------
 * Recibe la clave de cifrado AES, de tamaño 16 bytes para AES-128, 
 * rellena el vector w con las subclaves generadas a partir de la 
 * clave original, key. 
 *
 * Las Nk palabras de 32 bits de la clave se copian en las Nk primeras
 * posiciones del vector w. El resto de subclaves de ronda se calculan
 * aplicando una serie de transformaciones, comenzando para cada ronda
 * con la subclave generada para la ronda anterior. 
 * ------------------------------------------------------------------
 * Entradas:
 *
 * -key: clave original de tamaño variable según AES-128, AES-192 o 
 *       AES-256.
 * -w  : vector que contendrá las subclaves para cada ronda, de nuevo
 *       de tamaño variable según el tipo de AES. Se rellenarán las 
 *       palabras en formato little endiann.
 * --------------------------------------------------------------------
 * Salidas:
 * 
 *  Ninguna, la función irá rellenando el vector w.
 * ---------------------------------------------------------------------
 */
void KeyExpansionV3(uint8_t key[4*Nk], uint32_t w[Nb*(Nr+1)]){

	uint32_t temp; // Variable temporal 
  	int i = 0;     // Variable contador
 	/*Comenzamos copiando la clave original en las 4 primeras subclaves de ronda*/
  	while(i < Nk){
    		w[i] = ( (uint32_t)key[4*i]   <<  24) |
               	       ( (uint32_t)key[4*i+1] <<  16) |
                       ( (uint32_t)key[4*i+2] <<   8) |
                       ( (uint32_t)key[4*i+3]);
    		i++;
  	}
 	/*Comenzamos con el resto de subclaves para las rondas restantes*/
  	i = Nk;

  	while( i < (Nb*(Nr+1))){ // Seguir mientras no se hayan generado todas la subclaves de ronda
    		temp = w[i-1]; // La palabra al comienzo del cáculo de la sbclave es la anterior
    		if((i % Nk) == 0){ // Si estamos al inicio de ronda...
      			temp = SubWordV3(RotWordV3(temp)) ^ Rcon[i/Nk]; // .. aplicamos todas las operaciones
    		}else if((Nk > 6) && ((i%Nk) == 4)){ // si no si estamos en AES-256 y estamos en mitad de ronda..
      			temp = SubWordV3(temp); // Hacemos una transformación distinta
    		}
    		w[i] = w[i - Nk] ^ temp; // Por último, preparamos la siguiente ronda
    		i++;
   	}
	/*Round Keys a formato little endiann*/
        for(int i = 0; i < (Nb*(Nr+1)); i++){
                w[i] =  (w[i]<<24)            |
                       ((w[i]<<8)&0x00FF0000) |
                       ((w[i]>>8)&0x0000FF00) |
                        (w[i]>>24);
        }
}
/*
 * Fin KeyExpansionV3
 */

/*
 * void CipherV3(uint8_t in[4*Nb], uint8_t out[4*Nb], uint32_t w[Nb*(Nr+1)])
 * ---------------------------------------------------------------------
 * Recibe un vector de datos a cifrar de 16 bytes (AES-128) y realiza
 * el cifrado completo usando las subclaves generadas con KeyExpansion.
 *
 * La función realiza:
 *  - Ronda inicial: AddRoundKey con las primeras Nb palabras de w.
 *  - Rondas intermedias (1 a Nr-1):
 *      * Se usan las instrucciones AES32ESMI del NEORV32 para acelerar 
 *        el cifrado, que operan byte a byte.
 *      * Para cada palabra de 32 bits del bloque (Nb=4 palabras), se aplica
 *        un bucle que llama 4 veces a AES32ESMI, una por cada byte de la palabra.
 *      * Cada palabra se combina con la subclave correspondiente de w para esa ronda.
 *  - Ronda final:
 *      * Se utiliza AES32ESI, que aplica SubBytes, ShiftRows y AddRoundKey
 *        en una operación simplificada para la última ronda.
 * ---------------------------------------------------------------------
 * Entradas:
 * - in : vector de 16 bytes con el mensaje a cifrar.
 * - w  : vector de subclaves de 32 bits generadas por KeyExpansion.
 * ---------------------------------------------------------------------
 * Salidas:
 * - out : vector de 16 bytes con el mensaje cifrado al final de todas
 *         las rondas.
 * ---------------------------------------------------------------------
 */
void CipherV3(uint8_t in[4*Nb], uint8_t out[4*Nb], uint32_t w[Nb*(Nr+1)]){

	uint32_t state[Nb] = {0};  // Variable estado, almacena los datos a cifrar en Nb palabras de 32 bits
	/*Copia de datos de entrada(in) en variable state teniendo en cuenta el endianness*/
	for(int c = 0; c < 4; c++){
		for(int r = 0; r < 4; r++){
        		state[c] |= ((uint32_t)in[r + 4*c]) << (r*8);
     		}
   	}
	/*Ronda Inicial AddRoundKey*/
	for(int c = 0; c < 4; c++){
     		state[c] = state[c] ^ w[c]; // xor entre stado inicial y 4 primeras subclaves 
   	}	/*Fin ronda inicial*/

	/*Rondas intermedias,aceleradas con la instrucción aes32esmi*/
   	for(int round = 1; round < Nr; round++){
   		uint32_t U0 = w[round*4], U1 = w[round*4+1], U2 = w[round*4+2], U3 = w[round*4+3];
    		uint32_t T0 = state[0], T1 = state[1], T2 = state[2], T3 = state[3];

    		asm volatile(
		/*Columna 0*/
        	"aes32esmi %[U0], %[U0], %[T0], 0\n\t"
        	"aes32esmi %[U0], %[U0], %[T1], 1\n\t"
        	"aes32esmi %[U0], %[U0], %[T2], 2\n\t"
        	"aes32esmi %[U0], %[U0], %[T3], 3\n\t"
		/*Columna 1*/
        	"aes32esmi %[U1], %[U1], %[T1], 0\n\t"
        	"aes32esmi %[U1], %[U1], %[T2], 1\n\t"
        	"aes32esmi %[U1], %[U1], %[T3], 2\n\t"
        	"aes32esmi %[U1], %[U1], %[T0], 3\n\t"
		/*Columna 2*/
        	"aes32esmi %[U2], %[U2], %[T2], 0\n\t"
        	"aes32esmi %[U2], %[U2], %[T3], 1\n\t"
        	"aes32esmi %[U2], %[U2], %[T0], 2\n\t"
        	"aes32esmi %[U2], %[U2], %[T1], 3\n\t"
		/*CColumna 3*/
        	"aes32esmi %[U3], %[U3], %[T3], 0\n\t"
        	"aes32esmi %[U3], %[U3], %[T0], 1\n\t"
        	"aes32esmi %[U3], %[U3], %[T1], 2\n\t"
        	"aes32esmi %[U3], %[U3], %[T2], 3\n\t"
        	: /*Asignación registros de salida*/
          	[U0] "+r" (U0), [U1] "+r" (U1), [U2] "+r" (U2), [U3] "+r" (U3)
        	: /*Asignación registros de entrada*/
          	[T0] "r" (T0), [T1] "r" (T1), [T2] "r" (T2), [T3] "r" (T3)
    		);
		/*Actualizamos matriz de estado*/
    		state[0] = U0;
    		state[1] = U1;
    		state[2] = U2;
    		state[3] = U3;
   	} 
	/*Ronda final acelerada usando aes32esi*/
                uint32_t U0 = w[Nr*4], U1 = w[Nr*4+1], U2 = w[Nr*4+2], U3 = w[Nr*4+3];
                uint32_t T0 = state[0], T1 = state[1], T2 = state[2], T3 = state[3];

                asm volatile(
		/*Columna 0*/
                "aes32esi %[U0], %[U0], %[T0], 0\n\t"
                "aes32esi %[U0], %[U0], %[T1], 1\n\t"
                "aes32esi %[U0], %[U0], %[T2], 2\n\t"
                "aes32esi %[U0], %[U0], %[T3], 3\n\t"
		/*Columna 1*/
                "aes32esi %[U1], %[U1], %[T1], 0\n\t"
                "aes32esi %[U1], %[U1], %[T2], 1\n\t"
                "aes32esi %[U1], %[U1], %[T3], 2\n\t"
                "aes32esi %[U1], %[U1], %[T0], 3\n\t"
		/*Columna 2*/
                "aes32esi %[U2], %[U2], %[T2], 0\n\t"
                "aes32esi %[U2], %[U2], %[T3], 1\n\t"
                "aes32esi %[U2], %[U2], %[T0], 2\n\t"
                "aes32esi %[U2], %[U2], %[T1], 3\n\t"
		/*Columna 3*/
                "aes32esi %[U3], %[U3], %[T3], 0\n\t"
                "aes32esi %[U3], %[U3], %[T0], 1\n\t"
                "aes32esi %[U3], %[U3], %[T1], 2\n\t"
                "aes32esi %[U3], %[U3], %[T2], 3\n\t"
                : /*Asignación registros de salida*/
                [U0] "+r" (U0), [U1] "+r" (U1), [U2] "+r" (U2), [U3] "+r" (U3)
                : /*Asignación registros de entrada */
                [T0] "r" (T0), [T1] "r" (T1), [T2] "r" (T2), [T3] "r" (T3)
                );

             	/*Actualizamos estado*/
                state[0] = U0;
                state[1] = U1;
                state[2] = U2;
                state[3] = U3;

	/*Copiamos la matriz estado en el vector de salida out*/
	for(int c = 0; c < 4; c++){
    		for(int r = 0; r < 4; r++){
      			out[r+4*c] = (uint8_t)((state[c] >> (r*8)) & 0xFF);
    		} 
  	}
}

// Definición macro para AES32DSMI modificada
// rs1: Registro fuente 1 (acumulador)
// rs2: Registro fuente 2 (subclave de ronda)
// bs:  Byte Select (0, 1, 2 o 3)

#define AES32DSMI_MOD(rd, rs1, rs2, bs) \
    asm volatile ( \
        ".insn r 0x33, 0x1, %3, %0, %1, %2" \
        : "=r"(rd)              /* Salida: %0 (registro destino) */ \
        : "r"(rs1), "r"(rs2),   /* Entradas: %1 y %2 */ \
          "i"(0x17 | (bs << 5)) /* Func7: %3 (Base 0x15 + bs) */ \
    );

void InvCipherV3(uint8_t in[4*Nb],uint8_t out[4*Nb],uint32_t w[Nb*(Nr+1)]){
	/*Declaración de matriz estado*/
	uint32_t state[4] = {0};
        /*Copia de datos de entrada(in) en variable state teniendo en cuenta el endianness*/
        for(int c = 0; c < 4; c++){
                for(int r = 0; r < 4; r++){
                        state[c] |= ((uint32_t)in[r + 4*c]) << (r*8);
//			neorv32_uart0_printf("state[%d] = 0x%x\n",c,state[c]);
                }
        }
	/*Preparar el keyschedule para el descifrado usando InvMixColumns*/
	for(int i = Nb; i < (Nr*Nb); i++ ){
 		uint32_t T0 = w[i];
		uint32_t T1 = 0;
            AES32DSMI_MOD(T1, 0, T0, 0);
 	        AES32DSMI_MOD(T1, T1, T0, 1);
	        AES32DSMI_MOD(T1, T1, T0, 2);
	        AES32DSMI_MOD(T1, T1, T0, 3);
		w[i] = T1;
	}
        /*Ronda Inicial AddRoundKey*/
        for(int c = 0; c < 4; c++){
                state[c] ^= w[Nr*Nb+c]; // xor entre stado inicial y 4 últimas subclaves 
//                neorv32_uart0_printf("state[%d] XOR 0x%x = 0x%x\n",c,w[Nr*Nb+c],state[c]);
        }       /*Fin ronda inicial*/

        /*Rondas intermedias,aceleradas con la instrucción aes32dsmi*/
        for(int round = (Nr-1); round > 0 ; round--){
                uint32_t U0 = w[round*4], U1 = w[round*4+1], U2 = w[round*4+2], U3 = w[round*4+3];
                uint32_t T0 = state[0], T1 = state[1], T2 = state[2], T3 = state[3];

                asm volatile(
                /*Columna 0*/
                "aes32dsmi %[U0], %[U0], %[T0], 0\n\t"
                "aes32dsmi %[U0], %[U0], %[T3], 1\n\t"
                "aes32dsmi %[U0], %[U0], %[T2], 2\n\t"
                "aes32dsmi %[U0], %[U0], %[T1], 3\n\t"
                /*Columna 1*/
                "aes32dsmi %[U1], %[U1], %[T1], 0\n\t"
                "aes32dsmi %[U1], %[U1], %[T0], 1\n\t"
                "aes32dsmi %[U1], %[U1], %[T3], 2\n\t"
                "aes32dsmi %[U1], %[U1], %[T2], 3\n\t"
                /*Columna 2*/
                "aes32dsmi %[U2], %[U2], %[T2], 0\n\t"
                "aes32dsmi %[U2], %[U2], %[T1], 1\n\t"
                "aes32dsmi %[U2], %[U2], %[T0], 2\n\t"
                "aes32dsmi %[U2], %[U2], %[T3], 3\n\t"
                /*CColumna 3*/
                "aes32dsmi %[U3], %[U3], %[T3], 0\n\t"
                "aes32dsmi %[U3], %[U3], %[T2], 1\n\t"
                "aes32dsmi %[U3], %[U3], %[T1], 2\n\t"
                "aes32dsmi %[U3], %[U3], %[T0], 3\n\t"
                : /*Asignación registros de salida*/
                [U0] "+r" (U0), [U1] "+r" (U1), [U2] "+r" (U2), [U3] "+r" (U3)
                : /*Asignación registros de entrada*/
                [T0] "r" (T0), [T1] "r" (T1), [T2] "r" (T2), [T3] "r" (T3)
                );
                /*Actualizamos matriz de estado*/
                state[0] = U0;
                state[1] = U1;
                state[2] = U2;
                state[3] = U3;

        } 
        /*Ronda final acelerada usando aes32dsi*/
                uint32_t U0 = w[0], U1 = w[1], U2 = w[2], U3 = w[3];
                uint32_t T0 = state[0], T1 = state[1], T2 = state[2], T3 = state[3];

                asm volatile(
                /*Columna 0*/
                "aes32dsi %[U0], %[U0], %[T0], 0\n\t"
                "aes32dsi %[U0], %[U0], %[T3], 1\n\t"
                "aes32dsi %[U0], %[U0], %[T2], 2\n\t"
                "aes32dsi %[U0], %[U0], %[T1], 3\n\t"
                /*Columna 1*/
                "aes32dsi %[U1], %[U1], %[T1], 0\n\t"
                "aes32dsi %[U1], %[U1], %[T0], 1\n\t"
                "aes32dsi %[U1], %[U1], %[T3], 2\n\t"
                "aes32dsi %[U1], %[U1], %[T2], 3\n\t"
                /*Columna 2*/
                "aes32dsi %[U2], %[U2], %[T2], 0\n\t"
                "aes32dsi %[U2], %[U2], %[T1], 1\n\t"
                "aes32dsi %[U2], %[U2], %[T0], 2\n\t"
                "aes32dsi %[U2], %[U2], %[T3], 3\n\t"
                /*Columna 3*/
                "aes32dsi %[U3], %[U3], %[T3], 0\n\t"
                "aes32dsi %[U3], %[U3], %[T2], 1\n\t"
                "aes32dsi %[U3], %[U3], %[T1], 2\n\t"
                "aes32dsi %[U3], %[U3], %[T0], 3\n\t"
                : /*Asignación registros de salida*/
                [U0] "+r" (U0), [U1] "+r" (U1), [U2] "+r" (U2), [U3] "+r" (U3)
                : /*Asignación registros de entrada */
                [T0] "r" (T0), [T1] "r" (T1), [T2] "r" (T2), [T3] "r" (T3)
                );

                /*Actualizamos estado*/
                state[0] = U0;
                state[1] = U1;
                state[2] = U2;
                state[3] = U3;


        /*Copiamos la matriz estado en el vector de salida out*/
        for(int c = 0; c < 4; c++){
                for(int r = 0; r < 4; r++){
                        out[r+4*c] = (uint8_t)((state[c] >> (r*8)) & 0xFF);
                } 
        }
} 
