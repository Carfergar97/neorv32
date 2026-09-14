/*******************************************************************************
 * Archivo:     neorv32_aes128_v3.h
 * Autor:       Juan Manuel Delgado Romero
 * Fecha:       Febrero 2026
 *
 * Institución: Universidad de Sevilla - Escuela Politécnica Superior
 * Titulación:  Grado en Ingeniería Electrónica Industrial
 * Proyecto:    Trabajo Fin de Grado (TFG)
 * Licencia:    MIT (Ver archivo LICENSE)
 *
 * Descripción: 
 * Archivo de cabecera de la librería para uso del algoritmo AES-128 optimizado
 * con las extensiones Zkne y Zknd de RISC-V (versión 3). Se incluyen constantes
 * y prototipos de las funciones de control.
 ******************************************************************************/


#ifndef NEORV32_AES128_V3_H

#define NEORV32_AES128_V3_H

#include <stdint.h>

/*Definiciones de las constantes para el AES-128*/
#define	Nk	4	//Número de palabras copiadas de la clave original en la clave expandida para AES-128
#define	Nb	4       //Número de columnas de 32 bits de cada estado, siempre 4 en el estándar NIST
#define Nr	10      //Número de rondas a ejecutar en el cifrado, 10 para AES-128
/*Fin declaración*/

/*Prototipos de las funciones*/
uint32_t RotWordV3(uint32_t word);

uint32_t SubWordV3(uint32_t word);

void KeyExpansionV3(uint8_t key[4*Nk], uint32_t w[Nb*(Nr+1)]);

void CipherV3(uint8_t in[4*Nb], uint8_t out[4*Nb], uint32_t w[Nb*(Nr+1)]);

void InvCipherV3(uint8_t in[4*Nb],uint8_t out[4*Nb],uint32_t w[Nb*(Nr+1)]);

#endif
