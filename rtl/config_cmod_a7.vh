//  config_cmod_a7.vh
//  Markku-Juhani O. Saarinen <mjos@iki.fi>.  See LICENSE.
//  Carlos Fernández-García <carlos@imse-cnm.csic.es>.

//  === High-level RTL and Firmware configuration

`ifndef CONFIG_VH
`define CONFIG_VH

`timescale  1 ns / 1 ps
`default_nettype none

`define     SLOTH                           //  standalone configuration
`define     SLOTH_CLK   100000000           //  input clock frequency
`define     RAM_XADR    17                  //  RAM (1 << RAM_XADR) bytes

//  === cpu core options
//`define   CORE_DEBUG
//`define   CORE_CUSTOM0                    //  custom instructions
`define     CORE_COMPRESSED                 //  "c" - compressed ISA
//`define   CORE_KRYPTO                     //  "k" - cryptography
`define     CORE_MULDIV                     //  "m" - multiplication
//`define   CORE_USEDSP                     //  use fpga dsp for "m"
//`define   CORE_E16REG                     //  "e" - small register file
//`define   CORE_FPU                        //  (affects only "c" atm)
//`define   CORE_TRAP_UNALIGNED             //  trap on unaligned load/store

//  === top options
`define     SLOTH_KECCAK                    //  FIPS 202 / SHA3 & SHAKE


`endif
