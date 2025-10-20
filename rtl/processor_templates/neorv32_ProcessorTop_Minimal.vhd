-- ================================================================================ --
-- NEORV32 Templates - Minimal setup without a bootloader                           --
-- -------------------------------------------------------------------------------- --
-- The NEORV32 RISC-V Processor - https://github.com/stnolting/neorv32              --
-- Copyright (c) NEORV32 contributors.                                              --
-- Copyright (c) 2020 - 2025 Stephan Nolting. All rights reserved.                  --
-- Licensed under the BSD-3-Clause license, see LICENSE for details.                --
-- SPDX-License-Identifier: BSD-3-Clause                                            --
-- ================================================================================ --

library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;

library neorv32;

entity neorv32_ProcessorTop_Minimal is
  generic (
    -- Clocking --
    CLOCK_FREQUENCY : natural := 125000000;       -- clock frequency of clk_i in Hz
    -- Internal Instruction memory --
    IMEM_EN         : boolean := true;    -- implement processor-internal instruction memory
    IMEM_SIZE       : natural := 64*1024;  -- size of processor-internal instruction memory in bytes
    -- Internal Data memory --
    DMEM_EN         : boolean := true;    -- implement processor-internal data memory
    DMEM_SIZE       : natural := 16*1024; -- size of processor-internal data memory in bytes
    -- Processor peripherals --
    IO_UART0_EN     : boolean := true;
    RISCV_ISA_M     : boolean := false;
    RISCV_ISA_C     : boolean := false;
    CPU_CONSTT_BR_EN      : boolean                        := false;       -- implement constant-time branches
    CPU_FAST_MUL_EN       : boolean                        := false;       -- use DSPs for M extension's multiplier
    CPU_FAST_SHIFT_EN     : boolean                        := false       -- use barrel shifter for shift operations
  );
  port (
    -- Global control --
    clk_i  : in  std_logic;
    rstn_i : in  std_logic;
    -- UART0 --
    uart0_rxd_i : in std_logic;
    uart0_txd_o : out std_logic
  );
end entity;

architecture neorv32_ProcessorTop_Minimal_rtl of neorv32_ProcessorTop_Minimal is

  signal w_rst: std_logic;
begin

  -- The core of the problem ----------------------------------------------------------------
  -- -------------------------------------------------------------------------------------------
  neorv32_inst: entity neorv32.neorv32_top
  generic map (
    -- Clocking --
    CLOCK_FREQUENCY  => CLOCK_FREQUENCY, -- clock frequency of clk_i in Hz
    -- Boot Configuration --
    BOOT_MODE_SELECT => 2,               -- boot from pre-initialized internal IMEM
    -- RISC-V CPU Extensions --
    RISCV_ISA_Zicntr => true,            -- implement base counters?
    -- Internal Instruction memory --
    IMEM_EN          => IMEM_EN,         -- implement processor-internal instruction memory
    IMEM_SIZE        => IMEM_SIZE,       -- size of processor-internal instruction memory in bytes
    -- Internal Data memory --
    DMEM_EN          => DMEM_EN,         -- implement processor-internal data memory
    DMEM_SIZE        => DMEM_SIZE,       -- size of processor-internal data memory in bytes
    -- Processor peripherals --
    IO_CLINT_EN      => true,            -- implement core local interruptor (CLINT)?
    IO_UART0_EN => IO_UART0_EN,
    RISCV_ISA_M => RISCV_ISA_M,
    RISCV_ISA_C => RISCV_ISA_C,
    CPU_FAST_MUL_EN => CPU_FAST_MUL_EN,
    CPU_CONSTT_BR_EN => CPU_CONSTT_BR_EN,
    CPU_FAST_SHIFT_EN => CPU_FAST_SHIFT_EN
  )
  port map(
    -- Global control --
    clk_i  => clk_i,    -- global clock, rising edge
    rstn_i => w_rst,   -- global reset, low-active, async
    -- UART0 --
    uart0_rxd_i => uart0_rxd_i,
    uart0_txd_o => uart0_txd_o 
  );

  -- Reset Inversion Logic --
  w_rst <= not rstn_i;

end architecture;
