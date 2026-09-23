-- ================================================================================ --
-- NEORV32 SoC - Custom Functions Subsystem (CFS)                                   --
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
use neorv32.neorv32_package.all;

entity neorv32_cfs is
  port (
    -- global control --
    clk_i     : in  std_ulogic; -- global clock line
    rstn_i    : in  std_ulogic; -- global reset line, low-active, async
    -- CPU access --
    bus_req_i : in  bus_req_t; -- bus request
    bus_rsp_o : out bus_rsp_t; -- bus response
    -- CPU interrupt --
    irq_o     : out std_ulogic; -- interrupt request
    -- external IO --
    cfs_in_i  : in  std_ulogic_vector(255 downto 0); -- custom inputs conduit
    cfs_out_o : out std_ulogic_vector(255 downto 0) -- custom outputs conduit
  );
end neorv32_cfs;

architecture neorv32_cfs_rtl of neorv32_cfs is

  component keccak_sloth is
    port (
      clk   : in  std_ulogic;
      rst   : in  std_ulogic;
      sel   : in  std_ulogic;
      irq   : out std_ulogic;
      wen   : in  std_ulogic_vector(3 downto 0);
      addr  : in  std_ulogic_vector(6 downto 0);
      wdata : in  std_ulogic_vector(31 downto 0);
      rdata : out std_ulogic_vector(31 downto 0)
    );
  end component;

  signal keccak_sel    : std_ulogic;
  signal keccak_irq    : std_ulogic;
  signal keccak_wen    : std_ulogic_vector(3 downto 0);
  signal keccak_addr   : std_ulogic_vector(6 downto 0);
  signal keccak_wdata  : std_ulogic_vector(31 downto 0);
  signal keccak_rdata  : std_ulogic_vector(31 downto 0);
  signal keccak_read_q : std_ulogic;

begin

  cfs_out_o <= (others => '0'); -- unused
  irq_o     <= keccak_irq;      -- optional; polling also works

  -- Do not alias CFS offsets >= 512 bytes onto Keccak registers.
  keccak_sel <= bus_req_i.stb;
  keccak_addr  <= bus_req_i.addr(8 downto 2); -- word offset, 0 ... 127
  keccak_wdata <= bus_req_i.data;
  keccak_wen   <= bus_req_i.ben when bus_req_i.rw = '1' else (others => '0');

  keccak_sloth_inst: keccak_sloth
  port map (
    clk   => clk_i,
    rst   => not rstn_i, -- accelerator reset is active-high
    sel   => keccak_sel,
    irq   => keccak_irq,
    wen   => keccak_wen,
    addr  => keccak_addr,
    wdata => keccak_wdata,
    rdata => keccak_rdata
  );

  -- keccak_sloth registers read data at its clock edge. read_q reproduces
  -- sloth_top's registered read-data source selection.
  bus_rsp_o.data <= keccak_rdata when keccak_read_q = '1' else (others => '0');

  bus_access: process(rstn_i, clk_i)
  begin
    if (rstn_i = '0') then
      bus_rsp_o.ack  <= '0';
      bus_rsp_o.err  <= '0';
      keccak_read_q  <= '0';
    elsif rising_edge(clk_i) then
      bus_rsp_o.ack <= bus_req_i.stb; -- standard CFS one-cycle response
      bus_rsp_o.err <= '0';
      keccak_read_q <= keccak_sel and (not bus_req_i.rw) and bus_req_i.stb;
    end if;
  end process;

end neorv32_cfs_rtl;
