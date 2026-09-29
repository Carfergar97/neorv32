-- ================================================================================ --
-- Keccak accelerator for SLOTH                                                      --
-- -------------------------------------------------------------------------------- --
-- Simple 32-bit interface to the Keccak accelerator.                               --
-- Based on the original implementation by Markku-Juhani O. Saarinen.               --
-- ================================================================================ --

library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;

entity keccak_sloth is
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
end keccak_sloth;

architecture keccak_sloth_rtl of keccak_sloth is

  -- data-register block ------------------------------------------------------------
  constant KECC_MEMA : natural := 0;   -- 1600-bit Keccak state
  constant KECC_ADRS : natural := 50;  -- 32-byte ADRS structure
  constant KECC_SEED : natural := 58;  -- PK.seed
  constant KECC_SKSD : natural := 66;  -- SK.seed
  constant KECC_MTOP : natural := 74;  -- end of data-register block

  -- control-register block ---------------------------------------------------------
  constant KECC_CTRL : natural := 120;
  constant KECC_TRIG : natural := 120;
  constant KECC_STOP : natural := 121;
  constant KECC_SECN : natural := 122;
  constant KECC_CHNS : natural := 123;

  subtype state_t is std_ulogic_vector(1599 downto 0);
  subtype word_t  is std_ulogic_vector(31 downto 0);
  type mem_t is array (0 to KECC_MTOP - 1) of word_t;

  -- Assemble consecutive 32-bit words into a vector. Word zero is the least
  -- significant word, matching the original MEM_BLOCK_50 Verilog macro.
  function mem_block_50(memory : mem_t; index : natural) return state_t is
    variable result : state_t;
  begin
    for i in 0 to 49 loop
      result((i * 32) + 31 downto i * 32) := memory(index + i);
    end loop;
    return result;
  end function;

  -- SHAKE256 padding for F(PK.seed, ADRS, M) and PRF(PK.seed, ADRS, SK.seed).
  function padf(
    n    : std_ulogic_vector(7 downto 0);
    seed : std_ulogic_vector(255 downto 0);
    adrs : std_ulogic_vector(255 downto 0);
    m    : std_ulogic_vector(255 downto 0)
  ) return state_t is
  begin
    if n = x"10" then -- n = 16
      return std_ulogic_vector'(511 downto 0 => '0') & x"80" &
             std_ulogic_vector'(559 downto 0 => '0') & x"1F" &
             m(127 downto 0) & adrs & seed(127 downto 0);
    elsif n = x"18" then -- n = 24
      return std_ulogic_vector'(511 downto 0 => '0') & x"80" &
             std_ulogic_vector'(431 downto 0 => '0') & x"1F" &
             m(191 downto 0) & adrs & seed(191 downto 0);
    else -- n = 32
      return std_ulogic_vector'(511 downto 0 => '0') & x"80" &
             std_ulogic_vector'(303 downto 0 => '0') & x"1F" &
             m & adrs & seed;
    end if;
  end function;

  signal mem        : mem_t;
  signal msel_w     : std_ulogic;
  signal addr_index : natural range 0 to 127;
  signal stop_r     : std_ulogic_vector(7 downto 0);
  signal rndc_r     : std_ulogic_vector(7 downto 0);
  signal secn_r     : std_ulogic_vector(7 downto 0);
  signal chns_r     : std_ulogic_vector(7 downto 0);
  signal chni_r     : std_ulogic_vector(7 downto 0);
  signal just_pad_w : std_ulogic;
  signal wots_prf_w : std_ulogic;
  signal st_i_w     : state_t;
  signal st_o_w     : state_t;
  signal rc_o_w     : std_ulogic_vector(7 downto 0);
  signal adrs_w     : std_ulogic_vector(255 downto 0);
  signal seed_m     : std_ulogic_vector(255 downto 0);
  signal hash_m     : std_ulogic_vector(255 downto 0);
  signal sksd_m     : std_ulogic_vector(255 downto 0);
  signal pad_w      : state_t;

begin

  addr_index <= to_integer(unsigned(addr));
  msel_w     <= '1' when addr_index < KECC_CTRL else '0';
  just_pad_w <= chns_r(7);
  wots_prf_w <= chns_r(6);

  st_i_w <= mem_block_50(mem, KECC_MEMA);

  keccak_round_inst: entity work.keccak_round
  port map (
    s_o => st_o_w,
    r_o => rc_o_w,
    s_i => st_i_w,
    r_i => rndc_r
  );

  adrs_w <= std_ulogic_vector(unsigned(mem(KECC_ADRS + 7)) +
                               shift_left(resize(unsigned(chni_r), 32), 24)) &
            mem(KECC_ADRS + 6) & mem(KECC_ADRS + 5) &
            mem(KECC_ADRS + 4) & mem(KECC_ADRS + 3) &
            mem(KECC_ADRS + 2) & mem(KECC_ADRS + 1) &
            mem(KECC_ADRS);
  seed_m <= mem(KECC_SEED + 7) & mem(KECC_SEED + 6) &
            mem(KECC_SEED + 5) & mem(KECC_SEED + 4) &
            mem(KECC_SEED + 3) & mem(KECC_SEED + 2) &
            mem(KECC_SEED + 1) & mem(KECC_SEED);
  hash_m <= st_i_w(255 downto 0);
  sksd_m <= mem(KECC_SKSD + 7) & mem(KECC_SKSD + 6) &
            mem(KECC_SKSD + 5) & mem(KECC_SKSD + 4) &
            mem(KECC_SKSD + 3) & mem(KECC_SKSD + 2) &
            mem(KECC_SKSD + 1) & mem(KECC_SKSD);
  pad_w  <= padf(secn_r, seed_m, adrs_w, sksd_m) when wots_prf_w = '1' else
            padf(secn_r, seed_m, adrs_w, hash_m);

  process(clk)
  begin
    if rising_edge(clk) then
      irq <= '0'; -- clear interrupt

      -- Data-register access. The original address map reserves offsets 0 to 119;
      -- only offsets 0 to 73 are backed by the data-register array.
      if (sel = '1') and (msel_w = '1') then
        if addr_index < KECC_MTOP then
          rdata <= mem(addr_index);
          if wen(0) = '1' then
            mem(addr_index)(7 downto 0) <= wdata(7 downto 0);
          end if;
          if wen(1) = '1' then
            mem(addr_index)(15 downto 8) <= wdata(15 downto 8);
          end if;
          if wen(2) = '1' then
            mem(addr_index)(23 downto 16) <= wdata(23 downto 16);
          end if;
          if wen(3) = '1' then
            mem(addr_index)(31 downto 24) <= wdata(31 downto 24);
          end if;
        end if;
      else
        if sel = '1' then
          case addr_index is
            when KECC_TRIG =>
              rdata <= x"0000" & chns_r & rndc_r;
              if wen(0) = '1' then
                rndc_r <= wdata(7 downto 0);
              end if;
            when KECC_STOP =>
              rdata <= x"000000" & stop_r;
              if wen(0) = '1' then
                stop_r <= wdata(7 downto 0);
              end if;
            when KECC_SECN =>
              rdata <= x"000000" & secn_r;
              if wen(0) = '1' then
                secn_r <= wdata(7 downto 0);
              end if;
            when KECC_CHNS =>
              rdata <= x"000000" & chns_r;
              if wen(0) = '1' then
                chns_r <= wdata(7 downto 0);
                chni_r <= x"00";
              end if;
            when others =>
              null;
          end case;
        end if;

        -- A permutation round and a CPU data-register access are mutually exclusive.
        if rndc_r /= x"00" then
          for i in 0 to 49 loop
            mem(KECC_MEMA + i) <= st_o_w((i * 32) + 31 downto i * 32);
          end loop;

          if rndc_r = stop_r then
            rndc_r <= x"00";
            if chns_r = x"00" then
              irq <= '1';
            end if;
          else
            rndc_r <= rc_o_w;
          end if;

        elsif chns_r /= x"00" then
          for i in 0 to 49 loop
            mem(KECC_MEMA + i) <= pad_w((i * 32) + 31 downto i * 32);
          end loop;

          if just_pad_w = '1' then
            -- 0x80: stop after padding (used for t and h).
            chns_r <= x"00";
          elsif wots_prf_w = '1' then
            -- Map WOTS_PRF to WOTS_HASH and FORS_PRF to FORS_TREE.
            if mem(KECC_ADRS + 4)(31 downto 24) = x"05" then
              mem(KECC_ADRS + 4)(31 downto 24) <= x"00";
            else
              mem(KECC_ADRS + 4)(31 downto 24) <= x"03";
            end if;
            chns_r <= "00" & chns_r(5 downto 0);
            rndc_r <= x"01";
          else
            chns_r <= std_ulogic_vector(unsigned(chns_r) - 1);
            chni_r <= std_ulogic_vector(unsigned(chni_r) + 1);
            rndc_r <= x"01";
          end if;
        end if;
      end if;

      -- Synchronous, active-high reset. rdata and the state memory deliberately
      -- retain their values, as they do in the original Verilog implementation.
      if rst = '1' then
        rndc_r <= x"00";
        stop_r <= x"74";
        chns_r <= x"00";
        chni_r <= x"00";
        secn_r <= x"10";
      end if;
    end if;
  end process;

end keccak_sloth_rtl;
