-- ================================================================================ --
-- ascon accelerator for SLOTH                                                      --
-- -------------------------------------------------------------------------------- --
-- Simple 32-bit interface to the ascon accelerator.                               --
-- Based on the original implementation by Markku-Juhani O. Saarinen.               --
-- ================================================================================ --

library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;

entity ascon_sloth is
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
end ascon_sloth;

architecture ascon_sloth_rtl of ascon_sloth is

  -- data-register block ------------------------------------------------------------
  constant ASCON_MEMA : natural := 0;   -- 1600-bit ascon state
  constant ASCON_ADRS : natural := 50;  -- 32-byte ADRS structure
  constant ASCON_SEED : natural := 58;  -- PK.seed
  constant ASCON_SKSD : natural := 66;  -- SK.seed
  constant ASCON_MTOP : natural := 74;  -- end of data-register block

  -- control-register block ---------------------------------------------------------
  constant ASCON_CTRL : natural := 120;
  constant ASCON_TRIG : natural := 120;
  constant ASCON_STOP : natural := 121;
  constant ASCON_SECN : natural := 122;
  constant ASCON_CHNS : natural := 123;

  subtype state_t is std_ulogic_vector(319 downto 0);
  subtype word_t  is std_ulogic_vector(31 downto 0);
  type mem_t is array (0 to ASCON_MTOP - 1) of word_t;

  -- Assemble consecutive 32-bit words into a vector. Word zero is the least
  -- significant word, matching the original MEM_BLOCK_50 Verilog macro.
  function mem_block_50(memory : mem_t; index : natural) return state_t is
    variable result : state_t;
  begin
    for i in 0 to 10-1 loop
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
  msel_w     <= '1' when addr_index < ASCON_CTRL else '0';
  just_pad_w <= chns_r(7);
  wots_prf_w <= chns_r(6);

  st_i_w <= mem_block_50(mem, ASCON_MEMA);

  ascon_round_inst: entity work.ascon_round
  port map (
    stateOut => st_o_w,
    rConOut => rc_o_w,
    stateIn => st_i_w,
    rConIn => rndc_r
  );

  adrs_w <= std_ulogic_vector(unsigned(mem(ASCON_ADRS + 7)) +
                               shift_left(resize(unsigned(chni_r), 32), 24)) &
            mem(ASCON_ADRS + 6) & mem(ASCON_ADRS + 5) &
            mem(ASCON_ADRS + 4) & mem(ASCON_ADRS + 3) &
            mem(ASCON_ADRS + 2) & mem(ASCON_ADRS + 1) &
            mem(ASCON_ADRS);
  seed_m <= mem(ASCON_SEED + 7) & mem(ASCON_SEED + 6) &
            mem(ASCON_SEED + 5) & mem(ASCON_SEED + 4) &
            mem(ASCON_SEED + 3) & mem(ASCON_SEED + 2) &
            mem(ASCON_SEED + 1) & mem(ASCON_SEED);
  hash_m <= st_i_w(255 downto 0);
  sksd_m <= mem(ASCON_SKSD + 7) & mem(ASCON_SKSD + 6) &
            mem(ASCON_SKSD + 5) & mem(ASCON_SKSD + 4) &
            mem(ASCON_SKSD + 3) & mem(ASCON_SKSD + 2) &
            mem(ASCON_SKSD + 1) & mem(ASCON_SKSD);
  -- It has been commented since I am not going to use it yet.
  -- pad_w  <= padf(secn_r, seed_m, adrs_w, sksd_m) when wots_prf_w = '1' else
  --           padf(secn_r, seed_m, adrs_w, hash_m);
  pad_w <= (others => '0');

  process(clk)
  begin
    if rising_edge(clk) then
      irq <= '0'; -- clear interrupt

      -- Data-register access. The original address map reserves offsets 0 to 119;
      -- only offsets 0 to 73 are backed by the data-register array.
      if (sel = '1') and (msel_w = '1') then
        if addr_index < ASCON_MTOP then
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
            when ASCON_TRIG =>
              rdata <= x"0000" & chns_r & rndc_r;
              if wen(0) = '1' then
                rndc_r <= wdata(7 downto 0);
              end if;
            when ASCON_STOP =>
              rdata <= x"000000" & stop_r;
              if wen(0) = '1' then
                stop_r <= wdata(7 downto 0);
              end if;
            when ASCON_SECN =>
              rdata <= x"000000" & secn_r;
              if wen(0) = '1' then
                secn_r <= wdata(7 downto 0);
              end if;
            when ASCON_CHNS =>
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
          for i in 0 to 10-1 loop
            mem(ASCON_MEMA + i) <= st_o_w((i * 32) + 31 downto i * 32);
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
          for i in 0 to 10-1 loop
            mem(ASCON_MEMA + i) <= pad_w((i * 32) + 31 downto i * 32);
          end loop;

          if just_pad_w = '1' then
            -- 0x80: stop after padding (used for t and h).
            chns_r <= x"00";
          elsif wots_prf_w = '1' then
            -- Map WOTS_PRF to WOTS_HASH and FORS_PRF to FORS_TREE.
            if mem(ASCON_ADRS + 4)(31 downto 24) = x"05" then
              mem(ASCON_ADRS + 4)(31 downto 24) <= x"00";
            else
              mem(ASCON_ADRS + 4)(31 downto 24) <= x"03";
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
        stop_r <= x"4B";
        chns_r <= x"00";
        chni_r <= x"00";
        secn_r <= x"10";
      end if;
    end if;
  end process;

end ascon_sloth_rtl;
