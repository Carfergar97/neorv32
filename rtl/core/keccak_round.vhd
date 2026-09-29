-- ================================================================================ --
-- Keccak-f[1600] round function                                                     --
-- -------------------------------------------------------------------------------- --
-- Purely combinatorial ("stackable") logic for Keccak-f[1600] (SHA-3).            --
-- Based on the original implementation by Markku-Juhani O. Saarinen.               --
-- ================================================================================ --

library ieee;
use ieee.std_logic_1164.all;

entity keccak_round is
  port (
    s_o : out std_ulogic_vector(1599 downto 0); -- state out
    r_o : out std_ulogic_vector(7 downto 0);    -- round constant out
    s_i : in  std_ulogic_vector(1599 downto 0); -- state in
    r_i : in  std_ulogic_vector(7 downto 0)     -- round constant in
  );
end keccak_round;

architecture keccak_round_rtl of keccak_round is

  signal c_w   : std_ulogic_vector(319 downto 0);
  signal d_w   : std_ulogic_vector(319 downto 0);
  signal th_w  : std_ulogic_vector(1599 downto 0);
  signal rp_w  : std_ulogic_vector(1599 downto 0);
  signal chi_w : std_ulogic_vector(1599 downto 0);

begin

  -- Theta (FIPS 202, section 3.2.1) ------------------------------------------------
  c_w <= s_i(319 downto 0) xor s_i(639 downto 320) xor
         s_i(959 downto 640) xor s_i(1279 downto 960) xor
         s_i(1599 downto 1280);

  d_w <= (c_w(255 downto 0) & c_w(319 downto 256)) xor
         (c_w(62 downto 0) & c_w(63) &
          c_w(318 downto 256) & c_w(319) &
          c_w(254 downto 192) & c_w(255) &
          c_w(190 downto 128) & c_w(191) &
          c_w(126 downto 64) & c_w(127));

  th_w <= s_i xor (d_w & d_w & d_w & d_w & d_w);

  -- Rho and Pi (FIPS 202, sections 3.2.2 and 3.2.3) --------------------------------
  rp_w <= th_w(1405 downto 1344) & th_w(1407 downto 1406) &
          th_w(982 downto 960)   & th_w(1023 downto 983) &
          th_w(920 downto 896)   & th_w(959 downto 921) &
          th_w(520 downto 512)   & th_w(575 downto 521) &
          th_w(129 downto 128)   & th_w(191 downto 130) &
          th_w(1479 downto 1472) & th_w(1535 downto 1480) &
          th_w(1136 downto 1088) & th_w(1151 downto 1137) &
          th_w(757 downto 704)   & th_w(767 downto 758) &
          th_w(347 downto 320)   & th_w(383 downto 348) &
          th_w(292 downto 256)   & th_w(319 downto 293) &
          th_w(1325 downto 1280) & th_w(1343 downto 1326) &
          th_w(1271 downto 1216) & th_w(1279 downto 1272) &
          th_w(870 downto 832)   & th_w(895 downto 871) &
          th_w(505 downto 448)   & th_w(511 downto 506) &
          th_w(126 downto 64)    & th_w(127 downto 127) &
          th_w(1410 downto 1408) & th_w(1471 downto 1411) &
          th_w(1042 downto 1024) & th_w(1087 downto 1043) &
          th_w(700 downto 640)   & th_w(703 downto 701) &
          th_w(619 downto 576)   & th_w(639 downto 620) &
          th_w(227 downto 192)   & th_w(255 downto 228) &
          th_w(1585 downto 1536) & th_w(1599 downto 1586) &
          th_w(1194 downto 1152) & th_w(1215 downto 1195) &
          th_w(788 downto 768)   & th_w(831 downto 789) &
          th_w(403 downto 384)   & th_w(447 downto 404) &
          th_w(63 downto 0);

  -- Chi (FIPS 202, section 3.2.4) --------------------------------------------------
  chi_w <= rp_w xor
           ((rp_w(1407 downto 1280) & rp_w(1599 downto 1408)) and
            not (rp_w(1343 downto 1280) & rp_w(1599 downto 1344))) &
           ((rp_w(1087 downto 960) & rp_w(1279 downto 1088)) and
            not (rp_w(1023 downto 960) & rp_w(1279 downto 1024))) &
           ((rp_w(767 downto 640) & rp_w(959 downto 768)) and
            not (rp_w(703 downto 640) & rp_w(959 downto 704))) &
           ((rp_w(447 downto 320) & rp_w(639 downto 448)) and
            not (rp_w(383 downto 320) & rp_w(639 downto 384))) &
           ((rp_w(127 downto 0) & rp_w(319 downto 128)) and
            not (rp_w(63 downto 0) & rp_w(319 downto 64)));

  -- Iota (FIPS 202, section 3.2.5) -------------------------------------------------
  -- Seven LFSR steps, converted from Galois to Fibonacci representation.
  r_o <= ((7 downto 0 => r_i(0)) and x"1A") xor
         ((7 downto 0 => r_i(1)) and x"34") xor
         ((7 downto 0 => r_i(2)) and x"68") xor
         ((7 downto 0 => r_i(3)) and x"D0") xor
         ((7 downto 0 => r_i(4)) and x"BA") xor
         ((7 downto 0 => r_i(5)) and x"6E") xor
         ((7 downto 0 => r_i(6)) and x"C6") xor
         ((7 downto 0 => r_i(7)) and x"8D");

  -- Expand the low seven round-constant bits into lane (0, 0).
  s_o <= chi_w(1599 downto 64) &
         (r_i(6) xor chi_w(63)) & chi_w(62 downto 32) &
         (r_i(5) xor chi_w(31)) & chi_w(30 downto 16) &
         (r_i(4) xor chi_w(15)) & chi_w(14 downto 8) &
         (r_i(3) xor chi_w(7))  & chi_w(6 downto 4) &
         (r_i(2) xor chi_w(3))  & chi_w(2) &
         (r_i(1) xor chi_w(1))  &
         (r_i(0) xor chi_w(0));

end keccak_round_rtl;
