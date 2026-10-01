library IEEE;
use IEEE.STD_LOGIC_1164.ALL;

-- Uncomment the following library declaration if using
-- arithmetic functions with Signed or Unsigned values
use IEEE.NUMERIC_STD.ALL;

-- Uncomment the following library declaration if instantiating
-- any Xilinx primitives in this code.
--library UNISIM;
--use UNISIM.VComponents.all;
entity ascon_round is
    generic(UROL:integer:=1);
    Port ( stateIn : in  std_ulogic_vector (319 downto 0);
           rConIn : in  std_ulogic_vector (7 DOWNTO 0);
           rConOut : out  std_ulogic_vector (7 DOWNTO 0);
           stateOut : out  std_ulogic_vector (319 downto 0));
end ascon_round;

architecture Behavioral of ascon_round is

    -- Returns the round constant of the round following rc.
    function next_rc( rc : std_ulogic_vector(7 DOWNTO 0) ) return std_ulogic_vector is
    begin
        case rc is
            when X"5a" => return X"4b";
            when X"69" => return X"5a";
            when X"78" => return X"69";
            when X"87" => return X"78";
            when X"96" => return X"87";
            when X"a5" => return X"96";
            when X"b4" => return X"a5";
            when X"c3" => return X"b4";
            when X"d2" => return X"c3";
            when X"e1" => return X"d2";
            when X"f0" => return X"e1";
            when X"0f" => return X"f0";
            when X"1e" => return X"0f";
            when X"2d" => return X"1e";
            when X"3c" => return X"2d";
            when others => return X"00";
        end case;
    end function next_rc;

begin
 PROCESS (stateIn, rConIn)
        VARIABLE x0, x1, x2, x3, x4 : std_ulogic_vector(63 DOWNTO 0);
        VARIABLE t0, t1 : std_ulogic_vector(63 DOWNTO 0);
        VARIABLE rc : std_ulogic_vector(7 DOWNTO 0);
    BEGIN
        ---------------------------------------------------------------------------
        --! Map bit vector to ascon state
        ---------------------------------------------------------------------------
        -- Map 320-bit vector to 5 x 64-bit lanes.
        x0 := stateIn(63 + 0 * 64 DOWNTO 0 * 64);
        x1 := stateIn(63 + 1 * 64 DOWNTO 1 * 64);
        x2 := stateIn(63 + 2 * 64 DOWNTO 2 * 64);
        x3 := stateIn(63 + 3 * 64 DOWNTO 3 * 64);
        x4 := stateIn(63 + 4 * 64 DOWNTO 4 * 64);

        ---------------------------------------------------------------------------
        --! Round 1 - comment this in for v1,v2,v3,v4,v5,v6
        ---------------------------------------------------------------------------
        -- Linear operations and addition of round constant.
        rc := rConIn;
        for r in 1 to UROL loop

          x0 := x0 XOR x4;
          x2(7 DOWNTO 0) := x2(7 DOWNTO 0) XOR x1(7 DOWNTO 0) XOR rc;
          x2(63 DOWNTO 8) := x2(63 DOWNTO 8) XOR x1(63 DOWNTO 8);
          x4 := x4 XOR x3;

          -- Nonlinear operations, same as used in Keccak-Sbox
          t0 := x0;
          t1 := x1;
          x0 := x0 XOR (NOT x1 AND x2);
          x1 := x1 XOR (NOT x2 AND x3);
          x2 := x2 XOR (NOT x3 AND x4);
          x3 := x3 XOR (NOT x4 AND t0);
          x4 := x4 XOR (NOT t0 AND t1);

          -- Linear operations.
          x1 := x1 XOR x0;
          x3 := x3 XOR x2;
          x0 := x0 XOR x4;
          x2 := NOT x2;

          -- Lane rotations.
          x0 := x0 XOR (x0(18 DOWNTO 0) & x0(63 DOWNTO 19)) XOR (x0(27 DOWNTO 0) & x0(63 DOWNTO 28));
          x1 := x1 XOR (x1(60 DOWNTO 0) & x1(63 DOWNTO 61)) XOR (x1(38 DOWNTO 0) & x1(63 DOWNTO 39));
          x2 := x2 XOR (x2(0 DOWNTO 0) & x2(63 DOWNTO 1)) XOR (x2(5 DOWNTO 0) & x2(63 DOWNTO 6));
          x3 := x3 XOR (x3(9 DOWNTO 0) & x3(63 DOWNTO 10)) XOR (x3(16 DOWNTO 0) & x3(63 DOWNTO 17));
          x4 := x4 XOR (x4(6 DOWNTO 0) & x4(63 DOWNTO 7)) XOR (x4(40 DOWNTO 0) & x4(63 DOWNTO 41));

          -- Advance to the round constant of the next round.
          rc := next_rc(rc);
        end loop;
        rConOut <= rc;
        -- Map 5 x 64-bit lanes to 320-bit vector.
        stateOut(63 + 0 * 64 DOWNTO 0 * 64) <= x0;
        stateOut(63 + 1 * 64 DOWNTO 1 * 64) <= x1;
        stateOut(63 + 2 * 64 DOWNTO 2 * 64) <= x2;
        stateOut(63 + 3 * 64 DOWNTO 3 * 64) <= x3;
        stateOut(63 + 4 * 64 DOWNTO 4 * 64) <= x4;

    END PROCESS;

end Behavioral;

