//  main.c
//  Markku-Juhani O. Saarinen <mjos@iki.fi>.  See LICENSE.

//  === testing main()

#include <string.h>
#include "neorv32_uart.h"
#include "sloth_hal.h"
#include "neorv32.h"

#define BAUD_RATE 19200
const char main_hello[] =
"\n[RESET]"
"\t   ______        __  __ __\n"
"\t  / __/ /  ___  / /_/ // /  SLotH Accelerator Test 2024/05\n"
"\t _\\ \\/ /__/ _ \\/ __/ _  /   SLH-DSA / FIPS 205 ipd\n"
"\t/___/____/\\___/\\__/_//_/    markku-juhani.saarinen@tuni.fi\n\n";

//  unit tests
int test_sloth();       //  test_sloth.c
int test_bench();       //  test_bench.c
// int test_leak();        //  test_leak.c

int main()
{
  neorv32_rte_setup();
  neorv32_uart0_setup(BAUD_RATE, 0);
    int fail = 0;

    neorv32_uart0_printf(main_hello);

    neorv32_uart0_printf("[INFO]\t=== Basic health test ===\n");
    fail += test_sloth();
    neorv32_uart0_printf("\n[INFO]\t=== Testbench === \n");
    fail += test_bench();
    //fail += test_leak();

    if (fail) {
        neorv32_uart0_printf("[FAIL]\tSome tests failed.\n");
    } else {
        neorv32_uart0_printf("[PASS]\tAll tests ok.\n");
    }

    //  get input (test UART)
#ifdef SLOTH
    neorv32_uart0_printf("\nUART Test. Press x to exit.\n");
    int ch, gpio, old_gpio;

    ch = 0;
    old_gpio = -1;

    do {
        // gpio = get_gpio_in();
        // if (gpio != old_gpio) {
        //     neorv32_uart0_printf("GPIO 0x");
        //     sio_put_hex(gpio, 2);
        //     neorv32_uart0_printf('\n');
        //     old_gpio = gpio;
        // }
        //
        if (neorv32_uart0_char_received()) {
            ch = neorv32_uart0_getc();
        //     neorv32_uart0_printf("UART 0x");
        //     sio_put_hex(ch, 2);
        //     neorv32_uart0_printf(' ');
        //     neorv32_uart0_printf(ch);
        //     neorv32_uart0_printf('\n');
        }

    } while (ch != 'x');
#endif
    neorv32_uart0_printf("\n");

    return 0;
}

