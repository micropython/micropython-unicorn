#include <unistd.h>
#include "py/mpconfig.h"

typedef struct _ucp_uart_t {
    volatile uint32_t TXR;
    volatile uint32_t RXR;
} ucp_uart_t;

#define UART0 ((ucp_uart_t*)0x40000000)

// Receive single character
int mp_hal_stdin_rx_chr(void) {
    unsigned char c = 0;
    c = UART0->RXR;
    return c;
}

// Send string of given length
void mp_hal_stdout_tx_strn(const char *str, mp_uint_t len) {
    while (len--) {
        UART0->TXR = *str++;
    }
}
