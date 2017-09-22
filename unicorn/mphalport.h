#include "py/obj.h"
#include "modmachine.h"

void mp_hal_delay_ms(mp_uint_t ms);
void mp_hal_delay_us(mp_uint_t us);
mp_uint_t mp_hal_ticks_ms(void);
mp_uint_t mp_hal_ticks_us(void);
mp_uint_t mp_hal_ticks_cpu(void);
void mp_hal_set_interrupt_char(int c);

#define mp_hal_pin_obj_t const machine_pin_obj_t*
#define mp_hal_pin_od_low(p) pin_set((mp_obj_t)p, 0)
#define mp_hal_pin_od_high(p) pin_set((mp_obj_t)p, 1)
#define mp_hal_get_pin_obj(o) machine_pin_get(o)
#define mp_hal_pin_read(p) (((p)->port->IDR & (1 << (p)->pin)) ? 1 : 0)
#define mp_hal_pin_open_drain(p) mp_hal_pin_config((p), 0, 0, 0)


static inline void mp_hal_pin_config(mp_hal_pin_obj_t pin, uint32_t mode, uint32_t pull, uint32_t alt) { }

static inline void mp_hal_delay_us_fast(uint32_t us) { return; }
