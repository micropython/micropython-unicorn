/*
 * This file is part of the MicroPython project, http://micropython.org/
 *
 * The MIT License (MIT)
 *
 * Copyright (c) 2013, 2014 Damien P. George
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include <stdio.h>

#include "py/runtime.h"
#include "modpyb.h"
#include "modmachine.h"
#include "unicorn_mcu.h"

typedef struct _pyb_adc_obj_t {
    mp_obj_base_t base;
    qstr pin_name;
    adc_t *port;
    mp_uint_t number;
} pyb_adc_obj_t;

STATIC const pyb_adc_obj_t pyb_adc_obj[] = {
    {{&pyb_adc_type}, MP_QSTR_X1, ADC_X, 1},
    {{&pyb_adc_type}, MP_QSTR_X2, ADC_X, 2},
    {{&pyb_adc_type}, MP_QSTR_X3, ADC_X, 3},
    {{&pyb_adc_type}, MP_QSTR_X4, ADC_X, 4},
    {{&pyb_adc_type}, MP_QSTR_X5, ADC_X, 5},
    {{&pyb_adc_type}, MP_QSTR_X6, ADC_X, 6},
    {{&pyb_adc_type}, MP_QSTR_X7, ADC_X, 7},
    {{&pyb_adc_type}, MP_QSTR_X8, ADC_X, 8},
    {{&pyb_adc_type}, MP_QSTR_X9, ADC_X, 9},
    {{&pyb_adc_type}, MP_QSTR_X10, ADC_X, 10},
    {{&pyb_adc_type}, MP_QSTR_X11, ADC_X, 11},
    {{&pyb_adc_type}, MP_QSTR_X12, ADC_X, 12},
    {{&pyb_adc_type}, MP_QSTR_Y1, ADC_Y, 1},
    {{&pyb_adc_type}, MP_QSTR_Y2, ADC_Y, 2},
    {{&pyb_adc_type}, MP_QSTR_Y3, ADC_Y, 3},
    {{&pyb_adc_type}, MP_QSTR_Y4, ADC_Y, 4},
    {{&pyb_adc_type}, MP_QSTR_Y5, ADC_Y, 5},
    {{&pyb_adc_type}, MP_QSTR_Y6, ADC_Y, 6},
    {{&pyb_adc_type}, MP_QSTR_Y7, ADC_Y, 7},
    {{&pyb_adc_type}, MP_QSTR_Y8, ADC_Y, 8},
    {{&pyb_adc_type}, MP_QSTR_Y9, ADC_Y, 9},
    {{&pyb_adc_type}, MP_QSTR_Y10, ADC_Y, 10},
    {{&pyb_adc_type}, MP_QSTR_Y11, ADC_Y, 11},
    {{&pyb_adc_type}, MP_QSTR_Y12, ADC_Y, 12},
};

void pyb_adc_print(const mp_print_t *print, mp_obj_t self_in, mp_print_kind_t kind) {
    mp_printf(print, "<ADC on channel=?>");
}

STATIC mp_obj_t pyb_adc_make_new(const mp_obj_type_t *type, size_t n_args, size_t n_kw, const mp_obj_t *args) {
    mp_arg_check_num(n_args, n_kw, 1, 1, false);

    machine_pin_obj_t *pin = machine_pin_get(args[0]);

    for (int i = 0; i < MP_ARRAY_SIZE(pyb_adc_obj); i++) {
        if (pyb_adc_obj[i].pin_name == pin->name) {
            return (mp_obj_t)&pyb_adc_obj[i];
        }
    }
    return mp_const_none;
}

STATIC mp_obj_t pyb_adc_read(mp_obj_t self_in) {
    pyb_adc_obj_t *self = self_in;
    return mp_obj_new_int(self->port->IDR[self->number - 1]);
}

STATIC MP_DEFINE_CONST_FUN_OBJ_1(pyb_adc_read_obj, pyb_adc_read);

STATIC const mp_rom_map_elem_t pyb_adc_locals_dict_table[] = {
    { MP_ROM_QSTR(MP_QSTR_read), MP_ROM_PTR(&pyb_adc_read_obj) },
};

STATIC MP_DEFINE_CONST_DICT(pyb_adc_locals_dict, pyb_adc_locals_dict_table);

const mp_obj_type_t pyb_adc_type = {
    { &mp_type_type },
    .name = MP_QSTR_ADC,
    .print = pyb_adc_print,
    .make_new = pyb_adc_make_new,
    .locals_dict = (mp_obj_dict_t*)&pyb_adc_locals_dict,
};
