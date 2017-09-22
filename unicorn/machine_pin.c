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
#include "modmachine.h"

STATIC const machine_pin_obj_t machine_pin_obj[] = {
    {{&machine_pin_type}, MP_QSTR_X1, GPIO_X, 1},
    {{&machine_pin_type}, MP_QSTR_X2, GPIO_X, 2},
    {{&machine_pin_type}, MP_QSTR_X3, GPIO_X, 3},
    {{&machine_pin_type}, MP_QSTR_X4, GPIO_X, 4},
    {{&machine_pin_type}, MP_QSTR_X5, GPIO_X, 5},
    {{&machine_pin_type}, MP_QSTR_X6, GPIO_X, 6},
    {{&machine_pin_type}, MP_QSTR_X7, GPIO_X, 7},
    {{&machine_pin_type}, MP_QSTR_X8, GPIO_X, 8},
    {{&machine_pin_type}, MP_QSTR_X9, GPIO_X, 9},
    {{&machine_pin_type}, MP_QSTR_X10, GPIO_X, 10},
    {{&machine_pin_type}, MP_QSTR_X11, GPIO_X, 11},
    {{&machine_pin_type}, MP_QSTR_X12, GPIO_X, 12},
    {{&machine_pin_type}, MP_QSTR_X13, GPIO_X, 13},
    {{&machine_pin_type}, MP_QSTR_X14, GPIO_X, 14},
    {{&machine_pin_type}, MP_QSTR_X15, GPIO_X, 15},
    {{&machine_pin_type}, MP_QSTR_X16, GPIO_X, 16},
    {{&machine_pin_type}, MP_QSTR_X17, GPIO_X, 17},
    {{&machine_pin_type}, MP_QSTR_X18, GPIO_X, 18},
    {{&machine_pin_type}, MP_QSTR_X19, GPIO_X, 19},
    {{&machine_pin_type}, MP_QSTR_X20, GPIO_X, 20},
    {{&machine_pin_type}, MP_QSTR_X21, GPIO_X, 21},
    {{&machine_pin_type}, MP_QSTR_X22, GPIO_X, 22},
    {{&machine_pin_type}, MP_QSTR_X23, GPIO_X, 23},
    {{&machine_pin_type}, MP_QSTR_X24, GPIO_X, 24},
    {{&machine_pin_type}, MP_QSTR_Y1, GPIO_Y, 1},
    {{&machine_pin_type}, MP_QSTR_Y2, GPIO_Y, 2},
    {{&machine_pin_type}, MP_QSTR_Y3, GPIO_Y, 3},
    {{&machine_pin_type}, MP_QSTR_Y4, GPIO_Y, 4},
    {{&machine_pin_type}, MP_QSTR_Y5, GPIO_Y, 5},
    {{&machine_pin_type}, MP_QSTR_Y6, GPIO_Y, 6},
    {{&machine_pin_type}, MP_QSTR_Y7, GPIO_Y, 7},
    {{&machine_pin_type}, MP_QSTR_Y8, GPIO_Y, 8},
    {{&machine_pin_type}, MP_QSTR_Y9, GPIO_Y, 9},
    {{&machine_pin_type}, MP_QSTR_Y10, GPIO_Y, 10},
    {{&machine_pin_type}, MP_QSTR_Y11, GPIO_Y, 11},
    {{&machine_pin_type}, MP_QSTR_Y12, GPIO_Y, 12},
};

machine_pin_obj_t *machine_pin_get(mp_obj_t *obj_in) {
    if (MP_OBJ_IS_TYPE(obj_in, &machine_pin_type)) {
        return (machine_pin_obj_t*)obj_in;
    }
    mp_raise_TypeError("expecting a Pin");
}

void pin_set(mp_obj_t self_in, int value) {
    machine_pin_obj_t *self = self_in;
    if (value) {
        self->port->ODR |= (1 << self->pin);
    } else {
        self->port->ODR &= ~(1 << self->pin);
    }
}

void machine_pin_print(const mp_print_t *print, mp_obj_t self_in, mp_print_kind_t kind) {
    machine_pin_obj_t *self = self_in;
    mp_printf(print, "Pin(%q)", self->name);
}

STATIC mp_obj_t machine_pin_make_new(const mp_obj_type_t *type, size_t n_args, size_t n_kw, const mp_obj_t *args) {
    mp_arg_check_num(n_args, n_kw, 1, MP_OBJ_FUN_ARGS_MAX, true);
    qstr args0 = mp_obj_str_get_qstr(args[0]);
    for (int i = 0; i < MP_ARRAY_SIZE(machine_pin_obj); i++) {
        if (machine_pin_obj[i].name == args0) {
            return (mp_obj_t)&machine_pin_obj[i];
        }
    }
    return mp_const_none;
}

STATIC mp_obj_t machine_pin_off(mp_obj_t self_in) {
    pin_set(self_in, 0);
    return mp_const_none;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(machine_pin_off_obj, machine_pin_off);

STATIC mp_obj_t machine_pin_on(mp_obj_t self_in) {
    pin_set(self_in, 1);
    return mp_const_none;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(machine_pin_on_obj, machine_pin_on);

mp_obj_t machine_pin_call(mp_obj_t self_in, size_t n_args, size_t n_kw, const mp_obj_t *args) {
    mp_arg_check_num(n_args, n_kw, 0, 1, false);
    machine_pin_obj_t *self = self_in;
    if (n_args <= 0) {
        return MP_OBJ_NEW_SMALL_INT((self->port->IDR & (1 << self->pin)) ? 1 : 0);
    } else {
        if (mp_obj_get_int(args[0]) == 0) {
            self->port->ODR &= ~(1 << self->pin);
        } else {
            self->port->ODR |= (1 << self->pin);
        }
        return mp_const_none;
    }
}

STATIC mp_obj_t machine_pin_value(mp_uint_t n_args, const mp_obj_t *args) {
    return machine_pin_call(args[0], n_args - 1, 0, args + 1);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(machine_pin_value_obj, 1, 2, machine_pin_value);

STATIC const mp_rom_map_elem_t machine_pin_locals_dict_table[] = {
    { MP_ROM_QSTR(MP_QSTR_on), MP_ROM_PTR(&machine_pin_on_obj) },
    { MP_ROM_QSTR(MP_QSTR_off), MP_ROM_PTR(&machine_pin_off_obj) },
    { MP_ROM_QSTR(MP_QSTR_value), MP_ROM_PTR(&machine_pin_value_obj) },

    { MP_ROM_QSTR(MP_QSTR_IN), MP_ROM_INT(0) },
    { MP_ROM_QSTR(MP_QSTR_OUT), MP_ROM_INT(1) },
    { MP_ROM_QSTR(MP_QSTR_PULL_UP), MP_ROM_INT(0) },
    { MP_ROM_QSTR(MP_QSTR_PULL_DOWN), MP_ROM_INT(1) },
    { MP_ROM_QSTR(MP_QSTR_PULL_NONE), MP_ROM_INT(0) },
};

STATIC MP_DEFINE_CONST_DICT(machine_pin_locals_dict, machine_pin_locals_dict_table);

const mp_obj_type_t machine_pin_type = {
    { &mp_type_type },
    .name = MP_QSTR_Pin,
    .print = machine_pin_print,
    .make_new = machine_pin_make_new,
    .call = machine_pin_call,
    .locals_dict = (mp_obj_dict_t*)&machine_pin_locals_dict,
};
