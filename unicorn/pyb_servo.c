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
#include "unicorn_mcu.h"

#define PYB_SERVO_NUM (1)

typedef struct _pyb_servo_obj_t {
    mp_obj_base_t base;
    servo_t *pins;
    mp_uint_t servo_id;
} pyb_servo_obj_t;

STATIC const pyb_servo_obj_t pyb_servo_obj[] = {
    {{&pyb_servo_type}, SERVO_1, 1},
};

STATIC void pyb_servo_print(const mp_print_t *print, mp_obj_t self_in, mp_print_kind_t kind) {
    pyb_servo_obj_t *self = self_in;
    mp_printf(print, "<Servo %lu at ?us>", self->servo_id);
}

STATIC mp_obj_t pyb_servo_make_new(const mp_obj_type_t *type, size_t n_args, size_t n_kw, const mp_obj_t *args) {
    mp_arg_check_num(n_args, n_kw, 1, 1, false);

    mp_int_t servo_id = mp_obj_get_int(args[0]) - 1;

    if (!(0 <= servo_id && servo_id < PYB_SERVO_NUM)) {
        nlr_raise(mp_obj_new_exception_msg_varg(&mp_type_ValueError, "Servo %d does not exist", servo_id + 1));
    }

    return (mp_obj_t)&pyb_servo_obj[servo_id];
}

STATIC mp_obj_t pyb_servo_angle(mp_uint_t n_args, const mp_obj_t *args) {
    pyb_servo_obj_t *self = args[0];
    if (n_args == 1) {
        return mp_obj_new_int(self->pins->ANGLE);
    } else {
        self->pins->ANGLE = mp_obj_get_int(args[1]);
        if (n_args == 3) {
            self->pins->TIME = mp_obj_get_int(args[2]);
        }
    }
    return mp_const_none;
}

STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(pyb_servo_angle_obj, 1, 3, pyb_servo_angle);

STATIC const mp_rom_map_elem_t pyb_servo_locals_dict_table[] = {
    { MP_ROM_QSTR(MP_QSTR_angle), MP_ROM_PTR(&pyb_servo_angle_obj) },
};

STATIC MP_DEFINE_CONST_DICT(pyb_servo_locals_dict, pyb_servo_locals_dict_table);

const mp_obj_type_t pyb_servo_type = {
    { &mp_type_type },
    .name = MP_QSTR_Servo,
    .print = pyb_servo_print,
    .make_new = pyb_servo_make_new,
    .locals_dict = (mp_obj_dict_t*)&pyb_servo_locals_dict,
};
