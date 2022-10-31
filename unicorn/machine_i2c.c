#include <stdio.h>
#include <string.h>

#include "py/runtime.h"
#include "py/mphal.h"
#include "py/mperrno.h"
#include "extmod/machine_i2c.h"
#include "unicorn_mcu.h"

typedef struct _machine_i2c_obj_t {
    mp_obj_base_t base;
} machine_i2c_obj_t;

STATIC const machine_i2c_obj_t machine_i2c_obj[] = {
    {{&machine_i2c_type}},
};

STATIC void machine_i2c_print(const mp_print_t *print, mp_obj_t self_in, mp_print_kind_t kind) {
    mp_printf(print, "I2C(1, freq=unicorn, timeout=unicorn)");
}

STATIC mp_obj_t machine_i2c_make_new(const mp_obj_type_t *type, size_t n_args, size_t n_kw, const mp_obj_t *all_args) {
    enum { ARG_id, ARG_scl, ARG_sda, ARG_freq, ARG_timeout };
    static const mp_arg_t allowed_args[] = {
        { MP_QSTR_id, MP_ARG_REQUIRED | MP_ARG_OBJ },
        { MP_QSTR_scl, MP_ARG_KW_ONLY | MP_ARG_OBJ, {.u_obj = MP_OBJ_NULL} },
        { MP_QSTR_sda, MP_ARG_KW_ONLY | MP_ARG_OBJ, {.u_obj = MP_OBJ_NULL} },
        { MP_QSTR_freq, MP_ARG_KW_ONLY | MP_ARG_INT, {.u_int = 400000} },
        { MP_QSTR_timeout, MP_ARG_KW_ONLY | MP_ARG_INT, {.u_int = 1000} },
    };
    mp_arg_val_t args[MP_ARRAY_SIZE(allowed_args)];
    mp_arg_parse_all_kw_array(n_args, n_kw, all_args, MP_ARRAY_SIZE(allowed_args), allowed_args, args);

    // work out i2c bus
    int i2c_id = 0;
    if (MP_OBJ_IS_STR(args[ARG_id].u_obj)) {
        const char *port = mp_obj_str_get_str(args[ARG_id].u_obj);
        if (0) {
        #ifdef MICROPY_HW_I2C1_NAME
        } else if (strcmp(port, "X") == 0) {
            i2c_id = 1;
        #endif
        } else {
            nlr_raise(mp_obj_new_exception_msg_varg(&mp_type_ValueError,
                "I2C(%s) doesn't exist", port));
        }
    } else {
        nlr_raise(mp_obj_new_exception_msg_varg(&mp_type_ValueError,
            "I2C(%d) doesn't exist", i2c_id));
    }

    // get static peripheral object
    machine_i2c_obj_t *self = (machine_i2c_obj_t*)&machine_i2c_obj[i2c_id - 1];

    // here we would check the scl/sda pins and configure them, but it's not implemented
    if (args[ARG_scl].u_obj != MP_OBJ_NULL || args[ARG_sda].u_obj != MP_OBJ_NULL) {
        mp_raise_ValueError("explicit choice of scl/sda is not implemented");
    }

    // initialise the I2C peripheral
    //machine_i2c_init(self, args[ARG_freq].u_int, args[ARG_timeout].u_int);

    return MP_OBJ_FROM_PTR(self);
}

STATIC int machine_i2c_readfrom(mp_obj_base_t *self_in, uint16_t addr, uint8_t *dest, size_t len, bool stop) {
    printf("READFROM\n");
    return 0;
}

STATIC int machine_i2c_writeto(mp_obj_base_t *self_in, uint16_t addr, const uint8_t *src, size_t len, bool stop) {

    I2C->COMMAND = 0;

    I2C->DATA = addr << 1;

    int ret = I2C->DATA;
    if (ret < 0) {
        return ret;
    } else if (ret != 0) {
        return -MP_ENODEV;
    }

    int num_acks = 0;

    while (len > 0U) {
        I2C->DATA = *src++;
        len--;
        ret = I2C->DATA;
        if (ret < 0) {
            return ret;
        } else if (ret != 0) {
            break;
        }
        ++num_acks;
    }

    if (stop) {
        I2C->COMMAND = 1;
    }

    return num_acks;
}

STATIC int machine_i2c_transfer_single(mp_obj_base_t *self_in, uint16_t addr, size_t len, uint8_t *buf, unsigned int flags) {
    if (flags & MP_MACHINE_I2C_FLAG_READ) {
        return machine_i2c_readfrom(self_in, addr, buf, len, flags & MP_MACHINE_I2C_FLAG_STOP);
    } else {
        return machine_i2c_writeto(self_in, addr, buf, len, flags & MP_MACHINE_I2C_FLAG_STOP);
    }
}

STATIC const mp_machine_i2c_p_t machine_i2c_p = {
    .transfer = mp_machine_i2c_transfer_adaptor,
    .transfer_single = machine_i2c_transfer_single,
};

const mp_obj_type_t machine_i2c_type = {
    { &mp_type_type },
    .name = MP_QSTR_I2C,
    .print = machine_i2c_print,
    .make_new = machine_i2c_make_new,
    .protocol = &machine_i2c_p,
    .locals_dict = (mp_obj_dict_t*)&mp_machine_i2c_locals_dict,
};
