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

#ifndef UNICORN_MCU
#define UNICORN_MCU

typedef struct _unicorn_controller_t {
    volatile uint32_t PENDING;
    volatile uint32_t EXCEPTION;
    volatile uint32_t INTR_CHAR;
    volatile uint32_t RAM_SIZE;
    volatile uint32_t STACK_SIZE;
    volatile uint32_t IDLE;
    volatile uint32_t INSNS;
} unicorn_controller_t;

#define UNICORN_CONTROLLER ((unicorn_controller_t*)0x40000100)

typedef struct _gpio_t {
    volatile uint32_t ODR;
    volatile uint32_t IDR;
} gpio_t;

#define GPIO ((gpio_t*)0x40000200)
#define GPIO_X ((gpio_t*)0x40000208)
#define GPIO_Y ((gpio_t*)0x40000210)

typedef struct _servo_t {
    volatile uint32_t ANGLE;
    volatile uint32_t TIME;
} servo_t;

#define SERVO_1 ((servo_t*)0x40000218)

typedef struct _adc_t {
    volatile uint32_t IDR[12];
} adc_t;

#define ADC_X ((adc_t*)0x40000220)
#define ADC_Y ((adc_t*)0x40000250)

typedef struct _rtc_t {
    volatile uint32_t TICKS_MS;
    volatile uint32_t TICKS_US;
} rtc_t;

#define RTC ((rtc_t*)0x40000300)

typedef struct _i2c_t {
    volatile uint32_t DATA;
    volatile uint32_t COMMAND; // (0) Start bit, (1) Stop bit
} i2c_t;

#define I2C ((i2c_t*)0x40000400)

#endif
