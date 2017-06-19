# Hello World!
# hello world!

print('hello world')
#####
# Big Integer
# bignum

print(1 << 1000)
#####
# Assembly
# inline assembler

@micropython.asm_thumb
def asm_add(r0, r1):
    add(r0, r0, r1)
print(asm_add(1, 2))
#####
# Switch
# push the USR button on the pyboard to flash the LEDs!
# try using the reset button on the pyboard to quit this script!
# switch callback not yet supported.

import time
import pyb

while True:
    if pyb.Switch().value():
        pyb.LED(1).on()
    else:
        pyb.LED(1).off()
    time.sleep_ms(50)

#####
# LEDs
# four LEDS numbered 1 to 4

import time
import pyb

for i in range(1000):
    pyb.LED((i%4) + 1).toggle()
    time.sleep_ms(100)
#####
# Time
# the time module is utime, a specialized MicroPython library
# sleep will break the clock speed
# dates not yet supported

import time

print(time.ticks_ms())

time.sleep_ms(1000)

print(time.ticks_us())

time.sleep_us(1000000)
#####
# Math
# a subset of the Python Math library

import math
import cmath

print(math.sqrt(5))
print(math.log10(100))
print(math.sin(12345) ** 2 + math.cos(12345) ** 2)
print(math.cosh(1) ** 2 - math.sinh(1) ** 2)
print(cmath.polar(1 + 1j))
