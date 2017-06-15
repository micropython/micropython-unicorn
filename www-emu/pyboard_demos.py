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
# push the USR button on the pyboard to turn the switch on!
# try using the reset button on the pyboard to quit this script!
# switch callback not yet supported.
import pyb
sw = pyb.Switch()
b = sw()
while True:
    s = sw()
    if b != s:
        print(s)
    b = s
#####
# LEDs
# there are four LEDS numbered 1 to 4
import pyb
for i in range(1000):
    pyb.LED((i%4) + 1).toggle()
