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
