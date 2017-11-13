# HELLO WORLD!
# hello world!

print('hello world')
#####
# BIG INTEGER
# bignum

print(1 << 1000)
#####
# ASSEMBLY
# inline assembler

@micropython.asm_thumb
def asm_add(r0, r1):
    add(r0, r0, r1)
print(asm_add(1, 2))
#####
# SWITCH
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
# LEDS
# four LEDS numbered 1 to 4

import time
import pyb

for i in range(1000):
    pyb.LED((i%4) + 1).toggle()
    time.sleep_ms(100)
#####
# TIME
# the time module is utime, a specialized MicroPython library
# sleep will break the clock speed
# dates not yet supported

import time

print(time.ticks_ms())

time.sleep_ms(1000)

print(time.ticks_us())

time.sleep_us(1000000)
#####
# MATH
# a subset of the Python Math library

import math
import cmath

print(math.sqrt(5))
print(math.log10(100))
print(math.sin(12345) ** 2 + math.cos(12345) ** 2)
print(math.cosh(1) ** 2 - math.sinh(1) ** 2)
print(cmath.polar(1 + 1j))
#####
# PIN LED
# PERIPHERALS: pin_led
# Using a Pin with micropython
# Make sure you have the LED checkbox marked!

import machine

# The LED is connected to our virtual pin Y12
y12 = machine.Pin('Y12')

y12(0 if y12() else 1)
#####
# ADC
# PERIPHERALS: pin_adc
# Using the ADC (Analogue to Digital Converter)
# Make sure you have the ADC checkbox marked!

import machine
import pyb

# The slider is connected to pin Y4, try adjusting it
y4 = machine.Pin('Y4')

adc = pyb.ADC(y4)

print(adc.read())
#####
# SERVO
# PERIPHERALS: pin_servo
# Using the Servo
# Make sure you have the Servo checkbox marked!

import machine
import pyb

# The pyboard has four simple servo connections
servo = pyb.Servo(1)

servo.angle(90, 5000)
#####
# I2C LCD
# PERIPHERALS: i2c_lcd
# A fully simulated I2C bus and LCD Display
# The framebuf class simplifies graphics in MicroPython
# Use the hardware i2c in example Pong for faster performance
# Make sure you have the I2C LCD checkbox marked!

import machine
import framebuf

scl = machine.Pin('X9')
sda = machine.Pin('X10')
i2c = machine.I2C(scl=scl, sda=sda)

fbuf = framebuf.FrameBuffer(bytearray(64 * 32 // 8), 64, 32, framebuf.MONO_HLSB)

logo = framebuf.FrameBuffer(bytearray(17 * 17 // 8), 17, 17, framebuf.MONO_HLSB)

logo.fill(0)
logo.fill_rect(1, 1, 15, 15, 1)
logo.vline(4, 4, 12, 0)
logo.vline(8, 1, 12, 0)
logo.vline(12, 4, 12, 0)
logo.vline(14, 13, 2, 0)

fbuf.fill(0)
fbuf.blit(logo, 23, 7)

i2c.writeto(8, fbuf)
#####
# MANDELBROT SET
# A python Mandelbrot set courtesy of 
# http://warp.povusers.org/MandScripts/python.html
# Try your own Python3 scripts on MicroPython!

minX = -2.0
maxX = 1.0
width = 60
height = 28
aspectRatio = 2

chars = ' .,-:;i+hHM$*#@ '

yScale = (maxX-minX)*(float(height)/width)*aspectRatio

for y in range(height):
    line = ''
    for x in range(width):
        c = complex(minX+x*(maxX-minX)/width, y*yScale/height-yScale/2)
        z = c
        for char in chars:
            if abs(z) > 2:
                break
            z = z*z+c
        line += char
    print(line)
#####
# Pong
# PERIPHERALS: i2c_lcd pin_adc
# Pong!
# Using emulated hardware i2c, we can push enough frames for
# rough animations. Performance for this project is reduced
# using chromium.

import machine
import framebuf
import time
import pyb

SCREEN_WIDTH = 64
SCREEN_HEIGHT = 32

game_over = False
score = 0

class Entity:
    def __init__(self, x, y, w, h, vx, vy):
        self.x = x;
        self.y = y;
        self.w = w;
        self.h = h;
        self.vx = vx;
        self.vy = vy;

    def draw(self, fbuf):
        fbuf.fill_rect(int(self.x), int(self.y), self.w, self.h, 1)

class Ball(Entity):
    def update(self, dt, player):
        self.x += self.vx * dt;
        if (self.x <= 0):
            self.x = 0
            self.vx = -self.vx
        if (self.x >= SCREEN_WIDTH - self.w):
            self.x = SCREEN_WIDTH - self.w
            self.vx = -self.vx
        self.y += self.vy * dt;
        if (self.y <= 0):
            self.y = 0
            self.vy = -self.vy
        if (self.y >= SCREEN_HEIGHT - self.h - player.h):
            if (self.x >= player.x and self.x <= player.x + player.w):
                self.y = SCREEN_HEIGHT - self.h - player.h
                self.vy = -self.vy
                global score
                score += 1
                if score % 2 == 0:
                    self.vx += (self.vx/abs(self.vx)) * 1
                if score % 3 == 0:
                    self.vy += (self.vy/abs(self.vy)) * 1
            else:
                global game_over
                game_over = True

class Player(Entity):
    pass

ball = Ball(32, 16, 1, 1, 2, -2)
player = Player(30, 31, 10, 1, 0, 0)

y4 = machine.Pin('Y4')
adc = pyb.ADC(y4)
i2c = machine.I2C('X')
fbuf = framebuf.FrameBuffer(bytearray(64 * 32 // 8), 64, 32, framebuf.MONO_HLSB)
tick = time.ticks_ms()

while not game_over:
    ntick = time.ticks_ms()
    ball.update(time.ticks_diff(ntick, tick) // 100, player)
    tick = ntick
    player.x = adc.read() * 58 / 255
    fbuf.fill(0)
    ball.draw(fbuf)
    player.draw(fbuf)
    i2c.writeto(8, fbuf)
    time.sleep_ms(50) # Adjust this for performance boosts

fbuf.fill(0)
fbuf.text('GAME', 15, 8)
fbuf.text('OVER', 15, 18)
i2c.writeto(8, fbuf)

print('Score: ', score)
