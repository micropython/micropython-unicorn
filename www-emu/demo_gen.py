import sys
import os

outfile = open('demo_scripts.js', 'w')
for filename in os.listdir():
    if filename[-9:] == '_demos.py':
        infile = open(filename, 'r')
        outfile.write('var ' + filename[:-9] + '_demos = new Map([["CHOOSE A DEMO...", "# Welcome to MicroPython on Unicorn!\\n\\n# The terminal beside this is no ordinary REPL.\\n# It utilizes the Unicorn CPU emulator converted\\n# to Javascript by Unicorn.js in order to run MicroPython\\n# \\\"bare metal\\\" on an ARM CPU emulation.\\n\\n# MicroPython on Unicorn is completely open source so \\n# make sure to report bugs to the issue tracker!.\\n\\n# Source: https://github.com/micropython/micropython-unicorn\\n\\n# The user and reset buttons along with the LEDs and pins\\n# on the pyboard below are fully functional. Unfortunately\\n# that\'s not quite the case for the clock speed approximation\\n# when delayed.\\n\\n# Try to write a script, paste some code or run a demo!\\n"], ')
        for demo in infile.read().split('#####\n'):
            outfile.write('["' + demo.split('\n')[0][2:] + '", "')
            for line in demo.split('\n')[1:-1]:
                outfile.write(line + '\\n')
            outfile.write('"], ')
        outfile.write(']);\n');
