import sys
import os

outfile = open('demo_scripts.js', 'w')
for filename in os.listdir():
    if filename[-9:] == '_demos.py':
        infile = open(filename, 'r')
        outfile.write('var ' + filename[:-9] + '_demos = new Map([["Choose a demo...", "# Write a script, paste some code or try a demo!\\n"], ')
        for demo in infile.read().split('#####\n'):
            outfile.write('["' + demo.split('\n')[0][2:] + '", "')
            for line in demo.split('\n')[1:-1]:
                outfile.write(line + '\\n')
            outfile.write('"], ')
        outfile.write(']);\n');
