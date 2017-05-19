MicroPython on Unicorn
======================

This repository contains an implementation of a virtual microcontroller based
on the Unicorn emulator, which is in turn based on QEMU.  It also contains a
port of MicroPython to that virtual microcontroller.  Unicorn has a JavaScript
version, unicorn.js, which is obtained by running Emscripten on the C version
of Unicorn, and allows the virtual microcontroller to run in the browser.  This
then gives a full MicroPython port running simulated-bare-metal in a web browser.
