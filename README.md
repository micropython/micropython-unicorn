MicroPython on Unicorn
======================

This repository contains an implementation of a virtual microcontroller based
on the Unicorn emulator, which is in turn based on QEMU.  It also contains a
port of MicroPython to that virtual microcontroller.  Unicorn has a JavaScript
version, unicorn.js, which is obtained by running Emscripten on the C version
of Unicorn, and allows the virtual microcontroller to run in the browser.  This
then gives a full MicroPython port running simulated-bare-metal in a web browser.

For a running demo please visit https://micropython.org/unicorn

Build Instructions
------------------

```
$ git submodule update --init
```

Firmware binaries can be customized in the unicorn directory.

```
$ cd unicorn
$ make CONFIG=pyboard
```

The web page may be built using

```
$ cd www-emu
$ make
```

In order to build without using gzip (For example when testing with `$ python -m http.server`)

```
$ cd www-emu
$ make nogzip
```

There is a critical bug in unicorn-engine which is addressed [here](https://github.com/unicorn-engine/unicorn/pull/880). In order for full functionality apply the patch to a unicorn submodule within a unicorn.js repository and build normally.
