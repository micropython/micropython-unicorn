var FLASH_ADDRESS = 0x08000000;
var FLASH_SIZE = 0x100000;
var RAM_ADDRESS = 0x20000000;
var MAX_RAM_SIZE = 0x40000;
var PERIPHERAL_ADDRESS = 0x40000000;
var PERIPHERAL_SIZE = 0x10000;
var UART0_TXR = 0x40000000;
var UART0_RXR = 0x40000004;
var UNICORN_CONTROLLER_PENDING = 0x40000100;
var UNICORN_CONTROLLER_EXCEPTION = 0x40000104;
var UNICORN_CONTROLLER_INTR_CHAR = 0x40000108;
var UNICORN_CONTROLLER_RAM_SIZE = 0x4000010c;
var UNICORN_CONTROLLER_STACK_SIZE = 0x40000110;
var UNICORN_CONTROLLER_IDLE = 0x40000114;
var GPIO_ODR = 0x40000200;
var GPIO_IDR = 0x40000204;
var RTC_TICKS_MS = 0x40000300;
var RTC_TICKS_US = 0x40000304;

var CYCLE_LIMIT = 39000;
var prev_binary = "";
var user_button_state = 0;
var epoch;

function int_to_bytes(n) {
    return new Uint8Array([n, n >> 8, n >> 16, n >> 24]);
}

function hook_read(handle, type, addr_lo, addr_hi, size,  value_lo, value_hi, user_data) {
    if (addr_lo == UART0_RXR) {
        if (next_char.length == 0) {
            try {
                emu.emu_stop();
                waiting = true;
            }
            catch (e){
                console.log(e, '\n');
            }
        } else { 
            n = next_char.pop();
            emu.mem_write(UART0_RXR, int_to_bytes(n));
        }
    } else if (addr_lo == UNICORN_CONTROLLER_RAM_SIZE) {
        emu.mem_write(UNICORN_CONTROLLER_RAM_SIZE, int_to_bytes(ram_size));
    } else if (addr_lo == UNICORN_CONTROLLER_STACK_SIZE) {
        emu.mem_write(UNICORN_CONTROLLER_STACK_SIZE, int_to_bytes(stack_size));
    } else if (addr_lo == GPIO_IDR) {
        emu.mem_write(GPIO_IDR, int_to_bytes(user_button_state));
    } else if (addr_lo == RTC_TICKS_MS) {
        emu.mem_write(RTC_TICKS_MS, int_to_bytes(parseInt(window.performance.now() - epoch, 10)));
    } else if (addr_lo == RTC_TICKS_US) {
        emu.mem_write(RTC_TICKS_US, int_to_bytes(parseInt((window.performance.now() - epoch) * 1000, 10)));
    }
    return;
}

function hook_write(handle, type, addr_lo, addr_hi, size,  value_lo, value_hi, user_data) {
    if (addr_lo == UART0_TXR) {
        if (value_lo == 4 && in_script) {
            if (in_error == true) {
                block_output = 1;
                in_error = false;
                in_script = false;
            } else {
                in_error = true;
            }
        } else if (block_output > 0) {
            block_output--;
        } else {
            term.write(String.fromCharCode(value_lo));
        }
    } else if (addr_lo == UNICORN_CONTROLLER_PENDING) {
        pending = value_lo;
    } else if (addr_lo == UNICORN_CONTROLLER_EXCEPTION) {
        exception = int_to_bytes(value_lo);
    } else if (addr_lo == UNICORN_CONTROLLER_INTR_CHAR) {
        ichr_addr = value_lo;
    } else if (addr_lo == UNICORN_CONTROLLER_IDLE) {
        if (idle) {
            idle = false;
            emu.emu_stop();
        } else {
            idle = true;
        }
    } else if (addr_lo == GPIO_ODR) {
        document.getElementById("red_led").style.display = ((value_lo & (1 << 0)) ? "inline" : "none");
        document.getElementById("green_led").style.display = ((value_lo & (1 << 1)) ? "inline" : "none");
        document.getElementById("yellow_led").style.display = ((value_lo & (1 << 2)) ? "inline" : "none");
        document.getElementById("blue_led").style.display = ((value_lo & (1 << 3)) ? "inline" : "none");
    }
    prev_val = value_lo;
    return;
}

function start() {
    set_editor_height();
    set_LEDs();

    binary = document.getElementById("binary").value;
    if (binary != prev_binary) {
        prev_binary = binary;
        demo_scripts = window[binary + "_demos"];
        set_demos();
        if (binary == "pyboard") {
            PYB.style.display = "inline";
        } else {
        PYB.style.display = "none";
        }
        var xhr = new XMLHttpRequest();
        xhr.open('GET', "firmware_" + binary + ".bin", true);
        xhr.responseType = 'arraybuffer';
        xhr.onload = function (e) {
            firmware = new Uint8Array(this.response);
            continue_start();
        }
        xhr.send();
    } else {
        continue_start();
    }
}

function continue_start() {
    emu = new uc.Unicorn(uc.ARCH_ARM, uc.MODE_THUMB);

    emu.mem_map(FLASH_ADDRESS, FLASH_SIZE, uc.PROT_ALL);
    emu.mem_map(RAM_ADDRESS, MAX_RAM_SIZE, uc.PROT_ALL);
    emu.mem_map(PERIPHERAL_ADDRESS, PERIPHERAL_SIZE, uc.PROT_ALL);

    addr = firmware[4] + (firmware[5] << 8) + (firmware[6] << 16) + (firmware[7] << 24);

    next_char = [];
    timestamp = new Date();
    cycles = 0;
    idle = false;
    waiting = false;
    block_output = 0;
    in_script = false;
    in_error = false;
    ram_size = Number(document.getElementById("ram_size").value);
    stack_size = Number(document.getElementById("stack_size").value);
    sp = RAM_ADDRESS + ram_size;

    emu.mem_write(FLASH_ADDRESS, firmware);
    emu.mem_write(FLASH_ADDRESS, int_to_bytes(sp));

    emu.hook_add(uc.HOOK_MEM_READ, hook_read, null, PERIPHERAL_ADDRESS, PERIPHERAL_ADDRESS + PERIPHERAL_SIZE);
    emu.hook_add(uc.HOOK_MEM_WRITE, hook_write, null, PERIPHERAL_ADDRESS, PERIPHERAL_ADDRESS + PERIPHERAL_SIZE);

    epoch = window.performance.now();

    execute();
}

function execute() {
    try {
        emu.emu_start(addr | 1, FLASH_ADDRESS + FLASH_SIZE, 0, CYCLE_LIMIT);
    }
    catch (er) {
        console.log(er, '\n');
        return;
    }
    cycles++;
    addr = emu.reg_read_i32(uc.ARM_REG_PC);
    if (!waiting) {
        requestAnimationFrame(execute);
    }
}

function inject(data) {
    keypress = data.split("").reverse().map(function(i) { return i.charCodeAt() });
    waiting = false;
    ichr = emu.mem_read(ichr_addr, 4);
    if (keypress[0] == ichr[0]) {
        emu.mem_write(pending, exception);
    } else {
        next_char = next_char.concat(keypress);
    }
    execute();
}

term.on('data', function (data) {
    inject(data);
});

reset_button.addEventListener("click", reset_emu);
PYB_reset_button.addEventListener("click", reset_emu);
PYB_user_button.addEventListener("mousedown", function() {
    user_button_state = 1;
});
PYB_user_button.addEventListener("mouseup", function() {
    user_button_state = 0;
});

function reset_emu() {
    term.reset();
    term.focus();
    start();
}

var run_button = document.getElementById("run_button");
run_button.addEventListener("click", function() {
    if (editor.getValue() == "") return
    inject(String.fromCharCode(3));
    inject(String.fromCharCode(1));
    inject(String.fromCharCode(4));
    while (!waiting) {
        execute();
    }
    term.reset();
    term.focus();
    block_output = 2;
    in_script = true;
    inject(editor.getValue());
    inject(String.fromCharCode(4));
    inject(String.fromCharCode(2));
});


function set_demos() {
    for (var i = demos.options.length - 1; i >= 0; i--) {
        demos.remove(i);
    }
    for (var [key, value] of demo_scripts) {
        demos.add(new Option(key, value));
    }
    editor.setValue(demos.value);
}

demos.addEventListener("change", function() {
    editor.setValue(demos.value);
});

function set_LEDs() {
    for (var led of ['red_led', 'green_led', 'yellow_led', 'blue_led']) {
        var img = document.getElementById(led);
        img.style.display = "none";
    }
}

function set_editor_height(){
    var editor_div = document.getElementById("editor_div");
    var viewport = document.querySelector('.xterm-viewport');
    editor_div.style.height = (parseFloat(viewport.style.lineHeight) * term.rows).toString() + "px";
}

window.addEventListener('resize', function() {
    term.fit();
    set_editor_height();
});

window.onload = function() {
    checkboxes = document.getElementsByClassName('components');
    for (var i = 0; i < checkboxes.length; i++) {
        checkboxes[i].addEventListener('change', function() {
            component = document.getElementById(this.value);
            component.style.display = this.checked ? "inline" : "none";
        });
    }
}

gauge = setInterval(function() {
    new_timestamp = new Date();
    if (!window.cycles) {
        speed = 0;
    } else {
        speed = (cycles * CYCLE_LIMIT / 1000000) / ((new_timestamp - timestamp) / 1000);
    }
    document.getElementById("clock_speed").innerHTML = speed.toFixed(2);
    timestamp = new_timestamp;
    cycles = 0;
}, 1000);

start();
