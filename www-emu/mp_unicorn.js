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

var CYCLE_LIMIT = 40000;

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
    }
    return;
}

function hook_write(handle, type, addr_lo, addr_hi, size,  value_lo, value_hi, user_data) {
    if (addr_lo == UART0_TXR) {
        if (in_script > 0) {
            in_script--;
        } else {
            term.write(String.fromCharCode(value_lo));
        }
    } else if (addr_lo == UNICORN_CONTROLLER_PENDING) {
        pending = value_lo;
    } else if (addr_lo == UNICORN_CONTROLLER_EXCEPTION) {
        exception = int_to_bytes(value_lo);
    } else if (addr_lo == UNICORN_CONTROLLER_INTR_CHAR) {
        ichr_addr = value_lo;
    }
    return;
}

function start() {
    binary = document.getElementById("binary").value;
    var xhr = new XMLHttpRequest();
    xhr.open('GET', binary, true);
    xhr.responseType = 'arraybuffer';
    xhr.onload = function (e) {
        firmware = new Uint8Array(this.response);
        continue_start();
    }
    xhr.send();
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
    waiting = false;
    in_script = 0;
    ram_size = Number(document.getElementById("ram_size").value);
    stack_size = Number(document.getElementById("stack_size").value);
    sp = RAM_ADDRESS + ram_size;

    emu.mem_write(FLASH_ADDRESS, firmware);
    emu.mem_write(FLASH_ADDRESS, int_to_bytes(sp));

    emu.hook_add(uc.HOOK_MEM_WRITE, hook_write, null, PERIPHERAL_ADDRESS, PERIPHERAL_ADDRESS + PERIPHERAL_SIZE);
    emu.hook_add(uc.HOOK_MEM_READ, hook_read, null, PERIPHERAL_ADDRESS, PERIPHERAL_ADDRESS + PERIPHERAL_SIZE);
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

var reset_button = document.getElementById("reset_button");
reset_button.addEventListener("click", function() {
    term.reset();
    term.focus();
    start();
});

var run_button = document.getElementById("run_button");
run_button.addEventListener("click", function() {
    inject(String.fromCharCode(1));
    inject(String.fromCharCode(4));
    term.reset();
    term.focus();
    in_script = 2;
    inject(editor.getValue());
    inject(String.fromCharCode(4));
    inject(String.fromCharCode(2));
});

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
