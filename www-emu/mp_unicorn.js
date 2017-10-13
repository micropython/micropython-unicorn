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
var UNICORN_CONTROLLER_INSNS = 0x40000118;
var GPIO_ODR = 0x40000200;
var GPIO_IDR = 0x40000204;
var GPIO_X_ODR = 0x40000208;
var GPIO_X_IDR = 0x4000020c;
var GPIO_Y_ODR = 0x40000210;
var GPIO_Y_IDR = 0x40000214;
var SERVO_1_ANGLE = 0x40000218;
var SERVO_1_TIME = 0x4000021c;
var ADC_X_IDR = 0x40000220;
var ADC_Y_IDR = 0x40000250;
var RTC_TICKS_MS = 0x40000300;
var RTC_TICKS_US = 0x40000304;
var I2C_DATA = 0x40000400;
var I2C_COMMAND = 0x40000404;

var CYCLE_LIMIT = 50000;
var prev_binary = "";
var user_button_state = 0;
var epoch;
var servo_angle = 0;
var servo_target = 0;
var servo_speed = 1;
var LCD_WIDTH = 64;
var LCD_HEIGHT = 32;
var EPSILON = 0.5;
var TICK_INSN_RATIO = 2.5; // The approximate number of clock ticks per instruction found through experimentation
var HARD_I2C_SCL_X = 9
var HARD_I2C_SDA_X = 10

var pins_x = 0;
var pins_y = 0;

class I2C {
    constructor(address, scl, sda) {
        this.address = address;
        this.scl_gpio = scl[0]
        this.scl_pin = scl[1]
        this.sda_gpio = sda[0]
        this.sda_pin = sda[1]

        this.active = true;
        this.selected = false;
        this.rw = 0;
        this.data = 0;
        this.recv = 0;
        this.send = -1;
        this.buffer = []
    }

    write(val) {
        var scl = this.scl_gpio(this.scl_pin)
        var nscl = extract_pin(val, this.scl_pin);
        var sda = this.sda_gpio(this.sda_pin)
        var nsda = extract_pin(val, this.sda_pin);
        if (nsda != sda) {
            if (scl) {
                if (!nsda) { // Start bit
                    this.active = true;
                    this.selected = false;
                    this.recv = 0;
                    this.data = 0;
                    this.buffer = [];
                } else { // Stop bit
                    this.active = false;
                    if (this.selected) {
                        this.process();
                        this.selected = false;
                    }
                }
            }
        }
        if (nscl != scl && this.active) {
            if (nscl) {
                if (this.recv < 8) {
                    this.data = (this.data << 1) + sda;
                    this.recv++;
                } else {
                    if (this.selected) { // Receive data
                        this.buffer.push(this.data);
                        this.send = 0;
                        this.data = 0;
                        this.recv = 0;
                    } else if ((this.data >> 1) == this.address) {
                        this.selected = true;
                        this.rw = this.data & 1;
                        this.send = 0;
                        this.data = 0;
                        this.recv = 0;
                    } else {
                        this.active = false;
                    }
                }
            } else if (!nscl) {
                this.send = -1;
            }
        }
    }

    read(GPIO, pins) {
        if (this.sda_gpio.name != GPIO || this.send == -1) {
            return pins;
        }
        pins = set_pin(pins, this.sda_pin, this.send);
        return pins;
    }

    process() {
    }
}

class LCD extends I2C {
    process() {
        var ctx = lcd_unicorn.getContext('2d');
        ctx.fillStyle = 'rgb(255, 255, 255)';
        for (var j = 0; j < LCD_HEIGHT; j++) {
            for (var i = 0; i < LCD_WIDTH / 8; i++) {
                if (this.buffer.length == 0) {
                    return;
                }
                var bite = this.buffer.shift();
                for (var k = 7; k >= 0; k--) {
                    if (bite >> k & 1) {
                        ctx.fillRect(i * 4 * 8 + ((7 - k) * 4), j * 4, 4, 4);
                    } else {
                        ctx.clearRect(i * 4 * 8 + ((7 - k) * 4), j * 4, 4, 4);
                    }
                }
            }
        }
    }
}

var i2c_devices = new Map([[8, new LCD(8, [X, HARD_I2C_SCL_X], [X, HARD_I2C_SDA_X])]])

function write_to_i2c_devices(pins) {
    // No X Y split?
    for (var key of i2c_devices.keys()) {
        i2c_devices.get(key).write(pins);
    }
}

function set_pin(pins, pin_no, val) {
    if (val) {
        return pins | (1 << pin_no);
    } else {
        return pins & ~(1 << pin_no);
    }
}

function hard_i2c_write(scl, sda) {
    var pins = pins_x;
    pins = set_pin(pins, HARD_I2C_SCL_X, scl);
    pins = set_pin(pins, HARD_I2C_SDA_X, sda);
    write_to_i2c_devices(pins);
    pins_x = pins;
}

function extract_pin(pins, n) {
    return ((pins & (1 << n)) ? 1 : 0);
}

function X(n) {
    return extract_pin(pins_x, n);
}

function Y(n) {
    return extract_pin(pins_y, n);
}

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
    } else if (addr_lo == UNICORN_CONTROLLER_INSNS) {
        emu.mem_write(UNICORN_CONTROLLER_INSNS, int_to_bytes(insns));
    } else if (addr_lo == GPIO_IDR) {
        emu.mem_write(GPIO_IDR, int_to_bytes(user_button_state));
    } else if (addr_lo == GPIO_X_IDR) {
        for (var key of i2c_devices.keys()) {
            pins_x = i2c_devices.get(key).read('X', pins_x);
        }
        emu.mem_write(GPIO_X_IDR, int_to_bytes(pins_x));
        emu.mem_write(GPIO_X_ODR, int_to_bytes(pins_x));
    } else if (addr_lo == GPIO_Y_IDR) {
        for (var key of i2c_devices.keys()) {
            pins_y = i2c_devices.get(key).read('Y', pins_y);
        }
        emu.mem_write(GPIO_Y_IDR, int_to_bytes(pins_y));
        emu.mem_write(GPIO_Y_ODR, int_to_bytes(pins_y));
    } else if (addr_lo == SERVO_1_ANGLE) {
        emu.mem_write(SERVO_1_ANGLE, int_to_bytes(servo_angle));
    } else if (addr_lo >= ADC_X_IDR && addr_lo < ADC_X_IDR + 0x30) {
    } else if (addr_lo >= ADC_Y_IDR && addr_lo < ADC_Y_IDR + 0x30) {
        if (addr_lo == ADC_Y_IDR + (3 * 4)) { //Pin Y4 connected to ADC slider
            emu.mem_write(addr_lo, int_to_bytes((adc_slider.value * 255) / 100));
        }
    } else if (addr_lo == RTC_TICKS_MS) {
        emu.mem_write(RTC_TICKS_MS, int_to_bytes(parseInt(window.performance.now() - epoch, 10)));
    } else if (addr_lo == RTC_TICKS_US) {
        emu.mem_write(RTC_TICKS_US, int_to_bytes(parseInt((window.performance.now() - epoch) * 1000, 10)));
    } else if (addr_lo == I2C_DATA) {
        for (var key of i2c_devices.keys()) {
            pins_x = i2c_devices.get(key).read('X', pins_x);
        }
        emu.mem_write(I2C_DATA, int_to_bytes(X(HARD_I2C_SDA_X)));
        hard_i2c_write(0, X(HARD_I2C_SDA_X));
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
        document.getElementById("red_led").style.display = extract_pin(value_lo, 0) ? "inline" : "none";
        document.getElementById("green_led").style.display = extract_pin(value_lo, 1) ? "inline" : "none";
        document.getElementById("yellow_led").style.display = extract_pin(value_lo, 2) ? "inline" : "none";
        document.getElementById("blue_led").style.display = extract_pin(value_lo, 3) ? "inline" : "none";
    } else if (addr_lo == GPIO_X_ODR) {
        write_to_i2c_devices(value_lo);
        pins_x = value_lo;
        emu.mem_write(GPIO_X_IDR, int_to_bytes(pins_x));
    } else if (addr_lo == GPIO_Y_ODR) {
        write_to_i2c_devices(value_lo);
        pins_y = value_lo;
        emu.mem_write(GPIO_X_IDR, int_to_bytes(pins_y));
        document.getElementById("pin_led_on").style.display = extract_pin(value_lo, 12) ? "inline" : "none";
    } else if (addr_lo == SERVO_1_ANGLE) {
        servo_target = value_lo;
        rotate_servo();
    } else if (addr_lo == SERVO_1_TIME) {
        servo_speed = (Math.abs(servo_angle - servo_target) / (value_lo / 1000)) / 60;
    } else if (addr_lo == I2C_DATA) {
        for (var i = 7; i >= 0; i--) {
            var j = (value_lo >> i) & 1;
            for (var k = 0; k < 3; k++) {
                hard_i2c_write(k % 2, j);
            }
        }
        hard_i2c_write(0, 1);
        hard_i2c_write(1, 1);
    } else if (addr_lo == I2C_COMMAND) {
        if (value_lo == 0) {
            hard_i2c_write(1, 1);
            hard_i2c_write(1, 0);
        } else if (value_lo == 1) {
            hard_i2c_write(1, 0);
            hard_i2c_write(1, 1);
        }
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
    insns = 0;
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
        return 1;
    }
    addr = emu.reg_read_i32(uc.ARM_REG_PC);
    if (!waiting) {
        cycles++;
        insns += CYCLE_LIMIT * TICK_INSN_RATIO;
        requestAnimationFrame(execute);
    }
    return 0;
}

function inject(data) {
    keypress = data.split("").reverse().map(function(i) { return i.charCodeAt() });
    waiting = false;
    ichr = emu.mem_read(ichr_addr, 4);
    if (keypress[0] == ichr[0]) {
        emu.mem_write(pending, exception);
    } else {
        next_char = keypress.concat(next_char);
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
        if (execute()) {
            return;
        }
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
    checkboxes = document.getElementsByClassName('components');
    for (var i = 0; i < checkboxes.length; i++) {
        var check = new Event('change');
        checkboxes[i].checked = (demos.value.search(checkboxes[i].value) != -1) ? true : false;
        checkboxes[i].dispatchEvent(check);
    }
    if (demos.value.search("# PERIPHERALS: ") != -1) {
        editor.setValue(demos.value.slice(demos.value.search("\n") + 1));
    } else {
        editor.setValue(demos.value);
    }
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

function rotate_servo() {
    if (servo_angle != servo_target) {
        servo_angle += servo_angle < servo_target ? servo_speed : -servo_speed;
        if (servo_angle > 90)
            servo_angle = 90;
        if (servo_angle < -90)
            servo_angle = -90;
        if (Math.abs(servo_angle - servo_target) < EPSILON)
            servo_angle = servo_target;
        pin_servo_blade.style.transform = "rotate(" + servo_angle.toString(10) + "deg)";
        requestAnimationFrame(rotate_servo);
    } else {
        servo_speed = 1;
    }
}

gauge = setInterval(function() {
    new_timestamp = new Date();
    if (!window.cycles) {
        speed = 0;
    } else {
        speed = (cycles * CYCLE_LIMIT * TICK_INSN_RATIO / 1000000) / ((new_timestamp - timestamp) / 1000);
    }
    document.getElementById("clock_speed").innerHTML = speed.toFixed(2);
    timestamp = new_timestamp;
    cycles = 0;
}, 1000);

start();
