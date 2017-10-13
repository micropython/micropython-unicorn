# Select the configuration to build with, defaulting to "minimal"
CONFIG ?= minimal
ifeq ($(wildcard mpconfigport_$(CONFIG).h),)
$(error Invalid CONFIG specified)
endif

BUILD = build_$(CONFIG)
FIRMWARE = $(BUILD)/firmware_$(CONFIG)

include ../micropython/py/mkenv.mk

# qstr definitions (must come before including py.mk)
QSTR_DEFS = qstrdefsport.h

# include py core make definitions
include $(TOP)/py/py.mk

CROSS_COMPILE = arm-none-eabi-

INC += -I.
INC += -I$(TOP)
INC += -I$(BUILD)

CFLAGS_CORTEX_M4 = -mthumb -mtune=cortex-m4 -mcpu=cortex-m4 -mfloat-abi=soft -fsingle-precision-constant -Wdouble-promotion
CFLAGS = $(INC) -Wall -Werror -std=c99 -nostdlib $(CFLAGS_CORTEX_M4) $(COPT)
CFLAGS += -DMP_CONFIGFILE="<mpconfigport_$(CONFIG).h>"

#Debugging/Optimization
ifeq ($(DEBUG), 1)
CFLAGS += -O0 -ggdb
else
CFLAGS += -Os -DNDEBUG
endif

LDFLAGS = -nostdlib -T unicorn.ld -Map=$@.map --cref
LIBS = $(shell $(CC) $(CFLAGS) -print-libgcc-file-name)

# Remove uncalled code from the final image.
CFLAGS += -fdata-sections -ffunction-sections
LDFLAGS += --gc-sections

SRC_C = \
	main.c \
	uart.c \
	help.c \
	mphalport.c \
	modutime.c \
	modmachine.c \
	machine_pin.c \
	machine_i2c.c \
	modpyb.c \
	pyb_led.c \
	pyb_switch.c \
	pyb_servo.c \
	pyb_adc.c \
	lib/utils/stdout_helpers.c \
	lib/utils/interrupt_char.c \
	lib/utils/pyexec.c \
	lib/libc/string0.c \
	lib/libm/math.c \
	lib/libm/fmodf.c \
	lib/libm/nearbyintf.c \
	lib/libm/ef_sqrt.c \
	lib/libm/log1pf.c \
	lib/libm/acoshf.c \
	lib/libm/asinhf.c \
	lib/libm/atanhf.c \
	lib/libm/kf_rem_pio2.c \
	lib/libm/kf_sin.c \
	lib/libm/kf_cos.c \
	lib/libm/kf_tan.c \
	lib/libm/ef_rem_pio2.c \
	lib/libm/erf_lgamma.c \
	lib/libm/sf_sin.c \
	lib/libm/sf_cos.c \
	lib/libm/sf_tan.c \
	lib/libm/sf_frexp.c \
	lib/libm/sf_modf.c \
	lib/libm/sf_ldexp.c \
	lib/libm/sf_erf.c \
	lib/libm/wf_lgamma.c \
	lib/libm/wf_tgamma.c \
	lib/libm/asinfacosf.c \
	lib/libm/atanf.c \
	lib/libm/atan2f.c \
	lib/mp-readline/readline.c \

# List of sources for qstr extraction
SRC_QSTR += $(SRC_C)

OBJ = $(PY_O) $(addprefix $(BUILD)/, $(SRC_C:.c=.o))

all: $(FIRMWARE).bin

$(FIRMWARE).elf: $(OBJ)
	$(ECHO) "LINK $@"
	$(Q)$(LD) $(LDFLAGS) -o $@ $^ $(LIBS)
	$(Q)$(SIZE) $@

$(FIRMWARE).bin: $(FIRMWARE).elf
	$(Q)$(OBJCOPY) -O binary -j .isr_vector -j .text -j .data $^ $@

include $(TOP)/py/mkrules.mk
