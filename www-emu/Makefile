BUILD = build
UNICORN_BUILD = ../unicorn/build

INDEX = index.html
MP_UNICORN = mp_unicorn.js
FIRMWARE = firmware.bin
UNICORN_JS = unicorn-arm.min.js
XTERM_JS = xterm.js
XTERM_CSS = xterm.css

# Using xterm.js release 2.6.0 and latest unicorn.js as no current release is functional
XTERM_HASH = 2221f70ff05ba2af42ee0d26bed2f75dafe2d116
UNICORN_JS_LINK = https://raw.githubusercontent.com/AlexAltea/unicorn.js/master/dist/$(UNICORN_JS)
XTERM_JS_LINK = https://raw.githubusercontent.com/sourcelair/xterm.js/$(XTERM_HASH)/dist/$(XTERM_JS)
XTERM_CSS_LINK = https://raw.githubusercontent.com/sourcelair/xterm.js/$(XTERM_HASH)/dist/$(XTERM_CSS)

all: gzip

gzip: $(BUILD) $(BUILD)/$(UNICORN_JS).gz $(BUILD)/$(XTERM_JS).gz $(BUILD)/$(XTERM_CSS).gz copy
	gzip $(BUILD)/$(MP_UNICORN)

# Make clean before switching between gzip and nogzip builds
nogzip: $(BUILD) $(BUILD)/$(UNICORN_JS) $(BUILD)/$(XTERM_JS) $(BUILD)/$(XTERM_CSS) copy

copy:
	cp $(INDEX) $(BUILD)
	cp $(MP_UNICORN) $(BUILD)
	cp $(UNICORN_BUILD)/$(FIRMWARE) $(BUILD)

$(BUILD):
	mkdir $(BUILD)

$(BUILD)/$(UNICORN_JS):
	wget -P $(BUILD) $(UNICORN_JS_LINK)

$(BUILD)/$(UNICORN_JS).gz: $(BUILD)/$(UNICORN_JS)
	gzip $(BUILD)/$(UNICORN_JS)

$(BUILD)/$(XTERM_JS):
	wget -P $(BUILD) $(XTERM_JS_LINK)

$(BUILD)/$(XTERM_JS).gz: $(BUILD)/$(XTERM_JS)
	gzip $(BUILD)/$(XTERM_JS)

$(BUILD)/$(XTERM_CSS):
	wget -P $(BUILD) $(XTERM_CSS_LINK)

$(BUILD)/$(XTERM_CSS).gz: $(BUILD)/$(XTERM_CSS)
	gzip $(BUILD)/$(XTERM_CSS)

.PHONY: clean

clean:
	rm -rf $(BUILD)
