BUILD = build
UNICORN_BUILDS = ../unicorn/build_

INDEX = index.html
MP_UNICORN = mp_unicorn.js
FIRMWARE = firmware_
UNICORN_JS = unicorn-arm.min.js
XTERM_JS = xterm.js
XTERM_CSS = xterm.css
CODEMIRROR_JS = codemirror.js
CODEMIRROR_CSS = codemirror.css

# Using xterm.js release 2.6.0 and latest unicorn.js as no current release is functional
XTERM_HASH = 2221f70ff05ba2af42ee0d26bed2f75dafe2d116
UNICORN_JS_LINK = https://raw.githubusercontent.com/AlexAltea/unicorn.js/master/dist/$(UNICORN_JS)
XTERM_JS_LINK = https://raw.githubusercontent.com/sourcelair/xterm.js/$(XTERM_HASH)/dist/$(XTERM_JS)
XTERM_CSS_LINK = https://raw.githubusercontent.com/sourcelair/xterm.js/$(XTERM_HASH)/dist/$(XTERM_CSS)

all: gzip

gzip: $(BUILD) $(BUILD)/$(UNICORN_JS).gz $(BUILD)/$(XTERM_JS).gz $(BUILD)/$(XTERM_CSS).gz $(BUILD)/$(CODEMIRROR_JS).gz $(BUILD)/$(CODEMIRROR_CSS).gz copy
	rm -f $(BUILD)/$(MP_UNICORN).gz
	gzip $(BUILD)/$(MP_UNICORN)

# Make clean before switching between gzip and nogzip builds
nogzip: $(BUILD) $(BUILD)/$(UNICORN_JS) $(BUILD)/$(XTERM_JS) $(BUILD)/$(XTERM_CSS) $(BUILD)/$(CODEMIRROR_JS) $(BUILD)/$(CODEMIRROR_CSS) copy

copy:
	cp $(INDEX) $(BUILD)
	cp $(MP_UNICORN) $(BUILD)
	-cp $(UNICORN_BUILDS)minimal/$(FIRMWARE)minimal.bin $(BUILD)
	-cp $(UNICORN_BUILDS)features/$(FIRMWARE)features.bin $(BUILD)

$(BUILD):
	mkdir $(BUILD)

$(BUILD)/$(UNICORN_JS):
	wget -P $(BUILD) $(UNICORN_JS_LINK)

$(BUILD)/$(UNICORN_JS).gz:
	wget -P $(BUILD) $(UNICORN_JS_LINK)
	gzip $(BUILD)/$(UNICORN_JS)

$(BUILD)/$(XTERM_JS):
	wget -P $(BUILD) $(XTERM_JS_LINK)

$(BUILD)/$(XTERM_JS).gz:
	wget -P $(BUILD) $(XTERM_JS_LINK)
	gzip $(BUILD)/$(XTERM_JS)

$(BUILD)/$(XTERM_CSS):
	wget -P $(BUILD) $(XTERM_CSS_LINK)

$(BUILD)/$(XTERM_CSS).gz:
	wget -P $(BUILD) $(XTERM_CSS_LINK)
	gzip $(BUILD)/$(XTERM_CSS)

$(BUILD)/$(CODEMIRROR_JS):
	cp $(CODEMIRROR_JS) $(BUILD)

$(BUILD)/$(CODEMIRROR_JS).gz:
	cp $(CODEMIRROR_JS) $(BUILD)
	gzip $(BUILD)/$(CODEMIRROR_JS)

$(BUILD)/$(CODEMIRROR_CSS):
	cp $(CODEMIRROR_CSS) $(BUILD)

$(BUILD)/$(CODEMIRROR_CSS).gz:
	cp $(CODEMIRROR_CSS) $(BUILD)
	gzip $(BUILD)/$(CODEMIRROR_CSS)

.PHONY: clean

clean:
	rm -rf $(BUILD)
