BUILD = build
UNICORN_BUILDS = ../unicorn/build_
IMAGES = images

DEMO_GEN = demo_gen.py

INDEX = index.html
MP_UNICORN_JS = mp_unicorn.js
MP_UNICORN_CSS = mp_unicorn.css
FIRMWARE = firmware_
UNICORN_JS = unicorn-arm.min.js
XTERM_JS = xterm.js
XTERM_CSS = xterm.css
FIT_JS = fit.js
CODEMIRROR_JS = codemirror.js
CODEMIRROR_CSS = codemirror.css
BOOTSTRAP_CSS = bootstrap.min.css
JQUERY_JS = jquery-3.2.1.min.js
IMAGEMAPSTER_JS = jquery.imagemapster.min.js
DEMO_SCRIPTS = demo_scripts.js

# Using xterm.js release 2.6.0 and latest unicorn.js as no current release is functional
XTERM_HASH = 2221f70ff05ba2af42ee0d26bed2f75dafe2d116
UNICORN_JS_LINK = https://raw.githubusercontent.com/AlexAltea/unicorn.js/master/dist/$(UNICORN_JS)
XTERM_JS_LINK = https://raw.githubusercontent.com/sourcelair/xterm.js/$(XTERM_HASH)/dist/$(XTERM_JS)
XTERM_CSS_LINK = https://raw.githubusercontent.com/sourcelair/xterm.js/$(XTERM_HASH)/dist/$(XTERM_CSS)
FIT_JS_LINK = https://raw.githubusercontent.com/sourcelair/xterm.js/$(XTERM_HASH)/dist/addons/fit/$(FIT_JS)

all: gzip

gzip: $(BUILD) $(BUILD)/$(UNICORN_JS).gz $(BUILD)/$(XTERM_JS).gz $(BUILD)/$(XTERM_CSS).gz $(BUILD)/$(FIT_JS).gz $(BUILD)/$(CODEMIRROR_JS).gz $(BUILD)/$(CODEMIRROR_CSS).gz $(BUILD)/$(BOOTSTRAP_CSS).gz $(BUILD)/$(JQUERY_JS).gz $(BUILD)/$(IMAGEMAPSTER_JS).gz copy
	rm -f $(BUILD)/$(MP_UNICORN_JS).gz
	gzip $(BUILD)/$(MP_UNICORN_JS)

# Make clean before switching between gzip and nogzip builds
nogzip: $(BUILD) $(BUILD)/$(UNICORN_JS) $(BUILD)/$(XTERM_JS) $(BUILD)/$(XTERM_CSS) $(BUILD)/$(FIT_JS) $(BUILD)/$(CODEMIRROR_JS) $(BUILD)/$(CODEMIRROR_CSS) $(BUILD)/$(BOOTSTRAP_CSS) $(BUILD)/$(JQUERY_JS) $(BUILD)/$(IMAGEMAPSTER_JS) copy

copy:
	cp $(INDEX) $(BUILD)
	cp $(MP_UNICORN_JS) $(BUILD)
	cp $(MP_UNICORN_CSS) $(BUILD)
	cp -r $(IMAGES) $(BUILD)
	-cp $(UNICORN_BUILDS)*/$(FIRMWARE)*.bin $(BUILD)
	python $(DEMO_GEN)
	mv $(DEMO_SCRIPTS) $(BUILD)

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

$(BUILD)/$(FIT_JS):
	wget -P $(BUILD) $(FIT_JS_LINK)

$(BUILD)/$(FIT_JS).gz:
	wget -P $(BUILD) $(FIT_JS_LINK)
	gzip $(BUILD)/$(FIT_JS)

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

$(BUILD)/$(BOOTSTRAP_CSS):
	cp $(BOOTSTRAP_CSS) $(BUILD)

$(BUILD)/$(BOOTSTRAP_CSS).gz:
	cp $(BOOTSTRAP_CSS) $(BUILD)
	gzip $(BUILD)/$(BOOTSTRAP_CSS)

$(BUILD)/$(JQUERY_JS):
	cp $(JQUERY_JS) $(BUILD)

$(BUILD)/$(JQUERY_JS).gz:
	cp $(JQUERY_JS) $(BUILD)
	gzip $(BUILD)/$(JQUERY_JS)

$(BUILD)/$(IMAGEMAPSTER_JS):
	cp $(IMAGEMAPSTER_JS) $(BUILD)

$(BUILD)/$(IMAGEMAPSTER_JS).gz:
	cp $(IMAGEMAPSTER_JS) $(BUILD)
	gzip $(BUILD)/$(IMAGEMAPSTER_JS)

.PHONY: clean

clean:
	rm -rf $(BUILD)
