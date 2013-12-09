.PHONY: all _config build install doc clean

OS ?= unix
PREFIX ?= /usr/local
INSTALLDIR := $(DESTDIR)$(PREFIX)

all: build

_config:
	./cmd configure

build: _config
	./cmd build

install:
	./cmd install

doc: _config
	./cmd doc

clean:
	./cmd clean
