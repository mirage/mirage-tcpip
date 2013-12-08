.PHONY: all _config build install doc clean

PREFIX ?= /usr/local
INSTALLDIR := $(DESTDIR)$(PREFIX)
INCLUDE := $(INSTALLDIR)/include/mirage
XEN_INCLUDE := $(INCLUDE)/xen

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
