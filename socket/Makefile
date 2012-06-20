.PHONY: all clean depend install

PREFIX ?= /usr/local
INSTALLDIR := $(DESTDIR)$(PREFIX)
INCLUDE := $(INSTALLDIR)/include/mirage
XEN_INCLUDE := $(INCLUDE)/xen

all: 
	./cmd configure
	./cmd build

install:
	./cmd install

clean:
	./cmd clean
