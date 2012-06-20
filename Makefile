NET ?= socket

ifneq "$(MIRAGE_NET)" ""
NET := $(MIRAGE_NET)
endif

.PHONY: all clean install test
.DEFAULT: all

all:
	cd $(NET) && $(MAKE) all
clean:
	cd $(NET) && $(MAKE) clean
install:
	cd $(NET) && $(MAKE) install
test:
	cd $(NET) && $(MAKE) test
