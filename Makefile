NET ?= socket

ifneq "$(MIRAGE_NET)" ""
NET := $(MIRAGE_NET)
endif

.PHONY: all clean install test
.DEFAULT: all

all:
	echo hello $(NET)
	cd $(NET) && $(MAKE) all
clean:
	cd $(NET) && $(MAKE) clean
install:
	echo hello $(NET)
	cd $(NET) && $(MAKE) install
test:
	cd $(NET) && $(MAKE) test
