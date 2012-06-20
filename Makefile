MODE ?= direct

.PHONY: all clean install test
.DEFAULT: all

all:
	cd $(MODE) && $(MAKE) all
clean:
	cd $(MODE) && $(MAKE) clean
install:
	cd $(MODE) && $(MAKE) install
test:
	cd $(MODE) && $(MAKE) test
