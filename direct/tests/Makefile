include Makefile.config

COMMON_SUBDIRS=

XEN_ONLY_SUBDIRS=iperf_self iperf_10k iperf_bigwrites iperf_smallwrites iperf_smallwrites_nodelay iperf_verifystream

ifeq ($(strip $(PLATFORM)),mirage-xen)
        SUBDIRS := $(COMMON_SUBDIRS) $(XEN_ONLY_SUBDIRS)
else
        SUBDIRS := $(COMMON_SUBDIRS)
endif

build: $(patsubst %,build-%,$(SUBDIRS))
clean: $(patsubst %,clean-%,$(SUBDIRS))
configure: $(patsubst %,configure-%,$(SUBDIRS))

build-%: configure-%
	cd $* && mirari build $(BACKEND)

configure-%:
	@echo "\n### $*: configure"
	cd $* && mirari configure $(BACKEND)

clean-%: 
	@echo "\n### $*: clean"
	if [ ! -r $*/Makefile ]; then \
		$(MAKE) configure-$* ;\
	fi ; \
	cd $* && mirari clean ;\
	$(RM) $*/myocamlbuild.ml $*/Makefile $*/*.xl main.native main.ml

run-%:
	cd $* && mirari run $(BACKEND)
