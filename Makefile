
.PHONY: build clean test install uninstall

build:
	dune build

test:
	dune runtest

install:
	dune install

uninstall:
	dune uninstall

clean:
	dune clean
