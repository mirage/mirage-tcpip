# default tests

unset EXTRA_DEPS
opam repo set-url default git://github.com/mirage/opam-repository#minios-xen
uname -m
opam update
echo XX minios
opam install -v minios-xen
opam install -y mirage
git clone -b mirage-dev git://github.com/mirage/mirage-skeleton
cd mirage-skeleton
export MINIOS_COMPILE_ARCH=x86_64
make MODE=xen && make clean
make MODE=unix && make clean
