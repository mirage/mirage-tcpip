# default tests

set -x
opam repo set-url default git://github.com/mirage/opam-repository#minios-xen
opam install -y mirage
git clone -b mirage-dev git://github.com/mirage/mirage-skeleton
cd mirage-skeleton
export MINIOS_COMPILE_ARCH=x86_64
make MODE=xen && make clean
make MODE=unix && make clean
