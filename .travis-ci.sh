# default tests

opam install -y mirage
git clone -b mirage-dev git://github.com/mirage/mirage-skeleton
cd mirage-skeleton
make MODE=xen && make clean
make MODE=unix && make clean
