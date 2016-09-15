# default tests

opam install -y mirage
git clone -b mirage-dev git://github.com/mirage/mirage-skeleton
cd mirage-skeleton
make all
