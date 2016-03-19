# default tests

opam install -y mirage
git clone git://github.com/mirage/mirage-www
cd mirage-www

for mode in unix xen; do
  export OPAMYES=1
  eval `opam config env`
  make MODE=$mode configure
  make MODE=$mode build
done
