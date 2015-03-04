PACKAGE=tcpip
wget https://raw.githubusercontent.com/samoht/ocaml-travisci-skeleton/master/.travis-opam.sh
sh .travis-opam.sh

export OPAMYES=1
#opam remote add mirage git://github.com/mirage/mirage-dev
eval `opam config env`
prefix=`opam config var prefix`

./configure --prefix=$prefix --enable-tests
make
make test

opam install tcpip
# Fails because opam invokes `make configure`
# which invokes `opam install`, and OPAM isn't reentrant
#opam install mirage-www
# But still need the "mirage" command to configure mirage-www
opam install mirage

git clone git://github.com/mirage/mirage-www
cd mirage-www

if [ "$OCAML_VERSION" = "4.02" ]; then
  MODE=unix
else
  MODE=xen
fi

make MODE=$MODE configure
make MODE=$MODE build
