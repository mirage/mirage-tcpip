# default tests

wget https://raw.githubusercontent.com/ocaml/ocaml-travisci-skeleton/master/.travis-opam.sh
bash -ex .travis-opam.sh

# try building mirage-www in Unix and Xen modes

export OPAMYES=1
eval `opam config env`
prefix=`opam config var prefix`

git clone git://github.com/mirage/mirage-www
cd mirage-www

opam install mirage
make MODE=$MIRAGE_MODE configure
make MODE=$MIRAGE_MODE build
