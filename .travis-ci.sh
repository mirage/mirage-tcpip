# default tests

wget https://raw.githubusercontent.com/ocaml/ocaml-travisci-skeleton/master/.travis-opam.sh
bash -ex .travis-opam.sh

# try building mirage-www in Unix and Xen modes

export OPAMYES=1
eval `opam config env`

opam repo add mirage-dev https://github.com/mirage/mirage-dev.git

git clone git://github.com/mirage/mirage-www
cd mirage-www

opam install mirage
make MODE=$MIRAGE_MODE configure
make MODE=$MIRAGE_MODE build
