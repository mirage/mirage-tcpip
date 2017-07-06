# default tests

wget https://raw.githubusercontent.com/ocaml/ocaml-travisci-skeleton/master/.travis-opam.sh
bash -ex .travis-opam.sh

# try building mirage-www in the mode set by the build matrix

export OPAMYES=1
eval `opam config env`

git clone -b master git://github.com/mirage/mirage-www
cd mirage-www
git log --oneline |head -5

opam install mirage
make MODE=$MIRAGE_MODE configure
make MODE=$MIRAGE_MODE depend
make MODE=$MIRAGE_MODE build
