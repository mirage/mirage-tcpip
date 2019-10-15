# build the examples
export OPAMYES=1
eval `opam config env`

cd examples/unikernel
git log --oneline |head -5

opam install mirage
mirage configure -t $MIRAGE_MODE
make depend
make
