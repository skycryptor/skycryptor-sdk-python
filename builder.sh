#!/usr/bin/env bash
LIBNAME="cryptomagic"
LIBFILE="lib$LIBNAME.a"
SOURCE_DIR="`pwd`"

# Cloning and building C++ library
#git clone https://gitlab.com/skycryptor/cpp-tmp-crypto.git "$LIBNAME"
cp -r ../cpp-tmp-crypto/ cryptomagic
cd cryptomagic
rm -rf build
mkdir -p build && cd build

cmake ..
make -j4
cp "$LIBFILE" "$SOURCE_DIR/skycryptor"
cd "$SOURCE_DIR" && rm -rf "$LIBNAME"
