#!/bin/sh

UTILS=binutils-gdb

BUILD=$(pwd)/../build
mkdir -p ../build

if [ -z $1 ]
then
./configure --enable-maintainer-mode --disable-option-checking \
			--target=mk-unknown-elf \
			--enable-debug \
			--disable-gnulib \
			--disable-sim \
			--disable-gdb \
			--disable-gold \
			--disable-gas \
			--disable-werror \
			--disable-64-bit-bfd \
			--disable-nls \
			--disable-gprof \
			--enable-deterministic-archives \
			--enable--interwork \
			--enable-plugins \
			--enable-ld \
			--prefix=${BUILD}
fi

make -j6
make install

# NOTE
# to clean run:
#
# rm binutils-gdb/*/config.cache
