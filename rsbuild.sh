#!/bin/sh


export STAGING_DIR=/home/aep/proj/captif//openwrt/staging_dir/
export PATH=$PATH:$STAGING_DIR/toolchain-mips_24kc_gcc-8.4.0_musl/bin/

export HOST_CC=gcc
export CC=mips-openwrt-linux-musl-gcc
export LD=mips-openwrt-linux-musl-gcc
export RUSTFLAGS="-C linker=mips-openwrt-linux-musl-gcc"

cargo +nightly-2019-11-17 build --target mips-unknown-linux-musl --release

mips-openwrt-linux-musl-strip target/mips-unknown-linux-musl/release/carrier-captif
