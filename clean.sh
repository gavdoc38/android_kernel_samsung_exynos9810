#!/bin/bash
clear
export ARCH=arm64
export PLATFORM_VERSION=15
export ANDROID_MAJOR_VERSION=v
export PATH=$HOME/:$PATH

ARGS='
CC=/home/gavin/android/clang-aosp/bin/clang
CROSS_COMPILE=/home/gavin/android/gcc-64/bin/aarch64-linux-android-
CLANG_TRIPLE=aarch64-linux-gnu-
ARCH=arm64
'

make ${ARGS} clean && make ${ARGS} mrproper #to clean the source
