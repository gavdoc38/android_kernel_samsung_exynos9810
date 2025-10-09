#!/bin/bash
clear
export ARCH=arm64
export PLATFORM_VERSION=15
export ANDROID_MAJOR_VERSION=v
export PATH=$HOME/:$PATH
export KBUILD_BUILD_TIMESTAMP='Fri Oct 3 17:24:40 CEST 2025'
export KBUILD_BUILD_USER='build-user'
export KBUILD_BUILD_HOST='build-host'

ARGS='
CC=/home/gavin/android/clang-aosp/bin/clang
CROSS_COMPILE=/home/gavin/android/gcc-64/bin/aarch64-linux-android-
CLANG_TRIPLE=aarch64-linux-gnu-
ARCH=arm64
'

make ${ARGS} clean && make ${ARGS} mrproper #to clean the source
make ${ARGS} exynos9810-star2lte_defconfig #making your current kernel config
#make ${ARGS} menuconfig #editing the kernel config via gui
make ${ARGS} -j$(nproc --all) #to compile the kernel

cd /home/gavin/android/out/
cp /home/gavin/android/android_kernel_samsung_exynos9810/arch/arm64/boot/Image kernel
../libmagiskboot.so repack boot.img
