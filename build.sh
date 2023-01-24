#!/bin/bash

# This script originates from:
# https://github.com/jbech-linaro/optee_examples/blob/build_using_shell/build.sh

# 2018-10-05: Note that due to the recent transition from using cpio directly to
# now use Buildroot instead things have been a bit more complicated building
# using something like this.
# A normal "make" in build.git will put all OP-TEE binaries (except optee_os)
# in: # <root>/out-br/...
#
# A difference now is that the public headers as tee_client_api.h and the
# library libteec.so no longer resides under the same root. Therefore all lines
# having something with $(TEEC_EXPORT)/{include/lib} in all Makefile in this git
# cannot point to the <root>/out-br/ git.
#
# As of now we still support building running:
#   $ make optee-os
#   $ make optee-client

# in build.git. Doing so will build and put the h-files needed in the old
# locations. So, to build using this shell script it's not sufficient to just
# run make. One also needs to run the optee-os and optee_client target, i.e.
#
# 1. In build.git: make
# 2. In build.git: make optee-os
# 2. In build.git: make optee-client
# 3. In optee-widevine-ref.git: ./build.sh
#
# Note! Don't forget to change paths from <root>/out-br/... to this folder
# in case you run GDB or have script doing scp with host + TA's.

clear
echo -e "build.sh\n--------"
echo -e "args: $@\n"

CURDIR=`pwd`

# This expects that this is place as a first level folder relative to the other
# OP-TEE folder in a setup using default repo configuration as described by the
# documentation in optee_os (README.md)
ROOT=${PWD}
ROOT=`dirname $ROOT`

TARGET=locki
BEAR=
CLEAN=
SYNC=
SHOW_GDB_INFO=true
MOUNT_DIR=

# Can change over time (look for "ELF load address <xyz>" in secure UART)
LOAD_ADDRESS=0x116000

# Path to the toolchain
export PATH=${ROOT}/toolchains/aarch32/bin:${ROOT}/toolchains/aarch64/bin:$PATH

# Path to the TA-DEV-KIT coming from optee_os
export TA_DEV_KIT_DIR=${ROOT}/optee_os/out/arm/export-ta_arm64

ARCH=aarch64
OS=linux
ABI=gnu
OS_TYPE=64
VENDOR=buildroot
BUILDROOT_OUT=${ROOT}/out-br

# Path to the client library (GP Client API), see main comment above.
export TEEC_EXPORT=${BUILDROOT_OUT}/host/${ARCH}-${VENDOR}-${OS}-${ABI}/sysroot/usr

export PLATFORM=vexpress
export PLATFORM_FLAVOR=qemu_virt

#export CROSS_COMPILE=arm-linux-gnueabihf-
CROSS_COMPILE=${ARCH}-${OS}-${ABI}-
export CROSS_COMPILE=${BUILDROOT_OUT}/host/bin/${CROSS_COMPILE}

while getopts a:bcd:f:gil:p:sht:v: option
do
	case "${option}"
		in
		a) echo "Building for AArch${OPTARG}"
		   if [ "${OPTARG}" -eq "32" ] ; then
			export CROSS_COMPILE=${BUILDROOT_OUT}/host/bin/arm-linux-gnueabihf-
			export TA_DEV_KIT_DIR=${ROOT}/optee_os/out/arm/export-ta_arm32
		   fi
		   ;;
		b) echo "Generate json file with bear"
		   BEAR='bear --append --'
		   ;;

		c) CLEAN=clean;;

		d) MOUNT_DIR="NOT_IMPLEMENTED";;

		f) export PLATFORM_FLAVOR=${OPTARG};;

		g) SHOW_GDB_INFO=;;

		i) echo "Available example TA/Host applications: "
		   ls -d */ | cut -f1 -d'/' | grep -v docs
		   echo ""
		   exit
		   ;;

		l) LOAD_ADDRESS=${OPTARG};;

		p) export PLATFORM=${OPTARG};;

		s) SYNC=true;;

		t) TARGET=${OPTARG};;

		v) V=${OPTARG};;

		h) echo " -a <32, 64>            default: 64 (architecture)"
		   echo " -c                     clean"
		   echo " -d                     mount point to shared folder with TA's"
		   echo " -f <PLATFORM_FLAVOR>   default: ${PLATFORM_FLAVOR}"
		   echo " -g                     hide GDB string"
		   echo " -i                     list all available TA/Host applications"
		   echo " -l                     Load address of the TA (see secure UART)"
		   echo " -p <PLATFORM>          default: ${PLATFORM}"
		   echo " -s                     run sync (QEMU_VIRTFS_ENABLE=y)"
		   echo " -t <ta-host_to_build>  default: ${TARGET}"
		   exit
		   ;;
	esac
done

# Check that optee_client has been built
if [ ! -d ${TEEC_EXPORT} ]; then
# TEEC_EXPORT should point to a folder where:
#    - libteec.so is under <path>/usr/lib
#    - tee_client_api.h etc under <path>/usr/include
#
# So typically TEEC_EXPORT will be something like:
#    TEEC_EXPORT=/some/path/usr
	echo "TEEC_EXPORT must be set!"
fi

# Check that optee_os has been built
if [ ! -d ${TA_DEV_KIT_DIR} ]; then
	echo "Error: OP-TEE OS hasn't been built"
	echo "  Try: cd ../build && CFG_TA_ASLR=n make -j`nproc` optee-os && cd -"
	echo "       then, retry!"
	exit
fi

echo "Build host and TA for:"
echo "  Target:          ${TARGET}"
echo "  PLATFORM:        ${PLATFORM}"
echo "  PLATFORM_FLAVOR: ${PLATFORM_FLAVOR}"
echo "  CROSS_COMPILE:   ${CROSS_COMPILE}"
echo -e "  LOAD_ADDRESS:    ${LOAD_ADDRESS}\n"

printf "\nBuilding 'Locki'\n"
cd $CURDIR/${TARGET}
$BEAR make CROSS_COMPILE=${CROSS_COMPILE} CFG_TEE_TA_LOG_LEVEL=4 ${CLEAN} V=${V}

# There is no ELF available after running clean, hence exit.
if [ ! -z ${CLEAN} ];then
	exit
fi;

if [ ! -z ${SHOW_GDB_INFO} ]; then
	echo -e "\nGDB target:"
	# Find the TA ELF
	TA_FILE=`ls ${CURDIR}/${TARGET}/ta/*.elf | grep -v stripped`
	# Grab the .text offset
	TA_TEXT_OFFSET=`${CROSS_COMPILE}readelf -S ${TA_FILE} | grep text | head -1 | awk '{print "0x"$5}'`
	# Add it to the load address
	TA_LOAD_ADDRESS=$((${TA_TEXT_OFFSET} + ${LOAD_ADDRESS}))
	echo "   add-symbol-file ${TA_FILE} `printf '0x%08x\n' ${TA_LOAD_ADDRESS}`"
fi;

if [ ! -z ${SYNC} ]; then
	echo -e "\nMount alias on device / QEMU:"
	TA_FILE=`cd ${CURDIR}/${TARGET}/ta/ && ls *.ta`
	M1="mkdir -p /host && mount -t 9p -o trans=virtio host /host"
	echo "   alias m1='${M1}'"

	M2="cd /lib/optee_armtz && ln -sf /host/locki/${TARGET}/ta/${TA_FILE} ${TA_FILE}"
	echo "   alias m2='${M2}'"

	M3="cd /usr/bin && ln -sf /host/locki/locki/host/${TARGET} ${TARGET}"
	echo "   alias m3='${M3}'"
	M4="cd /usr/lib && ln -sf /host/locki/locki/lib/liblocki.so liblocki.so"
	echo "   alias m4='${M4}'"
	M5="cd /usr/bin && ln -sf /host/locki/locki/test/locki_test locki_test"
	echo "   alias m5='${M5}'"
	echo "   alias all='${M1} && ${M2} && ${M3} && ${M4} && ${M5}'"
fi
