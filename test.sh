#!/bin/bash

set -eux -o pipefail

arch=$(uname -m)

if [ ! -f /sys/kernel/kexec_crash_size ] ||
   [[ $(cat /sys/kernel/kexec_crash_size) == '0' ]]; then
	echo '- error: kexec_crash_size' >&2
	exit 1
fi

# The powerpc has CONFIG_HAVE_DMA_CONTIGUOUS=n.
if [[ "$arch" != 'ppc64le' ]]; then
	if [ ! -f /sys/kernel/debug/cma/cma-reserved/count ] ||
	   [[ $(cat /sys/kernel/debug/cma/cma-reserved/count) == '0' ]]; then
		echo '- error: cma-reserved/count' >&2
		exit 1
	fi
fi

if [[ "$arch" == 'x86_64' ]] && ! ls -l /dev/pmem0; then
	echo '- error: /dev/pmem0 is gone.' >&2
	exit 1
fi

echo function > /sys/kernel/debug/tracing/current_tracer
echo nop > /sys/kernel/debug/tracing/current_tracer

# Test memory online and offline.
set +e
i=0
found=0
for mem in $(ls -d /sys/devices/system/memory/memory*); do
	((i++))
	echo "iteration: $i: $mem"
	echo offline > $mem/state
	if [ $? -eq 0 ] && [ $found -eq 0 ]; then
		found=1
		continue
	fi
	echo online > $mem/state
done
set -e

if [ ! -d ltp ]; then
	git clone https://github.com/cailca/ltp.git
fi

if [ ! -x /opt/ltp/runltp ]; then
	cd ltp
	make autotools
	./configure

	cpus=$(lscpu | sed -n 's/^CPU(s): *\([0-9]*\)/\1/p')
	make -j "$cpus"
	make install

	# The kernel may lack of keyctl configs.
	sed -i '/keyctl.*/d' /opt/ltp/runtest/syscalls

	# Some openstack guests lack of random number generators that could hang
	# for a long time.
	sed -i '/getrandom.*/d' /opt/ltp/runtest/syscalls

	# This test takes a long time and not worth running.
	sed -i '/fork13.*/d' /opt/ltp/runtest/syscalls

	case "$arch" in
	's390x' | 'x86_64')
		# This test sometimes triggers unneeded OOMs.
		sed -i '/msgstress02.*/d' /opt/ltp/runtest/syscalls
		;& # fall-through
	'aarch64')
		# Those tests have too much CPU load for KASAN_SW_TAGS. See,
		# https://lore.kernel.org/linux-arm-kernel/7ec14ad5-8d64-b842-a819-9d57cc8495e2@lca.pw/
		sed -i '/msgstress03.*/d' /opt/ltp/runtest/syscalls
		sed -i '/sendmsg02.*/d' /opt/ltp/runtest/syscalls
		;& # fall-through
	'ppc64le')
		# This test triggers unneeded OOMs all the time.
		sed -i '/msgstress04.*/d' /opt/ltp/runtest/syscalls
	esac
	cd ..
fi

# Don't care about the individual test case correctness here.
set +e
/opt/ltp/runltp -f syscalls,mm,fs,hugetlb,cpuhotplug

dmesg | grep -i warn | grep -v _NOWARN
dmesg | grep -i bug | grep -v -i debug
dmesg | grep -i error
dmesg | grep -i leak | grep -v kmemleak_alloc
dmesg | grep -i undefined
dmesg | grep -i corruption
