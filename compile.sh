#!/bin/bash

custom="$1"

set -eux -o pipefail

arch=$(uname -m)
cpus=$(lscpu | sed -n 's/^CPU(s): *\([0-9]*\)/\1/p')
cc=gcc
old=$(grep 'kernelopts=' /boot/grub2/grubenv)
new="page_poison=on crashkernel=512M page_owner=on numa_balancing=enable \
systemd.unified_cgroup_hierarchy=1 debug_guardpage_minorder=1 \
page_alloc.shuffle=1"
diff='/tmp/test.patch'

if [ ! -d linux ]; then
	git clone \
	    https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git
	cd linux
	git remote add linux-next \
	    https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git
	git fetch linux-next
	git fetch --tags linux-next
	git checkout -b next linux-next/master
else
	cd linux
fi

if [ ! -f .config ]; then
	yum -y install openssl-devel make gcc bc bison flex ncurses-devel \
	    autoconf automake numactl-devel libaio-devel libattr-devel \
	    libcap-devel libgcrypt-devel keyutils-libs zlib-devel \
	    elfutils-libelf-devel grubby wget tar numactl patch time

	# SELinux for developers remains a pipe dream.
	common='selinux=0 audit=0'

	if [[ "$arch" == 'aarch64' ]]; then
		grub2-editenv - set "$old $common"
		yum -y install clang
		cp ../arm64.config .config
	elif [[ "$arch" == 'ppc64le' ]]; then
		grub2-editenv - set "$old $new $common earlyprintk"
		cp ../powerpc.config .config
	elif [[ "$arch" == 'x86_64' ]]; then
		grub2-editenv - set "$old $common"
		cp ../x86.config .config
	else
		echo '- error: unsupported arch.' >&2
		exit 1
	fi

	# Kdump for developers remains a pipe dream too.
	if systemctl is-enabled kdump; then
		systemctl disable kdump
	fi

	# Beaker don't like OOM test cases.
	if systemctl is-enabled restraintd; then
		systemctl disable restraintd
	fi
else
	git remote update
fi

git diff > "$diff"

set +u
if [ -z "$custom" ]; then
	# Just in case ...
	if [[ $(git branch | grep \* | cut -d ' ' -f2) != 'next' ]]; then
		git checkout next
	fi

	git reset --hard linux-next/master
else
	git reset --hard
fi
set -u

for i in $(ls ../patch/*); do
	git am $i
done

if [[ "$arch" == 'aarch64' ]]; then
	cc=clang
fi

if [ -s "$diff" ]; then
	patch -Np1 < "$diff"
fi

make W=1 CC=$cc -j $cpus 2> warn.txt
make CC=$cc modules_install
make install

# The Fedora Linux 30 has CONFIG_BLK_DEV_DM_BUILTIN=y, so need to include dm-mod
# manually for a LVM rootfs.
if lvs | grep root && ! lsmod | grep dm_mod; then
	initrd=$(ls -t /boot/initramfs-* | head -1)
	kver=$(basename $initrd | sed 's/^initramfs-\(.*\)\.img/\1/')
	dracut --add-drivers dm-mod -f "$initrd" "$kver"
fi

# Some Openstack VMs may need this.
if ! grep 'saved_entry=0' /boot/grub2/grubenv && [ -z "$custom" ]; then
	grub2-editenv - set saved_entry=0
fi

# Possible a grub2 bug that the kernel address could overwrite the initramfs
# address as it gives "junk in compressed archive" even with
# CONFIG_DEBUG_PAGEALLOC=n. Stock kernel works fine possibly due to smaller
# kernel or/and .bss sizes.
if [[ "$arch" == 'aarch64' ]]; then
	vmlinuz=$(ls -t /boot/vmlinuz-* | head -1)
	initramfs=$(ls -t /boot/initramfs-* | head -1)
	cp "$vmlinuz" /boot/efi/
	cp "$initramfs" /boot/efi/

	vmlinuz=$(basename $vmlinuz)
	initramfs=$(basename $initramfs)
	rootfs=$(echo $old | sed 's/kernelopts=//')

	echo "$vmlinuz initrd=\\$initramfs $rootfs $new earlycon" > \
	    /boot/efi/startup.nsh
fi

set +e
for i in mm/ tlb hmm hugetlb memblock mm.h gfp mmzone memory vmalloc slab \
    slub shmem zbud zpool zsmalloc hmat pmem memremap iommu sched numa memmap \
    memremap iomem ioremap page cache '[^a-z]node' '[^a-z]efi' \
    '[^a-z]dma[^a-z]'; do
	grep $i warn.txt | grep -v 'Wmissing-prototypes' |
	    grep -v 'unction parameter'
done
