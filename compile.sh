#!/bin/bash

custom="$1"

set -eux -o pipefail

arch=$(uname -m)
cpus=$(lscpu | sed -n 's/^CPU(s): *\([0-9]*\)/\1/p')
: ${CC:=gcc}
args='systemd.unified_cgroup_hierarchy=1'

build_clang()
{
	yum -y install gcc-c++ python3 cmake ninja-build
	git clone https://github.com/ClangBuiltLinux/tc-build.git
	cd tc-build
	# Need GCC to compile it.
	CC=gcc ./build-llvm.py --use-good-revision \
		--install-folder /usr/local
	cd ..
}

# SELinux for developers remains a pipe dream.
common='selinux=0 audit=0'

if [[ "$arch" == 's390x' ]]; then
	old=$(grep 'options ' /boot/loader/entries/*-$(uname -r).conf)
	new="$old $args"
else
	old=$(grep 'kernelopts=' /boot/grub2/grubenv)
	new="$old $args $common"
fi
diff='/tmp/test.patch'
if [ ! -d linux ]; then
	git clone \
	    https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git
	ln -s $PWD/linux /usr/src/
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
	    autoconf automake libaio-devel libattr-devel libcap-devel \
	    libgcrypt-devel keyutils-libs zlib-devel elfutils-libelf-devel \
	    grubby wget tar patch time sysstat jq qemu-kvm genisoimage golang \
	    libseccomp-devel
	if [[ "$arch" != 's390x' ]]; then
		yum -y install numactl-devel numactl
	fi
	if [[ "$arch" == 'aarch64' ]]; then
		grub2-editenv - set "$new earlycon"
		cp ../arm64.config .config
	elif [[ "$arch" == 'ppc64le' ]]; then
		grub2-editenv - set "$new earlyprintk"
		cp ../powerpc.config .config
	elif [[ "$arch" == 'x86_64' ]]; then
		serial=$(sed 's/.* console=\(ttyS[0-9]*\,[0-9]*\).*/\1/' <<<"$old")
		grub2-editenv - set "$new earlyprintk=$serial"
		cp ../x86.config .config
	elif [[ "$arch" == 's390x' ]]; then
		sed -i 's/^timeout=.*/timeout=30/' /etc/zipl.conf
		sed -i "s;$old;$old $common;" \
		    /boot/loader/entries/*-$(uname -r).conf
		cp ../s390.config .config
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
set +e
ls ../patch/* | while read i; do
	git am "$i"
done
set -e
if [ -s "$diff" ]; then
	patch -Np1 < "$diff"
fi
# KCSAN needs at least Clang 11.
if [[ "$CC" == 'clang' ]] && ! which clang; then
	cd ..
	build_clang
	cd linux
fi
make W=1 CC=$CC -j $cpus 2> warn.txt
make CC=$CC modules_install
make CC=$CC install
# Some kernels have CONFIG_BLK_DEV_DM_BUILTIN=y, so need to include dm-mod
# manually for a LVM rootfs.
if lvs | grep root && ! lsmod | grep dm_mod; then
	initrd=$(ls -t /boot/initramfs-* | head -1)
	kver=$(basename $initrd | sed 's/^initramfs-\(.*\)\.img/\1/')
	dracut --add-drivers dm-mod -f "$initrd" "$kver"
fi
if [[ "$arch" == 's390x' ]]; then
	vmlinuz=$(ls -t /boot/vmlinuz-* | head -1)
	vmlinuz=$(basename $vmlinuz)
	loader=$(ls /boot/loader/entries/*${vmlinuz##vmlinuz}.conf)
	if ! grep "$args" $loader; then
		sed -i "s;^options .*;$new earlyprintk;" $loader
	fi
	zipl
elif ! grep 'saved_entry=0$' /boot/grub2/grubenv && [ -z "$custom" ]; then
	grub2-editenv - set saved_entry=0
fi
set +e
for i in mm/ tlb hmm hugetlb memblock mm.h gfp mmzone memory vmalloc slab \
    slub shmem zbud zpool zsmalloc hmat pmem memremap iommu sched numa memmap \
    memremap iomem ioremap page cache skb '[^a-z]node' '[^a-z]efi' \
    '[^a-z]dma[^a-z]'; do
	grep $i warn.txt | grep -v 'Wmissing-prototypes' |
	    grep -v 'unction parameter'
done
