#!/bin/bash

set -eux -o pipefail

arch=$(uname -m)
distro='ubuntu-18.04-server-cloudimg'
bios=''

case "$arch" in
'x86_64')
	image="$distro-amd64.img"
	;;
'aarch64')
	bios='-bios /usr/share/AAVMF/AAVMF_CODE.fd -M gic-version=host'
	image="$distro-arm64.img"
	;;
'ppc64le')
	image="$distro-ppc64el.img"
	;;
esac
if [ ! -f "$distro.qcow2" ]; then
	if [ ! -f "$image" ]; then
		curl -O "https://cloud-images.ubuntu.com/releases/bionic/release/$image"
	fi
	qemu-img create -b "$image" -f qcow2 "$distro.qcow2" 1T
fi
if [ ! -f "$distro.iso" ]; then
	cat > meta-data <<-EOF
	instance-id: $distro
	local-hostname: $distro
EOF
	cat > user-data <<-EOF
	#cloud-config
	password: $distro
	chpasswd: { expire: False }
	ssh_pwauth: True
EOF
	genisoimage -output "$distro.iso" -volid cidata -joliet -rock \
		user-data meta-data
fi
/usr/libexec/qemu-kvm -name "$distro" -cpu host -smp 2 -m 2G \
	-hda "$distro.qcow2" -cdrom "$distro.iso" $bios \
	-nic user,hostfwd=tcp::2222-:22 -serial mon:stdio
