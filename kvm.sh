#!/bin/bash

set -eux -o pipefail

device=${1:-''}
arch=$(uname -m)
distro='ubuntu-18.04-server-cloudimg'
bios=''
vfio='/sys/bus/pci/drivers/vfio-pci'
sysfs="/sys/bus/pci/devices/$device"
sriov=''

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
*)
	image="$distro-$arch.img"
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
if [ -f "$sysfs/reset" ]; then
	modprobe vfio-pci
	vendor=$(cat "$sysfs/vendor")
	devid=$(cat "$sysfs/device")
	echo "${vendor##0x} ${devid##0x}" > "$vfio/new_id"

	# Save the driver name to restore later if possible.
	driver=$(readlink "$sysfs/driver")
	echo "$device" > "$sysfs/driver/unbind"
	echo "$device" > "$vfio/bind"
	sriov="-device vfio-pci,host=$device"
fi
/usr/libexec/qemu-kvm -name "$distro" -cpu host -smp 2 -m 2G \
	-hda "$distro.qcow2" -cdrom "$distro.iso" $bios \
	-nic user,hostfwd=tcp::2222-:22 -nographic $sriov

if [ -n "$sriov" ]; then
	echo "${vendor##0x} ${devid##0x}" > "$vfio/remove_id"
	echo "$device" > "$vfio/unbind"

	# To restore PCI passthrough,
	# echo "$device" > $driver/bind
	# To restore SR-IOV,
	# echo 0 > /sys/class/net/<interface>/device/sriov_numvfs
	echo "$driver"
fi
