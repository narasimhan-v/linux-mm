#!/bin/bash

set -eux -o pipefail

# Borrow from moby/download-frozen-image-v2.sh.
error=0
runc=${1:-'runc'}
arch=$(uname -m)
registryBase='https://registry-1.docker.io'
authBase='https://auth.docker.io'
authService='registry.docker.io'
# Busybox and Alpine has problems with noNewPrivileges.
# Fedora, Debian, and CentOS are larger in size.
# RHEL UBI is not in docker.io and a bit annoying to fetch.
image='library/ubuntu'
token="$(curl -fsSL \
	"$authBase/token?service=$authService&scope=repository:$image:pull" |
	jq --raw-output '.token')"
manifestJson="$(
	curl -fsSL \
		-H "Authorization: Bearer $token" \
		-H 'Accept: application/vnd.docker.distribution.manifest.v2+json' \
		-H 'Accept: application/vnd.docker.distribution.manifest.list.v2+json' \
		-H 'Accept: application/vnd.docker.distribution.manifest.v1+json' \
		"$registryBase/v2/$image/manifests/latest"
)"
case "$arch" in
'x86_64')
	arch='amd64'
	;;
'aarch64')
	arch='arm64'
	;;
esac
newlineIFS=$'\n'
layersFs="$(echo "$manifestJson" |
	jq --raw-output --compact-output '.manifests[]')"
IFS="$newlineIFS"
layers=($layersFs)
unset IFS
# Parse first level multi-arch manifest.
for i in "${!layers[@]}"; do
	layerMeta="${layers[$i]}"
	maniArch="$(echo "$layerMeta" |
		jq --raw-output '.platform.architecture')"
	os="$(echo "$layerMeta" | jq --raw-output '.platform.os')"
	if [[ "$maniArch" != "$arch" ]] || [[ "$os" != 'linux' ]]; then
		continue
	fi
	digest="$(echo "$layerMeta" | jq --raw-output '.digest')"
	# Get second level single manifest.
	submanifestJson="$(
		curl -fsSL \
			-H "Authorization: Bearer $token" \
			-H 'Accept: application/vnd.docker.distribution.manifest.v2+json' \
			-H 'Accept: application/vnd.docker.distribution.manifest.list.v2+json' \
			-H 'Accept: application/vnd.docker.distribution.manifest.v1+json' \
			"$registryBase/v2/$image/manifests/$digest"
	)"
	break
done
if [ -d rootfs ]; then
	rm -r rootfs
fi
mkdir rootfs
cd rootfs
layersFs="$(echo "$submanifestJson" |
	jq --raw-output --compact-output '.layers[]')"
IFS="$newlineIFS"
layers=($layersFs)
unset IFS
# Only deal with one-layer image at the moment.
layerMeta="${layers[0]}"
digest="$(echo "$layerMeta" | jq --raw-output '.digest')"
curlHeaders="$(
	curl -S --progress-bar \
		-H "Authorization: Bearer $token" \
		"$registryBase/v2/$image/blobs/$digest" \
		-o layer.tar \
		-D-
)"
curlHeaders="$(echo "$curlHeaders" | tr -d '\r')"
blobRedirect="$(echo "$curlHeaders" |
	awk -F ': ' 'tolower($1) == "location" { print $2; exit }')"
curl -fSL --progress-bar "$blobRedirect" -o layer.tar
tar xvf layer.tar
cd ..

# Start runtime tests.
if [ -f config.json ]; then
	mv config.json config.json.bak
fi
$runc spec

# Test console support.
mv config.json config.json.orig
cat config.json.orig | jq '.process.args = ["tty"]' > config.json
# Some runtime console implementations may include a CR.
out="$($runc run root | tr -d '\r')"
if [[ "$out" != '/dev/pts/0' ]]; then
	echo "- error: unexpected console is $out." >&2
	exit 1
fi

# Test pause and resume.
mv config.json config.json.orig
cat config.json.orig |
	jq '.process.terminal = false | .process.args = ["sleep", "60"]' \
	> config.json
$runc run -d root
while ! $runc list | grep 'root' | grep 'running'; do
	sleep 5
done
$runc pause root
while ! $runc list | grep 'root' | grep 'paused'; do
	sleep 5
done
$runc resume root
while ! $runc list | grep 'root' | grep 'running'; do
	sleep 5
done
cat config.json |
	jq '.process.args = ["echo", "-n", "Hello, World!"] | .process' \
	> process.json
out="$($runc exec -p process.json root)"
if [[ "$out" != 'Hello, World!' ]]; then
	echo "- error: unexpected exec output is $out." >&2
	exit 1
fi

# Test ps.
out="$($runc ps root)"
if ! [[ "$out" =~ 'sleep' ]]; then
	echo "- error: unexpected ps output is $out." >&2
	# There is a runtime only cares about PIDs.
	error=$((error + 1))
fi
# Only top command so far will accept SIGTERM.
$runc kill root KILL
while ! $runc list | grep 'root' | grep 'stopped'; do
	sleep 5
done
# Need to clean up a detached container.
$runc delete root

# Test hostname.
mv config.json config.json.orig
cat config.json.orig |
	jq '.hostname = "runc.example.com" | .process.args = ["uname", "-n"]' \
	> config.json
out="$($runc run root)"
if [[ "$out" != 'runc.example.com' ]]; then
	echo "- error: unexpected hostname is $out." >&2
	exit 1
fi

# Test capabilities. Reading /dev/kcore should fail without CAP_SYS_RAWIO.
script='
rm -f /tmp/test
mknod /tmp/test b 1 1
echo -n $?
rm /tmp/test
echo -n $?
rm -rf /tmp/proc/
mkdir /tmp/proc/
mount -t proc proc /tmp/proc
echo -n $?
umount /tmp/proc
echo -n $?
cat /dev/kcore 2> /dev/null
echo -n $?
'
mv config.json config.json.orig
cat config.json.orig |
	jq --arg script "$script" \
	'.process.args = ["sh", "-c", $script] | .root.readonly = false' \
	> config.json
out="$($runc run root 2> /dev/null)"
# Not really sure about the errno from those mount/umount. EPIPE, anyone?
if [[ "$out" =~ '0' ]]; then
	echo "- error: unexpected deny code is $out." >&2
	exit 1
fi
for item in 'bounding' 'effective' 'inheritable' 'permitted'; do
	mv config.json config.json.orig
	cat config.json.orig |
		jq --arg item "$item" \
		'.process.capabilities[$item] |= .+ ["CAP_MKNOD","CAP_SYS_ADMIN"]' \
		> config.json
done
out="$($runc run root 2> /dev/null)"
if [[ "$out" != '00001' ]]; then
	echo "- error: unexpected allow code is $out." >&2
	exit 1
fi

# Prepare to run noNewPrivileges which is on by default.
chmod u+s 'rootfs/bin/ls'
script='
ls /root/ > /dev/null 2>&1
echo -n $?
'
mv config.json config.json.orig
cat config.json.orig |
	jq --arg script "$script" \
	'.process.user.gid = 100 | .process.user.uid = 100 | .process.args = ["sh", "-c", $script]' \
	> config.json
out="$($runc run root)"
if [[ "$out" == '0'  ]]; then
	echo "- error: unexpected accessing /root." >&2
	exit 1
fi
mv config.json config.json.orig
cat config.json.orig |
	jq '.process.noNewPrivileges = false' > config.json
out="$($runc run root)"
if [[ "$out" != '0'  ]]; then
	echo "- error: unexpected noNewPrivileges code is $out." >&2
	exit 1
fi

# Test sysctl.
script='
cat /proc/sys/net/ipv4/ip_forward
cat /proc/sys/net/core/somaxconn
'
mv config.json config.json.orig
# It seems ip_forward is 1 and somaxconn is 4096 by default.
cat config.json.orig |
	jq  --arg script "$script" \
	'.linux |= .+ {"sysctl":{"net.ipv4.ip_forward":"0","net.core.somaxconn":"256"}} | .process.args = ["sh", "-c", $script]' \
	> config.json
out="$($runc run root | tr -d '\n')"
if [[ "$out" != '0256' ]]; then
	echo "- error: unexpected sysctl code is $out." >&2
	exit 1
fi

# Test seccomp.
mv config.json config.json.orig
cat config.json.orig |
	jq '.process.user.gid = 0 | .process.user.uid = 0 | .process.args = ["chmod", "u+x", "/root"]' \
	> config.json
mv config.json config.json.orig
cat config.json.orig |
	jq '.linux |= .+ {"seccomp":{"defaultAction":"SCMP_ACT_ALLOW","syscalls":[{"action":"SCMP_ACT_ERRNO","names":["fchmodat"]}]}}' \
	> config.json
set +e
out="$($runc run root 2>&1)"
if ! [[ "$out" =~ 'Operation not permitted' ]]; then
	echo "- error: unexpected seccomp output is $out." >&2
	# There is a runtime with seccomp off by default.
	error=$((error + 1))
fi
set -e

# Test rootfsPropagation==shared.
# Assume the "/"  was mounted as shared.
# Mount propagation rule could be tricky. If the source directory is on a
# separate partition, it might end up with rootfsPropagation==private not
# working as expected later, so just use /etc for now.
cwd='/etc'
rootfs="$(pwd)/rootfs"
host="$cwd/runc"
# Prepare rootfs like docker/libcontainer.
mount -o bind "$rootfs" "$rootfs"
mount --make-private "$rootfs"
mv config.json config.json.orig
# "cat /proc/self/mountinfo" to check if unsure.
cat config.json.orig |
	jq --arg cwd "$cwd" '.linux.rootfsPropagation = "shared" | .process.args = ["sleep", "60"] |
		.mounts |= .+ [{"destination":"/rshared","options":["rbind"],"source":$cwd,"type":"bind"},
		{"destination":"/rslave","options":["rbind","rslave"],"source":$cwd,"type":"bind"},
		{"destination":"/rprivate","options":["rbind","rprivate"],"source":$cwd,"type":"bind"}]' \
		> config.json
$runc run -d root
touch /tmp/host
if [ ! -d "$host" ]; then
	mkdir "$host"
fi
mount -o bind /tmp "$host"
$runc exec root ls /rshared/runc/host
$runc exec root ls /rslave/runc/host
set +e
$runc exec root ls /rprivate/runc/host
if [ $? -eq 0 ]; then
	echo '- error: unexpected shared/rprivate mount.' >&2
	exit 1
fi
set -e
# It may happily return 0 here, so need to check if the file still exists.
$runc exec root umount /rslave/runc
if [ ! -f "$host/host" ]; then
	echo '- error: unexpected shared/rslave affecting host.' >&2
	exit 1
fi
$runc exec root umount /rshared/runc
if [ -f "$host/host" ]; then
	echo '- error: unexpected shared not affecting host.' >&2
	exit 1
fi
$runc delete -f root

# Test rootfsPropagation==slave which is the default.
mv config.json config.json.orig
cat config.json.orig |
	jq 'del(.linux.rootfsPropagation)' > config.json
$runc run -d root
mount -o bind /tmp "$host"
$runc exec root ls /rshared/runc/host
$runc exec root ls /rslave/runc/host
$runc exec root umount /rshared/runc
if [ ! -f "$host/host" ]; then
	echo '- error: unexpected slave/rshared affecting host.' >&2
	exit 1
fi
$runc delete -f root
umount "$host"

# Test rootfsPropagation==private.
mv config.json config.json.orig
cat config.json.orig |
	jq '.linux.rootfsPropagation = "private"' > config.json
$runc run -d root
mount -o bind /tmp "$host"
set +e
$runc exec root ls /rshared/runc/host
if [ $? -eq 0 ]; then
	echo '- error: unexpected private/rshared mount.' >&2
	exit 1
fi
$runc exec root ls /rslave/runc/host
if [ $? -eq 0 ]; then
	echo '- error: unexpected private/rslave mount.' >&2
	exit 1
fi
set -e
$runc delete -f root
umount "$host"
umount "$rootfs"

# Test rlimits.
script='
ulimit -v -H
ulimit -v -S
'
mv config.json config.json.orig
cat config.json.orig |
	jq --arg script "$script" \
	'.process.args = ["sh", "-c", $script] |
	.process.rlimits |= .+ [{"type":"RLIMIT_AS","hard":10485760,"soft":5242880}]' \
	> config.json
out="$($runc run root)"
if [[ "$out" != 10240$'\n'5120 ]]; then
	echo "- error: unexpected rlimits output is $out." >&2
	exit 1
fi

# Run a fuzzer if everything passed.
if [[ $error -ne 0 ]]; then
	exit $error
fi
if [ ! -d 'trinity' ]; then
	git clone https://github.com/kernelslacker/trinity.git
fi
cpus=$(lscpu | sed -n 's/^CPU(s): *\([0-9]*\)/\1/p')
if [ ! -x '/usr/bin/trinity' ]; then
	cd trinity
	./configure
	make -j "$cpus"
	make install
	cd ..
fi
mv config.json config.json.orig
# Reading of pseudo files have already been tested before, and it is unsafe to
# write garbage to them. Also, set memory.max to 1G to protect the system from
# crazy fuzzers which would affect the continuity.
cat config.json.orig |
	jq --arg cpus "$cpus" \
	'del(.linux.seccomp) | del(.process.rlimits) |
	.process.args = ["trinity", "--dangerous", "-C", $cpus,
			"--disable-fds=pseudo", "--arch", "64"] |
	.mounts |= .+ [{"destination":"/usr/bin/trinity",
			"options":["rbind","ro"],
			"source":"/usr/bin/trinity",
			"type":"bind"}] |
	.linux.cgroupsPath = "/runc" |
	.linux.resources.memory = {"limit": 1073741824}' \
	> config.json
# CAP_SYS_ADMIN is unsafe here. For example, sethostname() would make the life
# miserable.
for item in 'bounding' 'effective' 'inheritable' 'permitted'; do
	mv config.json config.json.orig
	cat config.json.orig |
		jq --arg item "$item" \
		'.process.capabilities[$item] = [
		"CAP_CHOWN","CAP_IPC_LOCK","CAP_LEASE","CAP_LINUX_IMMUTABLE",
		"CAP_NET_ADMIN","CAP_NET_RAW","CAP_NET_BIND_SERVICE",
		"CAP_SETGID","CAP_SETUID", "CAP_SETFCAP","CAP_SETPCAP",
		"CAP_SYS_NICE","CAP_SYS_PACCT","CAP_SYS_PTRACE","CAP_KILL",
		"CAP_SYS_RAWIO"]' \
		> config.json
done
$runc run root
