#!/bin/bash

set -eux -o pipefail

# Borrow from moby/download-frozen-image-v2.sh.
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
if [[ "$arch" == 'x86_64' ]]; then
	arch='amd64'
fi
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
if [ ! -d rootfs ]; then
	mkdir rootfs
fi
cd rootfs
rm -f layer.tar
layersFs="$(echo "$submanifestJson" |
	jq --raw-output --compact-output '.layers[]')"
IFS="$newlineIFS"
layers=($layersFs)
unset IFS
# Only deal with one-layer image at the moment.
layerMeta="${layers[0]}"
digest="$(echo "$layerMeta" | jq --raw-output '.digest')"
curlHeaders="$(
	curl -S --progress \
		-H "Authorization: Bearer $token" \
		"$registryBase/v2/$image/blobs/$digest" \
		-o layer.tar \
		-D-
)"
curlHeaders="$(echo "$curlHeaders" | tr -d '\r')"
blobRedirect="$(echo "$curlHeaders" |
	awk -F ': ' 'tolower($1) == "location" { print $2; exit }')"
curl -fSL --progress "$blobRedirect" -o layer.tar
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
	exit 1
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
	exit 1
fi
