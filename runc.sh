#!/bin/bash

set -eux -o pipefail

# Borrow from moby/download-frozen-image-v2.sh.
runc=${1:-'runc'}
arch=$(uname -m)
registryBase='https://registry-1.docker.io'
authBase='https://auth.docker.io'
authService='registry.docker.io'
image='library/busybox'
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

if [ -f config.json ]; then
	mv config.json config.json.bak
fi
$runc spec
mv config.json config.json.orig
cat config.json.orig | jq '.process.args = ["tty"]' > config.json
# Some runtime console implementations may include a CR.
out="$($runc run root | tr -d '\r')"
if [[ "$out" != '/dev/pts/0' ]]; then
	echo "- error: unexpected console is $out." >&2
	exit 1
fi
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
	echo "- error: unexpected runc exec output is $out." >&2
	exit 1
fi
# Only top command so far will accept SIGTERM.
$runc kill root KILL
while ! $runc list | grep 'root' | grep 'stopped'; do
	sleep 5
done
# Need to clean up a detached container.
$runc delete root
