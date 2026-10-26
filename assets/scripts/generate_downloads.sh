#!/bin/bash
set -e

OUT_FILE=README.md
DOWNLOAD_MARKER='<!-- caddy-security-downloads -->'
if [ "$#" -gt 1 ] || { [ "$#" -eq 1 ] && [ "$1" != --check ]; }; then
  echo "Usage: generate_downloads.sh [--check]" >&2
  exit 2
fi
marker_count=$(grep -Fxc -- "$DOWNLOAD_MARKER" "$OUT_FILE" || true)
case "$marker_count" in
  1) ;;
  0|'') echo "README download insertion marker is missing" >&2; exit 1 ;;
  *) echo "README download insertion marker must occur exactly once" >&2; exit 1 ;;
esac
if [ "$#" -eq 1 ]; then
  exit 0
fi

printf "Generating download links\n"

declare -a _TARGET_OS
declare -a _TARGET_ARCH
_TARGET_OS[${#_TARGET_OS[@]}]="linux"
_TARGET_OS[${#_TARGET_OS[@]}]="windows"
_TARGET_ARCH[${#_TARGET_ARCH[@]}]="amd64"

P1="github.com/greenpau/caddy-security"
P2="github.com/greenpau/caddy-trace"

V1="v"`cat VERSION`
# V2=`cat go.mod | grep "${P2}" | grep -v replace | cut -f2 | cut -d" " -f2`
V2="v1.1.13"
P1=$(echo ${P1} | sed 's/\//%2F/g')
P2=$(echo ${P2} | sed 's/\//%2F/g')

echo "package ${P1} ${V1}"
echo "package ${P2} ${V2}"

if [[ "$(uname -s)" == "Darwin" ]]; then
  sed -i '' -e '/\/caddyserver.com\/api\/download/d' README.md
else
  sed -i '/\/caddyserver.com\/api\/download/d' README.md
fi

DLOAD_LINE=$(grep -Fnx -- "$DOWNLOAD_MARKER" "$OUT_FILE" | cut -d":" -f1)
DLOAD_LINE=$((DLOAD_LINE+1))

for OS_ID in "${!_TARGET_OS[@]}"; do
  OS_NAME=${_TARGET_OS[$OS_ID]};
  for ARCH_ID in "${!_TARGET_ARCH[@]}"; do
    ARCH_NAME=${_TARGET_ARCH[$ARCH_ID]};
    HREF="https://caddyserver.com/api/download?os=${OS_NAME}&arch=${ARCH_NAME}&p=${P1}%40${V1}&p=${P2}%40${V2}";
    HREF_LINK="* <a href=\"${HREF}\" target=\"_blank\">${OS_NAME}/${ARCH_NAME}</a>";
    if [[ "$(uname -s)" == "Darwin" ]]; then
      gsed -i ''"${DLOAD_LINE}"' i '"${HREF_LINK}"'' README.md
    else
      sed -i ''"${DLOAD_LINE}"' i '"${HREF_LINK}"'' README.md
    fi
  done
done
