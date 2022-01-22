#!/bin/bash
set -e

printf "Generating download links\n"

OUT_FILE=README.md

declare -a _TARGET_OS
declare -a _TARGET_ARCH
_TARGET_OS[${#_TARGET_OS[@]}]="linux"
_TARGET_OS[${#_TARGET_OS[@]}]="windows"
_TARGET_ARCH[${#_TARGET_ARCH[@]}]="amd64"

P1="github.com/greenpau/caddy-security"
P2="github.com/greenpau/caddy-trace"

V1="v"`cat VERSION`
# V2=`cat go.mod | grep "${P2}" | grep -v replace | cut -f2 | cut -d" " -f2`
V2="v1.1.8"
P1=$(echo ${P1} | sed 's/\//%2F/g')
P2=$(echo ${P2} | sed 's/\//%2F/g')

#echo "package ${P1} ${V1}"
#echo "package ${P2} ${V2}"

sed -i '\/caddyserver.com\/api\/download/d' README.md

DLOAD_LINE=$(grep -Fn 'Download Caddy with the plugins enabled' README.md | cut -d":" -f1)
DLOAD_LINE=$((DLOAD_LINE+1))

for OS_ID in "${!_TARGET_OS[@]}"; do
  OS_NAME=${_TARGET_OS[$OS_ID]};
  for ARCH_ID in "${!_TARGET_ARCH[@]}"; do
    ARCH_NAME=${_TARGET_ARCH[$ARCH_ID]};
    HREF="https://caddyserver.com/api/download?os=${OS_NAME}&arch=${ARCH_NAME}&p=${P1}%40${V1}&p=${P2}%40${V2}";
    HREF_LINK="* <a href=\"${HREF}\" target=\"_blank\">${OS_NAME}/${ARCH_NAME}</a>";
    sed -i ''"${DLOAD_LINE}"' i '"${HREF_LINK}"'' README.md
  done
done
